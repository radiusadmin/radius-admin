"""CoA-Request / Disconnect-Request to a switch (RFC 5176), sent with radclient.

radclient comes from the site's FreeRADIUS build (--enable-fips-workaround), the same
code FreeRADIUS uses for the RADIUS packet MD5 that the protocol requires, so this adds
no new cryptographic implementation. The shared secret is handed over in a private
0600 file (-S), never on the command line. Attribute values come from accounting
records and are validated against strict patterns before use.

Actions (Catalyst 1300 firmware 4.1.3.36+, Cisco AV-pair commands):
  reauth      CoA-Request   Cisco-AVPair = "subscriber:command=reauthenticate"
  bounce      CoA-Request   Cisco-AVPair = "subscriber:command=bounce-host-port"
  disconnect  Disconnect-Request
"""
import ipaddress
import os
import re
import shutil
import subprocess
import tempfile
import time

SEARCH_DIRS = ("/usr/local/bin", "/usr/bin", "/usr/local/sbin", "/usr/sbin", "/opt/freeradius/bin",
               "/opt/freeradius/sbin")
DICT_DIRS = ("/usr/share/freeradius", "/usr/local/share/freeradius", "/opt/freeradius/share/freeradius")

_SESSION_RE = re.compile(r"^[\x21\x23-\x5b\x5d-\x7e]{1,128}$")        # printable, no space, '"' or '\'
_STATION_RE = re.compile(r"^[0-9A-Fa-f]{2}([:.\-]?[0-9A-Fa-f]{2}){5}$|^[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}$")
_PORT_RE = re.compile(r"^[A-Za-z0-9/._:\-]{1,64}$")
_SECRET_RE = re.compile(r"^[\x21-\x7e]{1,128}$")

ACTIONS = {
    "reauth": ("coa", 'Cisco-AVPair = "subscriber:command=reauthenticate"'),
    "bounce": ("coa", 'Cisco-AVPair = "subscriber:command=bounce-host-port"'),
    "disconnect": ("disconnect", None),
}


class CoaError(Exception):
    pass


def find_radclient(configured=""):
    """(radclient path, dictionary dir) or raises CoaError with a readable reason."""
    exe = configured or None
    if exe and not os.access(exe, os.X_OK):
        raise CoaError("radclient %s is not executable" % exe)
    if not exe:
        for d in SEARCH_DIRS:
            p = os.path.join(d, "radclient")
            if os.access(p, os.X_OK):
                exe = p
                break
    if not exe:
        raise CoaError("radclient not found (set radclient = /path/to/radclient in radius-admin.conf)")
    return exe


def find_dict_dir(radclient, configured=""):
    cands = [configured] if configured else []
    prefix = os.path.dirname(os.path.dirname(os.path.realpath(radclient)))
    cands += [os.path.join(prefix, "share", "freeradius")] + list(DICT_DIRS)
    for d in cands:
        if d and os.path.isfile(os.path.join(d, "dictionary")):
            return d
    raise CoaError("FreeRADIUS dictionaries not found (set radius_dict_dir in radius-admin.conf)")


def build_request(action, nas_ip, acct_session_id="", calling_station_id="", nas_port_id=""):
    """Attribute lines for radclient. Raises CoaError for unusable input."""
    if action not in ACTIONS:
        raise CoaError("unknown action")
    try:
        ip = ipaddress.ip_address(str(nas_ip))
    except ValueError:
        raise CoaError("bad NAS address") from None
    lines = []
    if acct_session_id:
        if not _SESSION_RE.match(acct_session_id):
            raise CoaError("accounting session id has unexpected characters")
        lines.append('Acct-Session-Id = "%s"' % acct_session_id)
    if calling_station_id:
        if not _STATION_RE.match(calling_station_id):
            raise CoaError("station id is not a MAC address")
        lines.append('Calling-Station-Id = "%s"' % calling_station_id)
    if nas_port_id:
        if not _PORT_RE.match(nas_port_id):
            raise CoaError("port id has unexpected characters")
        lines.append('NAS-Port-Id = "%s"' % nas_port_id)
    if not (acct_session_id or calling_station_id):
        raise CoaError("the session has neither an accounting session id nor a station MAC")
    lines.append(("NAS-IPv6-Address = %s" if ip.version == 6 else "NAS-IP-Address = %s") % ip)
    lines.append("Event-Timestamp = %d" % int(time.time()))
    extra = ACTIONS[action][1]
    if extra:
        lines.append(extra)
    lines.append("Message-Authenticator = 0x00")
    return "\n".join(lines) + "\n"


def parse_reply(out):
    """(ok, message) from radclient -x output."""
    m = re.search(r"Received (CoA-ACK|CoA-NAK|Disconnect-ACK|Disconnect-NAK)\b", out)
    if not m:
        if "No reply from server" in out or "no response" in out.lower():
            return False, "No reply from the switch (dynamic authorization not configured, wrong key, or UDP blocked)."
        last = [ln for ln in out.strip().splitlines() if ln.strip()]
        return False, ("radclient: " + last[-1].strip())[:300] if last else "No reply from the switch."
    kind = m.group(1)
    cause = re.search(r"Error-Cause\s*=\s*([^\n]+)", out[m.end():])
    if kind.endswith("ACK"):
        return True, "The switch acknowledged (%s)." % kind
    why = cause.group(1).strip() if cause else "no Error-Cause given"
    return False, "The switch refused (%s: %s)." % (kind, why)


def send(action, host, port, secret, request_text, radclient, dict_dir, timeout=3, retries=2):
    """Send one request. Returns (ok, message)."""
    try:
        ip = ipaddress.ip_address(str(host))
    except ValueError:
        return False, "bad switch address"
    if not _SECRET_RE.match(secret or ""):
        return False, "the switch's shared secret cannot be used (empty or unusual characters)"
    kind = ACTIONS[action][0]
    target = ("[%s]:%d" % (ip, port)) if ip.version == 6 else ("%s:%d" % (ip, port))
    d = tempfile.mkdtemp(prefix="ra-coa.")
    try:
        os.chmod(d, 0o700)
        with open(os.path.join(d, "dictionary"), "w") as fh:
            fh.write("# radius-admin: empty local dictionary (the main one comes from -D)\n")
        sp = os.path.join(d, "secret")
        fd = os.open(sp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(secret + "\n")
        argv = [radclient, "-x", "-r", str(max(1, int(retries))), "-t", str(timeout), "-d", d, "-D", dict_dir, "-S", sp,
                target, kind]
        try:
            p = subprocess.run(argv, input=request_text, capture_output=True, text=True,
                               timeout=(timeout + 1) * (retries + 1) + 5, check=False,
                               env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        except subprocess.TimeoutExpired:
            return False, "radclient did not finish in time"
        except OSError as e:
            return False, "cannot run radclient: %s" % e
        return parse_reply((p.stdout or "") + "\n" + (p.stderr or ""))
    finally:
        try:
            with open(os.path.join(d, "secret"), "r+b") as fh:
                fh.write(b"\0" * 140)
        except OSError:
            pass
        shutil.rmtree(d, ignore_errors=True)
