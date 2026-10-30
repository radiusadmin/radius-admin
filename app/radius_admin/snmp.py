"""Read-only SNMPv3 switch polling (SPEC section 12).

Net-SNMP command-line tools (apt package `snmp`) do the SNMP work; they link the
system OpenSSL, so SHA-2 authentication and AES-128 privacy run in the FIPS
provider. Credentials are written to a private 0600 snmp.conf in a fresh temporary
directory (SNMPCONFPATH) -- never on a command line or in the environment.

Collected per switch (all standard MIBs):
  per 802.1X port (SPEC section 13): IEEE8021-PAE-MIB dot1xAuthPaeState,
      dot1xAuthAuthControlledPortStatus, dot1xAuthSessionUserName; IF-MIB ifOperStatus;
      Q-BRIDGE-MIB dot1qPvid (via BRIDGE-MIB dot1dBasePortIfIndex)
  SNMPv2-MIB system: sysDescr, sysUpTime, sysName
  IEEE8021-PAE-MIB dot1xAuthAuthControlledPortControl (1 forceUnauthorized,
      2 auto, 3 forceAuthorized), indexed by ifIndex
  IF-MIB ifName, to name the ports (te1/0/1 ...)
  RADIUS-AUTH-CLIENT-MIB radiusAuthServerExtTable (RFC 4668) or the older
      radiusAuthServerTable (RFC 4668 / 2618) counters
"""
import ipaddress
import os
import re
import shutil
import subprocess
import tempfile

SNMPGET = "/usr/bin/snmpget"
SNMPWALK = "/usr/bin/snmpbulkwalk"

OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_DOT1X_PORT_CONTROL = "1.0.8802.1.1.1.1.2.1.1.6"
OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
OID_RADIUS_EXT = "1.3.6.1.2.1.67.1.2.1.1.4.1"    # radiusAuthServerExtEntry
OID_RADIUS_OLD = "1.3.6.1.2.1.67.1.2.1.1.3.1"    # radiusAuthServerEntry

# column numbers -> field names
# Per-port detail (SPEC section 13), all indexed by ifIndex unless noted.
OID_DOT1X_PAE_STATE = "1.0.8802.1.1.1.1.2.1.1.1"      # dot1xAuthPaeState
OID_DOT1X_PORT_STATUS = "1.0.8802.1.1.1.1.2.1.1.5"    # dot1xAuthAuthControlledPortStatus 1 authorized 2 unauthorized
OID_DOT1X_SESSION_USER = "1.0.8802.1.1.1.1.2.4.1.9"   # dot1xAuthSessionUserName
OID_IF_OPER = "1.3.6.1.2.1.2.2.1.8"                     # ifOperStatus 1 up 2 down
OID_BRIDGE_PORT_IF = "1.3.6.1.2.1.17.1.4.1.2"           # dot1dBasePortIfIndex (bridge port -> ifIndex)
OID_PVID = "1.3.6.1.2.1.17.7.1.4.5.1.1"                 # dot1qPvid, indexed by bridge port

PAE_STATES = {1: "initializing", 2: "no 802.1X client", 3: "connecting", 4: "authenticating",
              5: "authenticated", 6: "aborting", 7: "held after a failed attempt", 8: "forced authorized",
              9: "forced unauthorized", 10: "restarting"}
OPER = {1: "up", 2: "down", 3: "testing", 5: "dormant", 6: "not present", 7: "lower layer down"}
CONTROL = {1: "force-unauthorized", 2: "auto", 3: "force-authorized"}

RADIUS_EXT_COLS = {3: "address", 4: "port", 6: "requests", 7: "retransmissions", 8: "accepts",
                   9: "rejects", 12: "bad_authenticators", 13: "pending", 14: "timeouts"}
RADIUS_OLD_COLS = {2: "address", 3: "port", 5: "requests", 6: "retransmissions", 7: "accepts",
                   8: "rejects", 11: "bad_authenticators", 12: "pending", 13: "timeouts"}

_LINE_RE = re.compile(r"^\.?(?P<oid>[0-9][0-9.]*)\s*=\s*(?P<val>.*)$")
_PASS_RE = re.compile(r"^[\x21-\x7e]{8,64}$")   # printable ASCII, no spaces/quotes issues below
_USER_RE = re.compile(r"^[A-Za-z0-9._@-]{1,32}$")


class SnmpError(Exception):
    pass


def validate_username(v):
    v = (v or "").strip()
    if not _USER_RE.match(v):
        raise ValueError("Use 1–32 characters: letters, digits, . _ @ -")
    return v


def validate_passphrase(v, label):
    if not _PASS_RE.match(v or ""):
        raise ValueError("%s must be 8–64 printable characters without spaces." % label)
    if '"' in v or "\\" in v:
        raise ValueError("%s must not contain \" or \\." % label)
    return v


# ------------------------------------------------------------------ parsing
def parse_output(text):
    """Net-SNMP output with -On -OQ -Oe -Ot -Ox... -> {oid: value_str} (quotes removed)."""
    out = {}
    for line in text.splitlines():
        m = _LINE_RE.match(line.strip())
        if not m:
            continue
        val = m.group("val").strip()
        if val.startswith('"') and val.endswith('"') and len(val) >= 2:
            val = val[1:-1]
        if val.startswith("No Such") or val.startswith("No more variables"):
            continue
        out[m.group("oid")] = val
    return out


def _children(values, base):
    """{suffix_tuple: value} for every oid under base."""
    pre = base + "."
    res = {}
    for oid, v in values.items():
        if oid.startswith(pre):
            res[tuple(int(x) for x in oid[len(pre):].split("."))] = v
    return res


def _hex_to_text(v):
    """Net-SNMP -Ox prints octet strings as hex ('C0 00 02 05'); decode for addresses."""
    h = v.replace(" ", "").replace(":", "")
    if not h or len(h) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", h):
        return v
    return bytes.fromhex(h)


def decode_address(v):
    if isinstance(v, str) and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", v):
        return v
    b = _hex_to_text(v)
    if isinstance(b, bytes):
        if len(b) in (4, 16):
            return str(ipaddress.ip_address(b))
        try:
            return b.decode("ascii")
        except UnicodeDecodeError:
            return b.hex()
    return v


def _int(v):
    try:
        return int(str(v).split()[0].strip("()"))
    except (ValueError, IndexError):
        return None


_SHORT_IF_RE = re.compile(r"^(gi|te|fa|tw|fo|hu)(\d+)$", re.IGNORECASE)


def cli_port_name(name):
    """Standalone Catalyst 1300 switches report ifName 'gi4'; the CLI (and the CSV
    export) call that port 'gi1/0/4'. Stack members already report 'te1/0/1'."""
    m = _SHORT_IF_RE.match(name.strip())
    if m:
        return "%s1/0/%s" % (m.group(1).lower(), m.group(2))
    return name.strip()


def compress_ports(names):
    """['te1/0/1','te1/0/2','te1/0/3','te1/0/23'] -> 'te1/0/1-3,te1/0/23' (CSV format)."""
    groups = {}
    order = []
    loose = []
    for n in names:
        m = re.match(r"^(.*?)(\d+)$", n)
        if not m:
            loose.append(n)
            continue
        pre, num = m.group(1), int(m.group(2))
        if pre not in groups:
            groups[pre] = []
            order.append(pre)
        groups[pre].append(num)
    parts = []
    for pre in order:
        nums = sorted(set(groups[pre]))
        start = prev = nums[0]
        for n in nums[1:] + [None]:
            if n is not None and n == prev + 1:
                prev = n
                continue
            parts.append("%s%d" % (pre, start) if start == prev else "%s%d-%d" % (pre, start, prev))
            if n is not None:
                start = prev = n
    return ",".join(parts + loose)


def build_status(system, port_control, if_names, radius_ext, radius_old):
    """Turn raw walk results ({oid: value}) into the stored status dict."""
    st = {"sys_descr": system.get(OID_SYS_DESCR, "")[:500],
          "sys_name": system.get(OID_SYS_NAME, "")[:200],
          "uptime_seconds": None}
    up = system.get(OID_SYS_UPTIME)
    if up is not None:
        t = _int(up)   # -Ot prints raw timeticks
        st["uptime_seconds"] = t // 100 if t is not None else None
    ctl = _children(port_control, OID_DOT1X_PORT_CONTROL)
    names = {k[0]: v for k, v in _children(if_names, OID_IF_NAME).items()}
    st["dot1x_supported"] = bool(ctl)
    auto = []
    for (idx,), v in sorted(ctl.items()):
        if _int(v) == 2:
            auto.append(cli_port_name(names.get(idx, "if%d" % idx)))
    st["dot1x_ports"] = compress_ports(auto)
    st["dot1x_port_count"] = len(auto)
    servers = {}
    for values, base, cols in ((radius_ext, OID_RADIUS_EXT, RADIUS_EXT_COLS),
                               (radius_old, OID_RADIUS_OLD, RADIUS_OLD_COLS)):
        rows = _children(values, base)
        if not rows:
            continue
        for key, v in rows.items():
            col, idx = key[0], key[1:] if len(key) > 1 else (0,)
            field = cols.get(col)
            if not field:
                continue
            s = servers.setdefault(idx, {})
            s[field] = decode_address(v) if field == "address" else _int(v)
        break   # prefer the extended table when present
    st["radius_servers"] = [dict(s, index=".".join(str(i) for i in k)) for k, s in sorted(servers.items())]
    return st


def _octets_text(v):
    """Net-SNMP prints printable octet strings quoted (removed by parse_output) and
    binary ones as hex; MAB user names are MACs either way."""
    b = _hex_to_text(v) if re.fullmatch(r"([0-9A-Fa-f]{2} ?)+", v or "") else v
    if isinstance(b, bytes):
        try:
            return b.decode("ascii")
        except UnicodeDecodeError:
            return b.hex()
    return (b or "").strip()


def build_ports(port_control, if_names, pae, status, oper, users, bridge_if, pvid):
    """Per-port 802.1X detail for the ports with port-control auto (the 802.1X ports).
    Every input is a raw walk result ({oid: value}); missing tables just leave fields None."""
    ctl = _children(port_control, OID_DOT1X_PORT_CONTROL)
    names = {k[0]: v for k, v in _children(if_names, OID_IF_NAME).items()}
    pae_v = {k[0]: _int(v) for k, v in _children(pae, OID_DOT1X_PAE_STATE).items()}
    st_v = {k[0]: _int(v) for k, v in _children(status, OID_DOT1X_PORT_STATUS).items()}
    oper_v = {k[0]: _int(v) for k, v in _children(oper, OID_IF_OPER).items()}
    user_v = {k[0]: _octets_text(v) for k, v in _children(users, OID_DOT1X_SESSION_USER).items()}
    bp_if = {k[0]: _int(v) for k, v in _children(bridge_if, OID_BRIDGE_PORT_IF).items()}
    if_bp = {ifx: bp for bp, ifx in bp_if.items() if ifx is not None}
    pvid_v = {k[0]: _int(v) for k, v in _children(pvid, OID_PVID).items()}
    out = []
    for (idx,), v in sorted(ctl.items()):
        if _int(v) != 2:
            continue
        status_code = st_v.get(idx)
        op = oper_v.get(idx)
        pae_state = pae_v.get(idx)
        authorized = None if status_code is None else status_code == 1
        if authorized:
            text = "authorized"
        elif op is not None and op != 1:
            text = "link " + OPER.get(op, str(op))
        elif pae_state is not None:
            text = PAE_STATES.get(pae_state, "state %d" % pae_state)
        else:
            text = "unauthorized" if authorized is False else ""
        bport = if_bp.get(idx, idx)      # many switches number bridge ports like ifIndex
        out.append({"ifindex": idx, "name": cli_port_name(names.get(idx, "if%d" % idx)),
                    "authorized": authorized, "pae": pae_state, "state_text": text,
                    "oper": OPER.get(op) if op is not None else None,
                    "user": (user_v.get(idx) or "")[:253], "vlan": pvid_v.get(bport)})
    return out


# ---------------------------------------------------------------- execution
class Session:
    """Credentials in a private snmp.conf; use as a context manager."""

    def __init__(self, username, auth_protocol, auth_pass, priv_protocol, priv_pass,
                 timeout=2, retries=1):
        validate_username(username)
        validate_passphrase(auth_pass, "Authentication passphrase")
        validate_passphrase(priv_pass, "Privacy passphrase")
        if auth_protocol not in ("SHA-256", "SHA-384", "SHA-512") or priv_protocol != "AES":
            raise SnmpError("only SHA-256/384/512 authentication and AES-128 privacy are allowed")
        # Values are quoted (Net-SNMP config strings); the validators exclude '"', '\\',
        # whitespace and control characters, so nothing can break out of the quotes.
        self._conf = ('defVersion 3\ndefSecurityLevel authPriv\ndefSecurityName "%s"\n'
                      'defAuthType %s\ndefPrivType AES\ndefAuthPassphrase "%s"\ndefPrivPassphrase "%s"\n'
                      % (username, auth_protocol, auth_pass, priv_pass))
        self.timeout, self.retries = int(timeout), int(retries)
        self.dir = None

    def __enter__(self):
        self.dir = tempfile.mkdtemp(prefix="ra-snmp.")
        os.chmod(self.dir, 0o700)
        p = os.path.join(self.dir, "snmp.conf")
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(self._conf)
        self._conf = None
        return self

    def __exit__(self, *exc):
        if self.dir:
            p = os.path.join(self.dir, "snmp.conf")
            try:
                size = os.path.getsize(p)
                with open(p, "r+b") as fh:
                    fh.write(b"\0" * size)
            except OSError:
                pass
            shutil.rmtree(self.dir, ignore_errors=True)
            self.dir = None

    def _env(self):
        return {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "SNMPCONFPATH": self.dir,
                "SNMP_PERSISTENT_DIR": self.dir, "MIBS": "", "MIBDIRS": "/nonexistent", "HOME": self.dir}

    def run(self, prog, host, oids, hex_strings=False, deadline=30):
        if prog not in (SNMPGET, SNMPWALK):
            raise SnmpError("bad program")
        ipaddress.ip_address(host)   # only literal addresses, never names/options
        argv = [prog, "-On", "-OQ", "-Oe", "-Ot", "-t", str(self.timeout), "-r", str(self.retries)]
        if hex_strings:
            argv.append("-Ox")
        target = ("udp6:[%s]" % host) if ":" in host else ("udp:%s" % host)
        argv += [target] + list(oids)
        try:
            p = subprocess.run(argv, env=self._env(), stdin=subprocess.DEVNULL, capture_output=True,
                               text=True, timeout=deadline, check=False)
        except subprocess.TimeoutExpired:
            raise SnmpError("no answer within %d s" % deadline) from None
        except FileNotFoundError:
            raise SnmpError("Net-SNMP tools are not installed (apt install snmp)") from None
        err = (p.stderr or "").strip().splitlines()
        if p.returncode != 0 and not p.stdout.strip():
            msg = err[-1] if err else "exit %d" % p.returncode
            if "Timeout" in msg:
                msg = "no response (wrong address, credentials or access list?)"
            raise SnmpError(msg[:300])
        return parse_output(p.stdout)


def poll_switch(session, host):
    """Return a status dict; raises SnmpError when the switch does not answer."""
    system = session.run(SNMPGET, host, [OID_SYS_DESCR, OID_SYS_UPTIME, OID_SYS_NAME])
    if not system:
        raise SnmpError("no system information returned")
    ctl = session.run(SNMPWALK, host, [OID_DOT1X_PORT_CONTROL])
    names = session.run(SNMPWALK, host, [OID_IF_NAME]) if ctl else {}
    ext = session.run(SNMPWALK, host, [OID_RADIUS_EXT], hex_strings=True)
    old = {} if ext else session.run(SNMPWALK, host, [OID_RADIUS_OLD], hex_strings=True)
    st = build_status(system, ctl, names, ext, old)
    st["ports"] = []
    if st["dot1x_port_count"]:
        def walk(oid, hx=False):
            try:
                return session.run(SNMPWALK, host, [oid], hex_strings=hx)
            except SnmpError:
                return {}       # optional table (not every firmware has it)
        st["ports"] = build_ports(ctl, names, walk(OID_DOT1X_PAE_STATE), walk(OID_DOT1X_PORT_STATUS),
                                  walk(OID_IF_OPER), walk(OID_DOT1X_SESSION_USER, True),
                                  walk(OID_BRIDGE_PORT_IF), walk(OID_PVID))
    return st


def single_host(ipaddr):
    """The address to poll for a client entry, or None for networks / unusable entries."""
    try:
        net = ipaddress.ip_network(ipaddr, strict=False)
    except ValueError:
        return None
    if net.num_addresses != 1:
        return None
    return str(net.network_address)
