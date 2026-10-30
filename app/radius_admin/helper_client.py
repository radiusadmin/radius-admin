"""Client for the root helper (SPEC section 6): one JSON line in, one JSON line out."""
import json
import socket

MAX_LINE = 1024 * 1024  # responses may carry up to 200 lines of radiusd output
BACKUP_ID_RE = r"^\d{8}T\d{6}Z$"


class HelperError(Exception):
    pass


def call(socket_path: str, action: str, timeout: float = 120, **params) -> dict:
    req = dict(params)
    req["action"] = action
    data = (json.dumps(req, separators=(",", ":")) + "\n").encode("utf-8")
    if len(data) > 64 * 1024:
        raise HelperError("request too large")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        try:
            s.connect(socket_path)
        except OSError as e:
            raise HelperError("helper unavailable (%s)" % (e.strerror or e)) from None
        s.sendall(data)
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
            if len(buf) > MAX_LINE:
                raise HelperError("helper response too large")
    except socket.timeout:
        raise HelperError("helper timed out") from None
    finally:
        s.close()
    line = buf.split(b"\n", 1)[0]
    if not line:
        raise HelperError("empty response from helper")
    try:
        resp = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise HelperError("malformed response from helper") from None
    if not isinstance(resp, dict) or "ok" not in resp:
        raise HelperError("malformed response from helper")
    resp.setdefault("message", "")
    return resp
