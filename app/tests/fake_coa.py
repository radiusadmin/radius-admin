"""A minimal RFC 5176 dynamic-authorization server standing in for a switch (tests only).

Verifies the Request Authenticator and Message-Authenticator with the shared secret,
records the decoded attributes, and answers ACK (or NAK when told to). MD5 here is the
RADIUS protocol's own packet integrity check; the test sandbox is not in FIPS mode.
"""
import hashlib
import hmac
import socket
import struct
import threading

CODES = {40: "Disconnect-Request", 43: "CoA-Request"}
ACK = {40: 41, 43: 44}
NAK = {40: 42, 43: 45}
ATTR_NAMES = {1: "User-Name", 4: "NAS-IP-Address", 31: "Calling-Station-Id", 44: "Acct-Session-Id",
              55: "Event-Timestamp", 80: "Message-Authenticator", 87: "NAS-Port-Id", 101: "Error-Cause"}


def _attrs(data):
    out, i = [], 0
    while i + 2 <= len(data):
        t, ln = data[i], data[i + 1]
        if ln < 2 or i + ln > len(data):
            break
        out.append((t, data[i + 2:i + ln]))
        i += ln
    return out


class FakeSwitch:
    def __init__(self, secret, host="127.0.0.1", nak=False):
        self.secret = secret.encode()
        self.nak = nak
        self.requests = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, 0))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.2)
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def close(self):
        self._stop.set()
        self.thread.join(2)
        self.sock.close()

    def _run(self):
        while not self._stop.is_set():
            try:
                data, peer = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            self._handle(data, peer)

    def _handle(self, data, peer):
        code, ident, length = struct.unpack("!BBH", data[:4])
        req_auth = data[4:20]
        body = data[20:length]
        # Request Authenticator = MD5(Code+ID+Length+16 zero octets+Attributes+Secret)
        expect = hashlib.md5(data[:4] + b"\0" * 16 + body + self.secret).digest()
        attrs = _attrs(body)
        rec = {"code": CODES.get(code, code), "auth_ok": expect == req_auth, "attrs": {}, "cisco": []}
        for t, v in attrs:
            if t == 26 and len(v) > 6 and struct.unpack("!I", v[:4])[0] == 9:
                for vt, vv in _attrs(v[4:]):
                    if vt == 1:
                        rec["cisco"].append(vv.decode(errors="replace"))
            elif t == 80:
                # RFC 5176 3.5: computed over the packet with the Request Authenticator
                # field and the Message-Authenticator value both set to zeros
                zeroed = data[:4] + b"\0" * 16 + body.replace(b"\x50\x12" + v, b"\x50\x12" + b"\0" * 16, 1)
                rec["msg_auth_ok"] = hmac.new(self.secret, zeroed, "md5").digest() == v
            else:
                name = ATTR_NAMES.get(t, str(t))
                rec["attrs"][name] = (socket.inet_ntoa(v) if t == 4 else
                                      struct.unpack("!I", v)[0] if t == 55 else v.decode(errors="replace"))
        self.requests.append(rec)
        if not rec["auth_ok"]:
            return      # a real switch silently drops packets with a bad authenticator
        rcode = (NAK if self.nak else ACK)[code]
        rattrs = b""
        if self.nak:
            rattrs += struct.pack("!BBI", 101, 6, 503)      # Error-Cause = Session-Context-Not-Found
        rlen = 20 + len(rattrs)
        hdr = struct.pack("!BBH", rcode, ident, rlen)
        resp_auth = hashlib.md5(hdr + req_auth + rattrs + self.secret).digest()
        self.sock.sendto(hdr + resp_auth + rattrs, peer)
