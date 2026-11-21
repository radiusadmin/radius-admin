#!/usr/bin/env python3
"""Bench stand-in for a second-factor provider (SPEC section 29). TEST ONLY.

  fake-mfa-proxy.py --mode duo --listen 127.0.0.1:18120 --secret S
                    --primary 127.0.0.1:18121 --primary-secret P --decisions FILE --log FILE
  fake-mfa-proxy.py --mode remote --listen 127.0.0.1:18130 --secret S --password PW
                    --decisions FILE --log FILE

duo:    acts like the Duo Authentication Proxy's [radius_server_auto] section with
        client=radius_client: the Access-Request from FreeRADIUS is sent on (User-Name,
        User-Password, Message-Authenticator) to the primary server (radius-admin-mfa-primary);
        a reject is passed back without a second factor; on accept the "second factor" is
        asked and, when approved, Access-Accept goes back with the primary's Class.
remote: a remote RADIUS MFA server: checks the password itself (--password), asks the
        second factor and answers with extra attributes (Reply-Message, Session-Timeout and a
        forged Class) that FreeRADIUS must not pass on to the device.

The second factor's answer comes from the JSON file --decisions, re-read for every
request: {"<user name>": "allow" | "deny" | "silent" | "noclass" | "slow" | "slow40"}; a missing name
means "allow". silent = never answer; noclass = approve but drop the Class (duo);
slow = approve after 3 seconds, slow40 after 40 seconds. Every second-factor prompt is appended to --log as
"<user name> <decision>", so the bench can count prompts. Duplicate requests (same source,
identifier and authenticator, RFC 5080 section 2.2.2) get the cached answer and no new prompt.
"""
import argparse
import hashlib
import hmac
import json
import os
import socket
import struct
import threading
import time

ACCESS_REQUEST, ACCESS_ACCEPT, ACCESS_REJECT = 1, 2, 3
USER_NAME, USER_PASSWORD, REPLY_MESSAGE, CLASS, SESSION_TIMEOUT, PROXY_STATE, NAS_IP = 1, 2, 18, 25, 27, 33, 4
MESSAGE_AUTHENTICATOR = 80


def md5(data):
    return hashlib.md5(data, usedforsecurity=False).digest()


def parse(pkt):
    code, ident, length = struct.unpack("!BBH", pkt[:4])
    auth = pkt[4:20]
    attrs, i = [], 20
    while i < length:
        t, ln = pkt[i], pkt[i + 1]
        attrs.append((t, pkt[i + 2:i + ln]))
        i += ln
    return code, ident, auth, attrs


def build(code, ident, auth, attrs):
    body = b"".join(struct.pack("!BB", t, len(v) + 2) + v for t, v in attrs)
    return struct.pack("!BBH", code, ident, 20 + len(body)) + auth + body


def with_message_authenticator(code, ident, auth, attrs, secret):
    """attrs + Message-Authenticator, HMAC-MD5 over the packet with the MA zeroed and
    `auth` (request authenticator) in the authenticator field (RFC 3579 section 3.2)."""
    attrs = [a for a in attrs if a[0] != MESSAGE_AUTHENTICATOR] + [(MESSAGE_AUTHENTICATOR, b"\0" * 16)]
    mac = hmac.new(secret, build(code, ident, auth, attrs), hashlib.md5).digest()
    return attrs[:-1] + [(MESSAGE_AUTHENTICATOR, mac)]


def check_message_authenticator(pkt, secret):
    code, ident, auth, attrs = parse(pkt)
    got = [v for t, v in attrs if t == MESSAGE_AUTHENTICATOR]
    if not got:
        return False
    zeroed = [(t, b"\0" * 16 if t == MESSAGE_AUTHENTICATOR else v) for t, v in attrs]
    return hmac.compare_digest(hmac.new(secret, build(code, ident, auth, zeroed), hashlib.md5).digest(), got[0])


def decrypt_password(enc, secret, auth):
    out, last = b"", auth
    for i in range(0, len(enc), 16):
        block = enc[i:i + 16]
        out += bytes(a ^ b for a, b in zip(block, md5(secret + last)))
        last = block
    return out.rstrip(b"\0")


def encrypt_password(pw, secret, auth):
    pw += b"\0" * (-len(pw) % 16 or (16 if not pw else 0))
    out, last = b"", auth
    for i in range(0, len(pw), 16):
        block = bytes(a ^ b for a, b in zip(pw[i:i + 16], md5(secret + last)))
        out += block
        last = block
    return out


def reply(code, ident, req_auth, attrs, secret):
    attrs = with_message_authenticator(code, ident, req_auth, attrs, secret)
    pkt = build(code, ident, req_auth, attrs)
    return pkt[:4] + md5(pkt + secret) + pkt[20:]


def decision(path, user):
    try:
        with open(path) as fh:
            return json.load(fh).get(user, "allow")
    except (OSError, ValueError):
        return "allow"


class Fake:
    def __init__(self, a):
        self.a = a
        self.secret = a.secret.encode()
        self.lock = threading.Lock()
        self.seen = {}          # (src, id, authenticator) -> reply bytes or None while running
        host, port = a.listen.rsplit(":", 1)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, int(port)))

    def log(self, user, what):
        with self.lock, open(self.a.log, "a") as fh:
            fh.write("%s %s\n" % (user, what))

    def primary(self, user, password):
        """Send the password check to radius-admin-mfa-primary. Returns (code, Class values)."""
        secret = self.a.primary_secret.encode()
        auth = os.urandom(16)
        ident = auth[0]
        attrs = [(USER_NAME, user), (USER_PASSWORD, encrypt_password(password, secret, auth)),
                 (NAS_IP, socket.inet_aton("127.0.0.1"))]
        attrs = with_message_authenticator(ACCESS_REQUEST, ident, auth, attrs, secret)
        host, port = self.a.primary.rsplit(":", 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(10)
        try:
            s.sendto(build(ACCESS_REQUEST, ident, auth, attrs), (host, int(port)))
            pkt, _ = s.recvfrom(4096)
        except OSError:
            return None, []
        finally:
            s.close()
        code, rid, rauth, rattrs = parse(pkt)
        check = pkt[:4] + auth + pkt[20:]
        if rid != ident or not hmac.compare_digest(md5(check + secret), rauth):
            return None, []
        if not check_message_authenticator(pkt[:4] + auth + pkt[20:], secret):
            return None, []
        return code, [v for t, v in rattrs if t == CLASS]

    def handle(self, pkt, src):
        try:
            code, ident, auth, attrs = parse(pkt)
        except (IndexError, struct.error):
            return
        if code != ACCESS_REQUEST or not check_message_authenticator(pkt, self.secret):
            return
        key = (src, ident, auth)
        with self.lock:
            if key in self.seen:
                cached = self.seen[key]
                if cached:
                    self.sock.sendto(cached, src)
                return
            self.seen[key] = None
        user = b"".join(v for t, v in attrs if t == USER_NAME)
        enc = b"".join(v for t, v in attrs if t == USER_PASSWORD)
        password = decrypt_password(enc, self.secret, auth)
        proxy_state = [(t, v) for t, v in attrs if t == PROXY_STATE]
        name = user.decode("utf-8", "replace")
        if self.a.mode == "duo":
            pcode, classes = self.primary(user, password)
            if pcode != ACCESS_ACCEPT:
                self.log(name, "primary-reject")
                out = (ACCESS_REJECT, [(REPLY_MESSAGE, b"Login failed")])
            else:
                out = self.second_factor(name, [(CLASS, c) for c in classes])
        else:
            if password != self.a.password.encode():
                self.log(name, "password-reject")
                out = (ACCESS_REJECT, [])
            else:
                out = self.second_factor(name, [(REPLY_MESSAGE, b"remote says hello"),
                                                (SESSION_TIMEOUT, struct.pack("!I", 999)),
                                                (CLASS, b"radius-admin:pap-admin")])
        if out is None:
            return
        data = reply(out[0], ident, auth, out[1] + proxy_state, self.secret)
        with self.lock:
            self.seen[key] = data
        self.sock.sendto(data, src)

    def second_factor(self, name, accept_attrs):
        d = decision(self.a.decisions, name)
        self.log(name, d)
        if d == "silent":
            return None
        if d == "deny":
            return ACCESS_REJECT, [(REPLY_MESSAGE, b"Second factor denied")]
        if d == "slow":
            time.sleep(3)
        elif d == "slow40":
            time.sleep(40)
        if d == "noclass":
            accept_attrs = [x for x in accept_attrs if x[0] != CLASS]
        return ACCESS_ACCEPT, accept_attrs

    def serve(self):
        while True:
            pkt, src = self.sock.recvfrom(4096)
            threading.Thread(target=self.handle, args=(pkt, src), daemon=True).start()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=("duo", "remote"), required=True)
    ap.add_argument("--listen", required=True)
    ap.add_argument("--secret", required=True)
    ap.add_argument("--primary", default="127.0.0.1:18121")
    ap.add_argument("--primary-secret", default="")
    ap.add_argument("--password", default="")
    ap.add_argument("--decisions", required=True)
    ap.add_argument("--log", required=True)
    Fake(ap.parse_args()).serve()


if __name__ == "__main__":
    main()
