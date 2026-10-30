#!/usr/bin/env python3
"""Print a FreeRADIUS Password-With-Header value in the SPEC section 0 format:
{X-PBKDF2}HMACSHA2+256:<b64 4-byte BE iterations>:<b64 salt>:<b64 hash>
Usage: pbkdf2_hash.py <password> [iterations]"""
import base64
import hashlib
import ssl
import struct
import sys

pw = sys.argv[1].encode("utf-8")
it = int(sys.argv[2]) if len(sys.argv) > 2 else 600000
salt = ssl.RAND_bytes(16)
dk = hashlib.pbkdf2_hmac("sha256", pw, salt, it, 32)
b = lambda x: base64.b64encode(x).decode("ascii")  # noqa: E731
print("{X-PBKDF2}HMACSHA2+256:%s:%s:%s" % (b(struct.pack(">I", it)), b(salt), b(dk)))
