#!/usr/bin/env python3
"""Bench stand-in for Samba's ntlm_auth (there is no domain to join in the sandbox).

mods-available/mschap runs it as
    fake-ntlm-auth.py --log=FILE --request-nt-key --allow-mschapv2 --username=U
                      --challenge=<8-byte challenge hash, hex> --nt-response=<24 bytes, hex>
It checks the MSCHAPv2 NT-Response the way a domain controller does (DES with the NT hash
of the password, RFC 2759) for the people of the emulated directory, prints
"NT_KEY: <MD4 of the NT hash>" and exits 0, or prints a logon failure and exits 1. Every
call is appended to FILE so the bench can see who reached the "domain controller".
TEST ONLY.
"""
import os
import sys
import warnings

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "app"))
from radius_admin.crypto import _md4  # noqa: E402

DIRECTORY = {"jroe": "Directory-User-Pass-2026", "labtech": "Directory-User-Pass-2026",
             "nogroup": "Directory-User-Pass-2026", "j.doe": "Directory-User-Pass-2026"}


def des(key7, block):
    warnings.simplefilter("ignore")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    n = int.from_bytes(key7, "big")
    key = bytes(((n >> (49 - 7 * i)) & 0x7F) << 1 for i in range(8))
    enc = Cipher(algorithms.TripleDES(key * 3), modes.ECB()).encryptor()   # K1=K2=K3: single DES
    return enc.update(block) + enc.finalize()


def main():
    args = dict(a[2:].split("=", 1) for a in sys.argv[1:] if a.startswith("--") and "=" in a)
    user = args.get("username", "").lower()
    with open(args["log"], "a") as fh:
        fh.write(user + "\n")
    try:
        challenge, response = bytes.fromhex(args["challenge"]), bytes.fromhex(args["nt-response"])
    except (KeyError, ValueError):
        print("Invalid arguments")
        return 1
    if user not in DIRECTORY:
        print("No such user (0xc0000064)")
        return 1
    nt = _md4(DIRECTORY[user].encode("utf-16-le"))
    k = nt + b"\0" * 5
    if len(challenge) != 8 or des(k[0:7], challenge) + des(k[7:14], challenge) + des(k[14:21], challenge) != response:
        print("Logon failure (0xc000006d)")
        return 1
    print("NT_KEY: " + _md4(nt).hex().upper())
    return 0


if __name__ == "__main__":
    sys.exit(main())
