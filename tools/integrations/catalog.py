#!/usr/bin/env python3
"""Maintain integrations/catalog.json, the provider builds this project has checked
(SPEC section 29). Every change bumps the serial.

    catalog.py add PROVIDER VERSION FILE --vendor-sha256 HEX [--min-radius-admin X.Y.Z]
    catalog.py fips PROVIDER VERSION TESTED-ON [TESTED-ON ...]   # after the FIPS VM checks
    catalog.py withdraw PROVIDER VERSION
    catalog.py check
    catalog.py sign KEY.pem [OUT.sig]          # the release job does this (make-release.sh)
    catalog.py verify PUBKEY.pem [SIG]

`add` hashes the downloaded FILE and refuses unless the SHA-256 equals --vendor-sha256, the
value copied from the vendor's own checksum page: two independent sources must agree. FILE
must be the vendor's unmodified file with the expected name.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CATALOG = os.path.normpath(os.path.join(HERE, "..", "..", "integrations", "catalog.json"))
# Same rules as the root helper (helper/radius-admin-helper, INTEGRATIONS)
PROVIDERS = {"duo": {"file": "duoauthproxy-%s-src.tgz", "url_prefix": "https://dl.duosecurity.com/"}}
VERSION_RE = re.compile(r"\d{1,4}\.\d{1,4}\.\d{1,4}")
TESTED_RE = re.compile(r"[A-Za-z0-9._-]{1,40}")


def die(msg):
    print("catalog: " + msg, file=sys.stderr)
    sys.exit(1)


def load(path=None):
    with open(path or CATALOG, encoding="utf-8") as fh:
        cat = json.load(fh)
    check(cat)
    return cat


def save(cat, path=None):
    check(cat)
    with open(path or CATALOG, "w", encoding="utf-8") as fh:
        json.dump(cat, fh, indent=1, sort_keys=True)
        fh.write("\n")


def check(cat):
    if not (isinstance(cat, dict) and cat.get("format") == 1 and isinstance(cat.get("serial"), int)
            and cat["serial"] >= 1 and isinstance(cat.get("entries"), list)):
        die("unknown catalog format")
    seen = set()
    for e in cat["entries"]:
        prov = PROVIDERS.get(e.get("provider"))
        if prov is None or not VERSION_RE.fullmatch(str(e.get("version"))):
            die("invalid entry %r" % e)
        name = prov["file"] % e["version"]
        if (e.get("file") != name or e.get("url") != prov["url_prefix"] + name
                or not isinstance(e.get("size"), int) or e["size"] <= 0
                or not re.fullmatch(r"[0-9a-f]{64}", str(e.get("sha256")))
                or not isinstance(e.get("fips", False), bool) or not isinstance(e.get("withdrawn", False), bool)
                or not all(TESTED_RE.fullmatch(x) for x in e.get("fips_tested", []))
                or (e.get("fips") and not e.get("fips_tested"))):
            die("invalid entry for %s %s" % (e["provider"], e["version"]))
        if (e["provider"], e["version"]) in seen:
            die("duplicate entry for %s %s" % (e["provider"], e["version"]))
        seen.add((e["provider"], e["version"]))


def find(cat, provider, version):
    for e in cat["entries"]:
        if e["provider"] == provider and e["version"] == version:
            return e
    die("no entry for %s %s" % (provider, version))


def cmd_add(a):
    prov = PROVIDERS.get(a.provider) or die("unknown provider %s" % a.provider)
    if not VERSION_RE.fullmatch(a.version):
        die("version must be X.Y.Z")
    name = prov["file"] % a.version
    if os.path.basename(a.file) != name:
        die("the file must be the vendor's %s" % name)
    h, size = hashlib.sha256(), 0
    with open(a.file, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
            size += len(chunk)
    digest = h.hexdigest()
    if digest != a.vendor_sha256.strip().lower():
        die("SHA-256 %s does not match the vendor's %s: do not add this file" % (digest, a.vendor_sha256))
    cat = load()
    if any(e["provider"] == a.provider and e["version"] == a.version for e in cat["entries"]):
        die("%s %s is already in the catalog" % (a.provider, a.version))
    entry = {"provider": a.provider, "version": a.version, "file": name, "url": prov["url_prefix"] + name,
             "size": size, "sha256": digest, "fips": False, "fips_tested": [], "withdrawn": False}
    if a.min_radius_admin:
        if not VERSION_RE.fullmatch(a.min_radius_admin):
            die("--min-radius-admin must be X.Y.Z")
        entry["min_radius_admin"] = a.min_radius_admin
    cat["entries"].append(entry)
    cat["entries"].sort(key=lambda e: (e["provider"], [int(x) for x in e["version"].split(".")]))
    cat["serial"] += 1
    save(cat)
    print("added %s %s (%d bytes, SHA-256 %s); serial %d" % (a.provider, a.version, size, digest, cat["serial"]))


def cmd_fips(a):
    cat = load()
    e = find(cat, a.provider, a.version)
    for t in a.tested_on:
        if not TESTED_RE.fullmatch(t):
            die("invalid platform name %r" % t)
    e["fips"] = True
    e["fips_tested"] = sorted(set(e.get("fips_tested", [])) | set(a.tested_on))
    cat["serial"] += 1
    save(cat)
    print("%s %s marked FIPS-capable (%s); serial %d" % (a.provider, a.version, ", ".join(e["fips_tested"]),
                                                         cat["serial"]))


def cmd_withdraw(a):
    cat = load()
    find(cat, a.provider, a.version)["withdrawn"] = True
    cat["serial"] += 1
    save(cat)
    print("%s %s withdrawn; serial %d" % (a.provider, a.version, cat["serial"]))


def cmd_check(a):
    cat = load(a.catalog)
    print("catalog serial %d, %d entries: ok" % (cat["serial"], len(cat["entries"])))


def cmd_sign(a):
    load(a.catalog)
    out = a.out or a.catalog + ".sig"
    subprocess.run(["openssl", "dgst", "-sha384", "-sign", a.key, "-out", out, a.catalog], check=True)
    print("signed %s -> %s" % (a.catalog, out))


def cmd_verify(a):
    sig = a.sig or a.catalog + ".sig"
    r = subprocess.run(["openssl", "dgst", "-sha384", "-verify", a.pubkey, "-signature", sig, a.catalog],
                       capture_output=True, text=True)
    if r.returncode != 0 or "Verified OK" not in r.stdout:
        die("the signature does not verify")
    print("Verified OK")


def main(argv=None):
    global CATALOG
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--catalog", default=CATALOG)
    sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser("add")
    p.add_argument("provider")
    p.add_argument("version")
    p.add_argument("file")
    p.add_argument("--vendor-sha256", required=True)
    p.add_argument("--min-radius-admin")
    p = sp.add_parser("fips")
    p.add_argument("provider")
    p.add_argument("version")
    p.add_argument("tested_on", nargs="+")
    p = sp.add_parser("withdraw")
    p.add_argument("provider")
    p.add_argument("version")
    sp.add_parser("check")
    p = sp.add_parser("sign")
    p.add_argument("key")
    p.add_argument("out", nargs="?")
    p = sp.add_parser("verify")
    p.add_argument("pubkey")
    p.add_argument("sig", nargs="?")
    a = ap.parse_args(argv)
    CATALOG = a.catalog
    {"add": cmd_add, "fips": cmd_fips, "withdraw": cmd_withdraw, "check": cmd_check, "sign": cmd_sign,
     "verify": cmd_verify}[a.cmd](a)


if __name__ == "__main__":
    main()
