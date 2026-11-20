#!/usr/bin/env python3
"""Check whether a Duo Authentication Proxy build may be marked FIPS-capable in the catalog
(SPEC section 29.4, RUNBOOK "FIPS check of a Duo build"). Maintainer tool for a lab VM with
Ubuntu 24.04 Pro fips-updates; never run it on a production server.

    duo-fips-check.py source  DUO-SRC.tgz                  # inspect Duo's source file (no code runs)
    duo-fips-check.py host                                 # the machine's FIPS state
    duo-fips-check.py installed [--duo-dir /opt/duoauthproxy] [--running]
    duo-fips-check.py all DUO-SRC.tgz [--duo-dir DIR] [--running] [--json OUT]

What it checks (R = required for `catalog.py fips`, M = the maintainer decides):
  R1 the kernel runs in FIPS mode (/proc/sys/crypto/fips_enabled = 1)
  R2 the system OpenSSL has an active FIPS provider (Ubuntu's validated module)
  R3 Duo's bundled FIPS provider (pkgs/fips_modules/<arch>/fips.so) is intact: HMAC-SHA256 with
     OpenSSL's fipsinstall key equals the module-mac in its openssl.cnf, in the source file and
     in the installed tree, and the installed copy is the one from the source file
  R4 the installed provider loads with Duo's openssl.cnf and passes its self-tests (active)
  R5 Duo's Python in FIPS mode (fips_mode) refuses MD5 and computes SHA-256
  R6 (--running) the applied configuration has fips_mode=true and failmode=secure, the proxy
     is active and listening on 127.0.0.1:18120, and its log says FIPS mode is enabled
  M1 the provider version is covered by an active CMVP certificate for OpenSSL's FIPS provider
     (https://csrc.nist.gov/projects/cryptographic-module-validation-program); this tool only
     prints the version
  M2 Duo's FIPS provider is a prebuilt binary and its `cryptography` wheel links its own
     OpenSSL; whether that satisfies "components run in FIPS mode" is a policy decision

Exit status: 0 when every required check that ran passed, 1 otherwise, 2 on usage errors.
Output: a readable report, and with --json the same as JSON (paste it into the release notes).
"""
import argparse
import hashlib
import hmac
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import time

# OpenSSL's fipsinstall default MAC key (FIPS_KEY_STRING in OpenSSL's apps/fipsinstall.c); public,
# it detects accidental or careless modification of the module, it is not a secret.
FIPS_KEY = bytes.fromhex("f4556650ac31d35461610bac4ed81b1a181b2d8a43ea2854cbae22ca74560813")
ARCHES = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "aarch64", "arm64": "aarch64"}
SRC_RE = re.compile(r"duoauthproxy-(\d{1,4}\.\d{1,4}\.\d{1,4})-src\Z")
MAX_MEMBER = 64 * 1024 * 1024


class Report:
    def __init__(self):
        self.checks, self.facts = [], {}

    def add(self, cid, ok, detail, required=True):
        """ok: True, False or None (not run)."""
        self.checks.append({"check": cid, "ok": ok, "required": required, "detail": detail})

    def passed(self):
        return all(c["ok"] is not False for c in self.checks if c["required"]) and any(
            c["ok"] for c in self.checks if c["required"])

    def text(self):
        out = []
        for c in self.checks:
            mark = {True: "PASS", False: "FAIL", None: "----"}[c["ok"]] if c["required"] else "INFO"
            out.append("%s  %-4s %s" % (mark, c["check"], c["detail"]))
        out.append("")
        for k in sorted(self.facts):
            out.append("%s: %s" % (k, self.facts[k]))
        return "\n".join(out)


def module_mac(cnf_text):
    """The module-mac of the [fips_sect] in an openssl.cnf, as lower-case hex, or None."""
    sect = None
    for line in cnf_text.splitlines():
        line = line.split("#", 1)[0].strip()
        m = re.fullmatch(r"\[\s*([^\]]+?)\s*\]", line)
        if m:
            sect = m.group(1)
        elif sect == "fips_sect" and "=" in line:
            k, v = (x.strip() for x in line.split("=", 1))
            if k == "module-mac":
                hexv = v.replace(":", "").lower()
                return hexv if re.fullmatch(r"[0-9a-f]{64}", hexv) else None
    return None


def provider_mac(data):
    return hmac.new(FIPS_KEY, data, hashlib.sha256).hexdigest()


def provider_version(data):
    """The version string the FIPS provider embeds after its name (read, never loaded)."""
    i = data.find(b"OpenSSL FIPS Provider\x00")
    if i < 0:
        return None
    m = re.search(rb"\x00(\d{1,2}\.\d{1,3}\.\d{1,3})\x00", data[i:i + 256])
    return m.group(1).decode() if m else None


def machine_arch():
    return ARCHES.get(platform.machine().lower(), platform.machine().lower())


# ---------------------------------------------------------------- source file
def check_source(path, rep, arch=None):
    """Inspect Duo's source tarball without extracting or running anything."""
    arch = arch or machine_arch()
    found = {}
    wheels = []
    with tarfile.open(path, "r:gz") as tf:
        top = None
        for m in tf.getmembers():
            first = m.name.split("/", 1)[0]
            top = top or first
            if first != top:
                rep.add("R3", False, "%s holds more than one top directory" % os.path.basename(path))
                return None
            parts = m.name.split("/")
            if len(parts) == 5 and parts[1:3] == ["pkgs", "fips_modules"] and m.isfile() and m.size <= MAX_MEMBER:
                found.setdefault(parts[3], {})[parts[4]] = tf.extractfile(m).read()
            if len(parts) == 3 and parts[1] == "pkgs" and parts[2].startswith("cryptography-"):
                wheels.append(parts[2])
    vm = SRC_RE.fullmatch(top or "")
    rep.facts["duo_version"] = vm.group(1) if vm else "unknown (%s)" % top
    rep.facts["source_sha256"] = _sha256_file(path)
    rep.facts["cryptography_wheels"] = ", ".join(sorted(wheels)) or "none"
    result = {}
    for a, files in sorted(found.items()):
        so, cnf = files.get("fips.so"), files.get("openssl.cnf")
        if so is None or cnf is None:
            rep.add("R3", False, "pkgs/fips_modules/%s lacks fips.so or openssl.cnf" % a)
            continue
        want, got = module_mac(cnf.decode("utf-8", "replace")), provider_mac(so)
        result[a] = {"sha256": hashlib.sha256(so).hexdigest(), "version": provider_version(so), "mac_ok": want == got}
        rep.add("R3" if a == arch else "R3-" + a, want == got,
                "source pkgs/fips_modules/%s/fips.so: FIPS provider %s, module-mac %s" % (
                    a, result[a]["version"] or "(version not found)", "matches" if want == got else
                    "DOES NOT MATCH (expected %s, computed %s)" % (want, got)), required=(a == arch))
    if not found:
        rep.add("R3", False, "the source file has no pkgs/fips_modules (no bundled FIPS provider)")
    elif arch not in found:
        rep.add("R3", False, "no bundled FIPS provider for this machine's architecture (%s)" % arch)
    if arch in result:
        rep.facts["fips_provider_version"] = result[arch]["version"]
    rep.add("M2", None, "the FIPS provider is a prebuilt binary from Duo; cryptography comes as %s"
            % (rep.facts["cryptography_wheels"]), required=False)
    return result


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------- host
def run(argv, env=None, timeout=60):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env)
        return p.returncode, (p.stdout + p.stderr)
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, str(e)


def providers(output):
    """{name-key: {name, version, status}} from `openssl list -providers`."""
    out, cur = {}, None
    for line in output.splitlines():
        if re.fullmatch(r"  \S+", line):
            cur = out.setdefault(line.strip(), {})
        elif cur is not None:
            m = re.fullmatch(r"\s{4}(name|version|status):\s*(.*)", line)
            if m:
                cur[m.group(1)] = m.group(2).strip()
    return out


def check_host(rep, proc="/proc/sys/crypto/fips_enabled", openssl="openssl"):
    try:
        with open(proc) as fh:
            on = fh.read().strip() == "1"
        rep.add("R1", on, "kernel FIPS mode %s (%s)" % ("on" if on else "OFF", proc))
    except OSError:
        rep.add("R1", False, "kernel FIPS mode OFF (%s missing)" % proc)
    rc, out = run([openssl, "list", "-providers"])
    fips = providers(out).get("fips") if rc == 0 else None
    ok = bool(fips) and fips.get("status") == "active"
    rep.add("R2", ok, "system OpenSSL FIPS provider: %s" % (
        "%s %s, %s" % (fips.get("name", "?"), fips.get("version", "?"), fips.get("status", "?")) if fips
        else "not loaded"))
    rc, out = run([openssl, "version"])
    rep.facts["system_openssl"] = out.strip() if rc == 0 else "not found"
    rep.facts["os"] = _os_release()
    if shutil.which("pro"):
        rc, out = run(["pro", "status", "--format", "json"])
        try:
            svc = {s["name"]: s.get("status") for s in json.loads(out).get("services", [])}
            rep.facts["ubuntu_pro"] = ", ".join("%s=%s" % (k, svc[k]) for k in ("fips", "fips-updates") if k in svc)
        except (ValueError, AttributeError, KeyError, TypeError):
            rep.facts["ubuntu_pro"] = "status not readable"


def _os_release():
    try:
        with open("/etc/os-release") as fh:
            kv = dict(ln.rstrip("\n").split("=", 1) for ln in fh if "=" in ln)
        return kv.get("PRETTY_NAME", "?").strip('"')
    except OSError:
        return "?"


# ---------------------------------------------------------------- installed proxy
PY_PROBE = r"""
import json, os, sys
d = sys.argv[1]
os.environ["OPENSSL_MODULES"] = d
os.environ["OPENSSL_CONF"] = os.path.join(d, "openssl.cnf")
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives import hashes
r = {"openssl": backend.openssl_version_text(), "fips_before": bool(backend._fips_enabled)}
backend._enable_fips()
r["fips"] = bool(backend._fips_enabled)
for a in (hashes.SHA256(), hashes.MD5()):
    try:
        h = hashes.Hash(a)
        h.update(b"radius-admin")
        h.finalize()
        r[a.name] = "ok"
    except Exception as e:
        r[a.name] = "refused (%s)" % type(e).__name__
print(json.dumps(r))
"""


def check_installed(rep, duo_dir, source=None, running=False, openssl="openssl"):
    ossl = os.path.join(duo_dir, "usr", "local", "openssl")
    so_p, cnf_p = os.path.join(ossl, "fips.so"), os.path.join(ossl, "openssl.cnf")
    try:
        with open(so_p, "rb") as fh:
            so = fh.read()
        with open(cnf_p, encoding="utf-8", errors="replace") as fh:
            cnf = fh.read()
    except OSError as e:
        rep.add("R3i", False, "installed FIPS provider not readable: %s" % e)
        return
    want, got = module_mac(cnf), provider_mac(so)
    digest = hashlib.sha256(so).hexdigest()
    same = None
    if source:
        same = (source.get(machine_arch()) or {}).get("sha256") == digest
    rep.add("R3i", want == got and same is not False,
            "installed %s: module-mac %s%s" % (so_p, "matches" if want == got else "DOES NOT MATCH",
                                                "" if same is None else ("; same file as in the source" if same
                                                                         else "; NOT the file from the source")))
    rep.facts["installed_fips_so_sha256"] = digest
    rep.facts["installed_fips_provider_version"] = provider_version(so)
    env = dict(os.environ, OPENSSL_MODULES=ossl, OPENSSL_CONF=cnf_p)
    rc, out = run([openssl, "list", "-providers"], env=env)
    p = providers(out).get("fips") if rc == 0 else None
    rep.add("R4", bool(p) and p.get("status") == "active",
            "Duo's FIPS provider with Duo's openssl.cnf: %s" % (
                "%s %s, %s (self-tests passed)" % (p.get("name"), p.get("version"), p.get("status")) if p
                else "did not load: %s" % " ".join(out.split())[:300]))
    py = os.path.join(duo_dir, "usr", "local", "bin", "python3")
    rc, out = run([py, "-I", "-c", PY_PROBE, ossl], env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    try:
        r = json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        rep.add("R5", False, "Duo's Python probe failed: %s" % " ".join(out.split())[:300])
    else:
        ok = r.get("fips") is True and r.get("sha256") == "ok" and str(r.get("md5", "")).startswith("refused")
        rep.add("R5", ok, "Duo's Python (cryptography, %s) in FIPS mode: SHA-256 %s, MD5 %s" % (
            r.get("openssl"), r.get("sha256"), r.get("md5")))
        rep.facts["duo_cryptography_openssl"] = r.get("openssl")
    if running:
        check_running(rep, duo_dir)
    else:
        rep.add("R6", None, "not checked (add --running after applying a FIPS configuration)")
    if rep.facts.get("installed_fips_provider_version"):
        rep.add("M1", None, "compare OpenSSL FIPS Provider %s with CMVP's active certificates"
                % rep.facts["installed_fips_provider_version"], required=False)


def check_running(rep, duo_dir, listen="127.0.0.1:18120"):
    cfg_p = os.path.join(duo_dir, "conf", "authproxy.cfg")
    try:
        with open(cfg_p, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as e:
        rep.add("R6", False, "cannot read %s: %s" % (cfg_p, e))
        return
    keys = dict(re.findall(r"(?m)^\s*([a-z_]+)\s*=\s*(\S+)\s*$", text))
    conf_ok = keys.get("fips_mode") == "true" and keys.get("failmode", "secure") == "secure"
    rc, _ = run(["systemctl", "is-active", "--quiet", "duoauthproxy.service"])
    active = rc == 0
    rc, out = run(["ss", "-H", "-lun"])
    listening = any(len(c) >= 5 and c[3] == listen for c in (ln.split() for ln in out.splitlines()))
    log_p = os.path.join(duo_dir, "log", "authproxy.log")
    try:
        with open(log_p, encoding="utf-8", errors="replace") as fh:
            lines = [ln.strip() for ln in fh if "fips mode" in ln.lower()]
    except OSError:
        lines = []
    rep.facts["authproxy_log_fips_lines"] = " | ".join(lines[-3:]) or "none"
    # Duo logs "FIPS mode is not enabled" at every start without fips_mode
    logged = bool(lines) and "not enabled" not in lines[-1].lower() and "enabled" in lines[-1].lower()
    rep.add("R6", conf_ok and active and listening and logged,
            "applied configuration fips_mode=%s failmode=%s; service %s; %s; last start logged: %s" % (
                keys.get("fips_mode", "(missing)"), keys.get("failmode", "secure"), "active" if active else "NOT active",
                "listening on " + listen if listening else "NOT listening on " + listen,
                lines[-1].split("] ", 1)[-1] if lines else "(no FIPS line in %s)" % log_p))


# ---------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("what", choices=("source", "host", "installed", "all"))
    ap.add_argument("source_file", nargs="?")
    ap.add_argument("--duo-dir", default="/opt/duoauthproxy")
    ap.add_argument("--running", action="store_true")
    ap.add_argument("--arch", help="architecture of the provider to check in the source (default: this machine)")
    ap.add_argument("--json", metavar="OUT")
    a = ap.parse_args(argv)
    if a.what in ("source", "all") and not a.source_file:
        ap.error("%s needs Duo's source file" % a.what)
    rep = Report()
    rep.facts["checked_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    rep.facts["machine"] = machine_arch()
    src = None
    if a.what in ("source", "all"):
        src = check_source(a.source_file, rep, a.arch)
    if a.what in ("host", "all"):
        check_host(rep)
    if a.what in ("installed", "all"):
        check_installed(rep, a.duo_dir, src, a.running)
    print(rep.text())
    verdict = rep.passed()
    if a.what == "all":
        print("\n%s" % ("All required checks passed. If M1 and M2 are acceptable, record it with:\n"
                        "  tools/integrations/catalog.py fips duo %s ubuntu-24.04-pro-fips-updates"
                        % rep.facts.get("duo_version", "X.Y.Z") if verdict else
                        "Not FIPS-capable on this machine: keep the catalog entry fips=false."))
    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump({"checks": rep.checks, "facts": rep.facts, "passed": verdict}, fh, indent=1, sort_keys=True)
            fh.write("\n")
    return 0 if verdict else 1


if __name__ == "__main__":
    sys.exit(main())
