#!/usr/bin/env python3
"""Issue and keep track of radius-admin licence files (maintainer tool, SPEC section 31).

Runs on the maintainer's machine only. Needs python3-cryptography. Nothing here talks to the
network except `serve`, which listens on 127.0.0.1 only.

    licence-tool.py keygen                      create the signing key (once)
    licence-tool.py issue --licensee "Example Corp" --tier 50-249 [--type commercial]
                          [--starts 2026-12-01] [--expires 2027-11-30] [--scope ...] [--notes ...]
    licence-tool.py verify FILE                 check a licence file against the public key
    licence-tool.py list                        the register
    licence-tool.py serve [--port 8766]         local web page to issue, renew and list licences

Files live in the licence home (default /root/.config/radius-admin/licence-signing, override
with LICENCE_HOME or --home), never in the repository:

    signing-key.pem   ECDSA P-384 private key (0600). Back it up offline; losing it means a new
                      key and a release that ships the new public key.
    public.pem        its public half; copy to app/radius_admin/licence_keys/<key id>.pem
    register.json     every licence issued (id, licensee, dates, notes, revoked note)
    issued/<id>.json  the signed files, as sent to customers

The file format is described in app/radius_admin/licence.py; tests/licence/ checks that the
app accepts what this tool signs.
"""
import argparse
import base64
import datetime
import hashlib
import html
import http.server
import json
import os
import re
import secrets
import sys
import tempfile
import urllib.parse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

PRODUCT = "radius-admin"
DEFAULT_HOME = "/root/.config/radius-admin/licence-signing"
TIERS = ("50-249", "250-999", "1,000-4,999", "5,000+", "")
TYPES = ("commercial", "exception")
DEFAULT_SCOPE = "Unlimited servers and devices"
ID_RE = re.compile(r"RA-(\d{4})-(\d{4,})")


class ToolError(Exception):
    pass


# ----------------------------------------------------------------- format (mirrors the app)
def canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def key_id(public_key):
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()[:16]


def _date(v, name):
    try:
        return datetime.date.fromisoformat(v)
    except (TypeError, ValueError):
        raise ToolError("%s must be a date like 2026-12-01" % name) from None


# ----------------------------------------------------------------- home directory
class Home:
    def __init__(self, path):
        self.path = path
        self.key_file = os.path.join(path, "signing-key.pem")
        self.pub_file = os.path.join(path, "public.pem")
        self.register_file = os.path.join(path, "register.json")
        self.issued = os.path.join(path, "issued")

    def keygen(self):
        if os.path.exists(self.key_file):
            raise ToolError("%s exists already; refusing to replace a signing key" % self.key_file)
        os.makedirs(self.path, mode=0o700, exist_ok=True)
        os.makedirs(self.issued, mode=0o700, exist_ok=True)
        key = ec.generate_private_key(ec.SECP384R1())
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
        fd = os.open(self.key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(pem)
        pub = key.public_key().public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)
        with open(self.pub_file, "wb") as f:
            f.write(pub)
        return key_id(key.public_key())

    def key(self):
        try:
            with open(self.key_file, "rb") as f:
                k = serialization.load_pem_private_key(f.read(), password=None)
        except FileNotFoundError:
            raise ToolError("no signing key in %s; run keygen first" % self.path) from None
        if not isinstance(k, ec.EllipticCurvePrivateKey) or k.curve.name != "secp384r1":
            raise ToolError("the signing key is not ECDSA P-384")
        return k

    def register(self):
        try:
            with open(self.register_file) as f:
                return json.load(f)
        except FileNotFoundError:
            return []

    def save_register(self, rows):
        os.makedirs(self.path, mode=0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path, prefix=".register.")
        with os.fdopen(fd, "w") as f:
            json.dump(rows, f, indent=1, sort_keys=True)
            f.write("\n")
        os.replace(tmp, self.register_file)

    def next_id(self, today):
        n = 0
        for r in self.register():
            m = ID_RE.fullmatch(r.get("licence_id", ""))
            if m and int(m.group(1)) == today.year:
                n = max(n, int(m.group(2)))
        return "RA-%d-%04d" % (today.year, n + 1)

    def issue(self, licensee, tier="", type_="commercial", starts=None, expires=None, scope=DEFAULT_SCOPE,
              notes="", renews="", today=None):
        today = today or datetime.date.today()
        licensee = (licensee or "").strip()
        if not licensee or len(licensee) > 200:
            raise ToolError("licensee: 1 to 200 characters")
        if type_ not in TYPES:
            raise ToolError("type: commercial or exception")
        if tier not in TIERS:
            raise ToolError("tier: one of " + ", ".join(t for t in TIERS if t))
        if len(scope) > 300 or len(notes) > 1000:
            raise ToolError("scope at most 300, notes at most 1000 characters")
        s = _date(starts, "starts") if starts else today
        if expires in (None, "") and type_ == "commercial":
            try:                                   # one year: 2026-12-01 .. 2027-11-30
                e = s.replace(year=s.year + 1) - datetime.timedelta(days=1)
            except ValueError:                     # 29 February
                e = datetime.date(s.year + 1, 2, 28)
        elif expires in (None, ""):
            e = None
        else:
            e = _date(expires, "expires")
        if e is not None and e < s:
            raise ToolError("expires is before starts")
        key = self.key()
        lid = self.next_id(today)
        payload = {"product": PRODUCT, "licence_id": lid, "type": type_, "licensee": licensee, "tier": tier,
                   "scope": scope, "issued": today.isoformat(), "starts": s.isoformat(),
                   "expires": e.isoformat() if e else None, "notes": notes}
        sig = key.sign(canonical(payload), ec.ECDSA(hashes.SHA384()))
        doc = {"format": 1, "key_id": key_id(key.public_key()), "payload": payload,
               "signature": base64.b64encode(sig).decode("ascii")}
        text = json.dumps(doc, indent=1, sort_keys=True) + "\n"
        os.makedirs(self.issued, mode=0o700, exist_ok=True)
        path = os.path.join(self.issued, lid + ".json")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        rows = self.register()
        rows.append(dict(payload, renews=renews, revoked="", file=os.path.basename(path)))
        self.save_register(rows)
        return lid, path, text

    def find(self, lid):
        for r in self.register():
            if r.get("licence_id") == lid:
                return r
        raise ToolError("no licence %s in the register" % lid)

    def note(self, lid, revoked):
        rows = self.register()
        for r in rows:
            if r.get("licence_id") == lid:
                r["revoked"] = revoked[:300]
                self.save_register(rows)
                return
        raise ToolError("no licence %s in the register" % lid)

    def file_text(self, lid):
        if not ID_RE.fullmatch(lid):
            raise ToolError("bad licence id")
        with open(os.path.join(self.issued, lid + ".json")) as f:
            return f.read()

    def verify(self, text):
        """The payload when `text` is signed by this home's key, else ToolError."""
        try:
            doc = json.loads(text)
            pub = self.key().public_key()
            if doc.get("format") != 1 or doc.get("key_id") != key_id(pub):
                raise ToolError("not signed with this signing key")
            pub.verify(base64.b64decode(doc["signature"], validate=True), canonical(doc["payload"]),
                       ec.ECDSA(hashes.SHA384()))
        except ToolError:
            raise
        except Exception:
            raise ToolError("not a valid licence file (bad JSON or signature)") from None
        return doc["payload"]


def status_of(r, today):
    if r.get("revoked"):
        return "revoked", "Revoked: " + r["revoked"]
    s = datetime.date.fromisoformat(r["starts"])
    e = datetime.date.fromisoformat(r["expires"]) if r.get("expires") else None
    if s > today:
        return "future", "Starts %s" % s
    if e is None:
        return "ok", "No end date"
    left = (e - today).days
    if left < 0:
        return "expired", "Ended %d days ago" % -left
    if left < 30:
        return "soon", "%d days left" % left
    return "ok", "%d days left" % left


# ----------------------------------------------------------------- local web page
CSS = """
:root { --ink:#1d2b38; --soft:#5a6b7b; --line:#d6dde4; --bg:#f6f8fa; --card:#fff; --acc:#1f6f8b; --on-acc:#fff;
  --acc-bg:#e3f0f5; --warn:#9a5b00; --bad:#a23030; }
@media (prefers-color-scheme: dark) { :root { --ink:#e3e9ef; --soft:#9fb0bf; --line:#33414e; --bg:#141b22;
  --card:#1c252e; --acc:#6fb7cf; --on-acc:#0e1a22; --acc-bg:#1f3440; --warn:#e0a54a; --bad:#e07a7a; } }
* { box-sizing: border-box; }
body { margin:0; font:15px/1.5 system-ui,sans-serif; color:var(--ink); background:var(--bg); }
header { padding:.8rem 1.5rem; border-bottom:1px solid var(--line); background:var(--card); display:flex;
  gap:1rem; align-items:center; flex-wrap:wrap; }
header h1 { font-size:1.1rem; margin:0 1rem 0 0; }
nav { display:flex; gap:.5rem; flex-wrap:wrap; }
nav a { display:inline-block; padding:.4rem .9rem; border:1px solid var(--line); border-radius:6px; color:var(--ink);
  text-decoration:none; font-weight:500; }
nav a:hover { border-color:var(--acc); }
nav a[aria-current=page] { background:var(--acc-bg); border-color:var(--acc); color:var(--acc); }
header .home { margin-left:auto; }
main { padding:1.5rem; max-width:1200px; margin:0 auto; }
.card { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:1rem 1.2rem; margin:0 0 1rem; }
table { border-collapse:collapse; width:100%; } th, td { text-align:left; padding:.45rem .5rem;
  border-bottom:1px solid var(--line); vertical-align:top; } th { color:var(--soft); font-weight:600; font-size:.85rem; }
.mono { font-family:ui-monospace,monospace; } .muted { color:var(--soft); font-size:.85rem; }
.s-ok { color:var(--acc); } .s-soon, .s-future { color:var(--warn); } .s-expired, .s-revoked { color:var(--bad); }
form.stack { max-width:34rem; }
label { display:block; margin:.9rem 0 .25rem; font-weight:600; font-size:.9rem; }
label:first-of-type { margin-top:0; }
input, select, textarea { display:block; width:100%; padding:.45rem .55rem; border:1px solid var(--line);
  border-radius:6px; background:var(--bg); color:var(--ink); font:inherit; }
textarea { resize:vertical; }
.actions { margin-top:1.2rem; padding-top:1rem; border-top:1px solid var(--line); }
button, .btn { display:inline-block; padding:.5rem 1.1rem; border-radius:6px; border:1px solid var(--acc);
  background:var(--acc); color:var(--on-acc); font:inherit; font-weight:600; cursor:pointer; text-decoration:none; }
.btn-q { background:transparent; color:var(--acc); padding:.2rem .5rem; margin:0 .2rem .2rem 0; font-size:.85rem;
  font-weight:500; }
.err { border-left:4px solid var(--bad); } .okmsg { border-left:4px solid var(--acc); }
form.inline { display:inline; }
"""


def make_handler(home, token):
    class H(http.server.BaseHTTPRequestHandler):
        server_version = "licence-tool"

        def log_message(self, fmt, *a):
            sys.stderr.write("%s %s\n" % (self.command, self.path.split("?")[0]))

        # -------------------------------------------------- plumbing
        def _authed(self):
            for part in self.headers.get("Cookie", "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == "lt" and secrets.compare_digest(v, token):
                    return True
            return False

        def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
            data = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'; "
                             "frame-ancestors 'none'; base-uri 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "same-origin")   # no-referrer makes browsers send Origin: null
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _redirect(self, where, extra=None):
            self.send_response(303)
            self.send_header("Location", where)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _page(self, title, body, code=200):
            e = html.escape
            nav = "".join("<a href='%s'%s>%s</a>" % (href, " aria-current=page" if label == title else "", label)
                          for href, label in (("/", "Licences"), ("/new", "Issue"), ("/verify", "Verify a file")))
            self._send(code, "<!doctype html><html lang=en><head><meta charset=utf-8>"
                       "<meta name=viewport content='width=device-width,initial-scale=1'>"
                       "<title>%s · Licences</title><link rel=stylesheet href='/style.css'></head><body>"
                       "<header><h1>radius-admin licences</h1><nav aria-label='Pages'>%s</nav>"
                       "<span class='muted home'>%s</span></header><main>%s</main>"
                       "</body></html>" % (e(title), nav, e(home.path), body))

        def _form(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n > 65536:
                raise ToolError("request too large")
            data = urllib.parse.parse_qs(self.rfile.read(n).decode("utf-8"), keep_blank_values=True)
            f = {k: v[0] for k, v in data.items()}
            if not secrets.compare_digest(f.get("csrf", ""), token):
                raise PermissionError("bad form token")
            origin = self.headers.get("Origin")
            if origin and urllib.parse.urlsplit(origin).netloc != self.headers.get("Host", ""):
                raise PermissionError("cross-site request")
            return f

        def _csrf(self):
            return "<input type=hidden name=csrf value='%s'>" % token

        # -------------------------------------------------- routes
        def do_GET(self):
            u = urllib.parse.urlsplit(self.path)
            q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
            if u.path == "/style.css":
                return self._send(200, CSS, "text/css; charset=utf-8")
            if not self._authed():
                if secrets.compare_digest(q.get("token", ""), token):
                    return self._redirect("/", {"Set-Cookie": "lt=%s; HttpOnly; SameSite=Strict; Path=/" % token})
                return self._send(403, "Open the URL printed by licence-tool.py serve.", "text/plain; charset=utf-8")
            try:
                if u.path == "/":
                    return self._list(q.get("msg", ""))
                if u.path == "/new":
                    return self._new(q.get("renew", ""))
                if u.path == "/verify":
                    return self._verify_page()
                if u.path == "/download":
                    lid = q.get("id", "")
                    text = home.file_text(lid)
                    return self._send(200, text, "application/json",
                                      {"Content-Disposition": "attachment; filename=\"%s.json\"" % lid})
            except (ToolError, OSError) as e:
                return self._page("Error", "<p class='card err'>%s</p>" % html.escape(str(e)), 400)
            self._send(404, "not found", "text/plain")

        def do_POST(self):
            if not self._authed():
                return self._send(403, "forbidden", "text/plain")
            u = urllib.parse.urlsplit(self.path)
            try:
                f = self._form()
            except PermissionError as e:
                return self._send(403, str(e), "text/plain")
            except ToolError as e:
                return self._send(400, str(e), "text/plain")
            try:
                if u.path == "/new":
                    lid, _path, _text = home.issue(f.get("licensee", ""), f.get("tier", ""),
                                                   f.get("type", "commercial"), f.get("starts") or None,
                                                   f.get("expires") or None, f.get("scope", DEFAULT_SCOPE),
                                                   f.get("notes", ""), renews=f.get("renews", ""))
                    return self._redirect("/?" + urllib.parse.urlencode({"msg": "Issued %s." % lid}))
                if u.path == "/revoke":
                    home.note(f.get("id", ""), f.get("reason", "").strip() or "revoked")
                    return self._redirect("/?" + urllib.parse.urlencode({"msg": "Marked %s." % f.get("id", "")}))
                if u.path == "/verify":
                    p = home.verify(f.get("text", ""))
                    rows = "".join("<tr><th>%s</th><td>%s</td></tr>" % (html.escape(k), html.escape(str(v)))
                                   for k, v in sorted(p.items()))
                    return self._page("Verify a file", "<div class='card okmsg'><p>Valid signature from this key.</p>"
                                      "<table>%s</table></div>" % rows)
            except ToolError as e:
                if u.path == "/new":
                    return self._new(f.get("renews", ""), error=str(e), values=f)
                return self._page("Error", "<p class='card err'>%s</p>" % html.escape(str(e)), 400)
            self._send(404, "not found", "text/plain")

        # -------------------------------------------------- pages
        def _list(self, msg):
            e = html.escape
            today = datetime.date.today()
            rows = []
            for r in reversed(home.register()):
                cls, text = status_of(r, today)
                lid = r["licence_id"]
                renew = "<a class='btn btn-q' href='/new?renew=%s'>Renew</a>" % e(lid)
                dl = "<a class='btn btn-q' href='/download?id=%s'>Download</a>" % e(lid)
                rev = ("" if r.get("revoked") else
                       "<form class=inline method=post action='/revoke'>%s<input type=hidden name=id value='%s'>"
                       "<input type=hidden name=reason value='revoked'><button class='btn btn-q'>Mark revoked"
                       "</button></form>" % (self._csrf(), e(lid)))
                rows.append("<tr><td class=mono>%s</td><td>%s<div class=muted>%s</div></td><td>%s</td><td>%s</td>"
                            "<td>%s</td><td>%s</td><td class='s-%s'>%s</td><td>%s%s%s</td></tr>" % (
                                e(lid), e(r["licensee"]), e(r.get("notes", "")), e(r["type"]), e(r.get("tier", "")),
                                e(r["starts"]), e(r.get("expires") or "—"), cls, e(text), dl, renew, rev))
            body = ""
            if msg:
                body += "<p class='card okmsg'>%s</p>" % e(msg)
            body += ("<div class=card><table><thead><tr><th>Licence</th><th>Licensee</th><th>Type</th><th>Tier</th>"
                     "<th>Starts</th><th>Expires</th><th>Status</th><th></th></tr></thead><tbody>%s</tbody></table>"
                     "%s</div><p class=muted>Revoking only marks the register: licence files are checked offline, "
                     "so a server keeps showing a revoked file as valid until it expires.</p>" % (
                         "".join(rows), "" if rows else "<p class=muted>No licences issued yet.</p>"))
            self._page("Licences", body)

        def _new(self, renew, error="", values=None):
            e = html.escape
            v = dict(values or {})
            if renew and not values:
                old = home.find(renew)
                start = (datetime.date.fromisoformat(old["expires"]) + datetime.timedelta(days=1)
                         if old.get("expires") else datetime.date.today())
                v = {"licensee": old["licensee"], "tier": old.get("tier", ""), "type": old["type"],
                     "scope": old.get("scope", DEFAULT_SCOPE), "notes": old.get("notes", ""),
                     "starts": start.isoformat(), "renews": renew}
            tiers = "".join("<option value='%s'%s>%s</option>" % (e(t), " selected" if v.get("tier", "50-249") == t
                                                                  else "", e(t or "— none —")) for t in TIERS)
            types = "".join("<option%s>%s</option>" % (" selected" if v.get("type", "commercial") == t else "", t)
                            for t in TYPES)
            body = ("<p class='card err'>%s</p>" % e(error)) if error else ""
            body += ("<div class=card><form class=stack method=post action='/new'>%s"
                     "<input type=hidden name=renews value='%s'>%s"
                     "<label for=licensee>Licensee (organization)</label>"
                     "<input id=licensee name=licensee required maxlength=200 value='%s'>"
                     "<label for=type>Type</label><select id=type name=type>%s</select>"
                     "<label for=tier>Headcount tier</label><select id=tier name=tier>%s</select>"
                     "<label for=starts>Starts</label><input id=starts name=starts type=date value='%s'>"
                     "<label for=expires>Expires (empty: one year for commercial, none for an exception)</label>"
                     "<input id=expires name=expires type=date value='%s'>"
                     "<label for=scope>Scope</label><input id=scope name=scope maxlength=300 value='%s'>"
                     "<label for=notes>Notes (shown on the customer's Licence page)</label>"
                     "<textarea id=notes name=notes maxlength=1000 rows=3>%s</textarea>"
                     "<div class=actions><button type=submit>Sign and issue</button></div></form></div>" % (
                         self._csrf(), e(v.get("renews", "")),
                         ("<p class=muted>Renewal of %s.</p>" % e(v["renews"])) if v.get("renews") else "",
                         e(v.get("licensee", "")), types, tiers, e(v.get("starts", "")), e(v.get("expires", "")),
                         e(v.get("scope", DEFAULT_SCOPE)), e(v.get("notes", ""))))
            self._page("Issue", body, 400 if error else 200)

        def _verify_page(self):
            self._page("Verify a file", "<div class=card><form class=stack method=post action='/verify'>%s"
                       "<label for=text>Licence file contents</label><textarea id=text name=text rows=12 "
                       "class=mono></textarea><div class=actions><button type=submit>Verify</button></div>"
                       "</form></div>" % self._csrf())
    return H


# ----------------------------------------------------------------- CLI
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--home", default=os.environ.get("LICENCE_HOME", DEFAULT_HOME))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen")
    p = sub.add_parser("issue")
    p.add_argument("--licensee", required=True)
    p.add_argument("--tier", default="50-249", choices=TIERS)
    p.add_argument("--type", default="commercial", choices=TYPES)
    p.add_argument("--starts")
    p.add_argument("--expires")
    p.add_argument("--scope", default=DEFAULT_SCOPE)
    p.add_argument("--notes", default="")
    p.add_argument("--renews", default="")
    p = sub.add_parser("verify")
    p.add_argument("file")
    sub.add_parser("list")
    p = sub.add_parser("serve")
    p.add_argument("--port", type=int, default=8766)
    a = ap.parse_args(argv)
    home = Home(a.home)
    try:
        if a.cmd == "keygen":
            kid = home.keygen()
            print("signing key: %s (0600; back it up offline)" % home.key_file)
            print("public key:  %s -> app/radius_admin/licence_keys/%s.pem" % (home.pub_file, kid))
        elif a.cmd == "issue":
            lid, path, _ = home.issue(a.licensee, a.tier, a.type, a.starts, a.expires, a.scope, a.notes, a.renews)
            print("%s -> %s" % (lid, path))
        elif a.cmd == "verify":
            with open(a.file) as f:
                p = home.verify(f.read())
            print(json.dumps(p, indent=1, sort_keys=True))
        elif a.cmd == "list":
            today = datetime.date.today()
            for r in home.register():
                print("%-14s %-10s %-11s %s..%s  %-18s %s" % (r["licence_id"], r["type"], r.get("tier", ""),
                      r["starts"], r.get("expires") or "", status_of(r, today)[1], r["licensee"]))
        elif a.cmd == "serve":
            home.key()                       # fail early without a key
            token = secrets.token_urlsafe(24)
            srv = http.server.ThreadingHTTPServer(("127.0.0.1", a.port), make_handler(home, token))
            print("Open http://localhost:%d/?token=%s  (Ctrl+C stops)" % (a.port, token), flush=True)
            try:
                srv.serve_forever()
            except KeyboardInterrupt:
                pass
    except ToolError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
