"""Vendor profiles: what differs between makers of switches, access points and firewalls.

A profile is a JSON document (format 1, SPEC section 26) describing, for one family of
devices, the reply attributes that assign a VLAN or grant full admin rights, the CoA
packets for re-authenticate / bounce port / disconnect, and how the device's SNMP port
names map to the names it sends in RADIUS (NAS-Port-Id). Built-in profiles ship as files
in vendor_profiles/; every document, built in or not, goes through validate() before it
is used, so a profile can never place free-form text in the FreeRADIUS configuration:
attribute names, operators, values and placeholders are checked field by field.

The same validated form is what export_json() writes and what an import reads back.
Custom profiles, created in the portal or imported, are stored validated in ui.vendor_profile;
catalog() returns the built-in ones plus those. Custom profiles are always "unverified" and
may not reuse a built-in id.
"""
import json
import os
import re
import urllib.parse

FORMAT = 1
DEFAULT_ID = "cisco-c1300"
BUILTIN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor_profiles")

STATUSES = ("supported", "unverified")
REPLY_LISTS = ("vlan", "admin_full")       # required, each with at least one attribute
OPTIONAL_REPLY_LISTS = ("role",)           # may be absent or empty
# NAS-Port-Type values a profile may accept MAC authentication (MAB) from
MAB_PORT_TYPES = ("Ethernet", "Wireless-802.11")
COA_ACTIONS = ("reauth", "bounce", "disconnect")
COA_PACKETS = ("coa", "disconnect")
# How a CoA / Disconnect request names the session:
#   mac-then-session  Calling-Station-Id when known, else Acct-Session-Id (Catalyst 1300:
#                     it finds no session when the request also names an Acct-Session-Id)
#   session-and-mac   Acct-Session-Id and Calling-Station-Id, each when known (RFC 5176 3.3)
COA_IDENTIFY = ("mac-then-session", "session-and-mac")

# Placeholders a reply value may consist of (the whole value, never part of it), the
# reply lists that may use them, and what the policy renderer puts in their place.
PLACEHOLDERS = {"{vlan}": ("vlan",), "{role}": ("role",)}

MAX_ATTRS = 8
MAX_PORT_RULES = 8

_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
_LABEL_RE = re.compile(r"[^\x00-\x1f\x7f]{1,64}")
_DESC_RE = re.compile(r"[^\x00-\x1f\x7f]{0,300}")
_ATTR_RE = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,63}")
# Printable ASCII without '"', '\\' (string syntax), '%' (xlat expansion), '$' (config
# references), '`' (exec strings) and braces (reserved for placeholders).
_VALUE_RE = re.compile(r"[\x20\x21\x23\x26-\x5b\x5d-\x5f\x61-\x7a\x7c\x7e]{1,247}")
_FORMAT_RE = re.compile(r"(?:[A-Za-z0-9/._:-]|\{[1-9](?::(?:lower|upper))?\})+")
_FORMAT_REF_RE = re.compile(r"\{([1-9])(?::(lower|upper))?\}")

# Attributes a profile may never set: server-internal control attributes, secrets,
# packet framing, and the attributes the CoA sender fills in itself.
_FORBIDDEN_NAMES = {
    "auth-type", "autz-type", "acct-type", "session-type", "post-auth-type", "pre-proxy-type",
    "post-proxy-type", "fall-through", "proxy-to-realm", "replicate-to-realm", "realm",
    "packet-type", "response-packet-type", "message-authenticator", "state", "class",
    "user-name", "user-password", "chap-password", "chap-challenge", "calling-station-id",
    "called-station-id", "acct-session-id", "nas-ip-address", "nas-ipv6-address", "nas-port-id",
    "event-timestamp", "simultaneous-use", "huntgroup-name",
}
_FORBIDDEN_PREFIXES = ("tmp-", "module-", "packet-", "exec-", "eap-", "tls-", "ldap-", "sql-",
                       "proxy-", "home-server-", "crypt-", "control-", "freeradius-", "virtual-server")
_FORBIDDEN_SUFFIXES = ("-password", "-passwd", "-secret")
_RAW_ATTR_RE = re.compile(r"(^|-)Attr-\d|^Vendor-", re.IGNORECASE)

_TOP_KEYS = {"format", "id", "label", "description", "status", "reply", "coa", "snmp", "setup", "mab"}
SETUP_TOPICS = ("accounting", "coa")
# Device commands shown on the portal's pages (escaped HTML text, never configuration).
_SETUP_RE = re.compile(r"[^\x00-\x08\x0b-\x1f\x7f]{1,1500}")
_COA_KEYS = {"port", "identify", "send_nas_port_id"} | set(COA_ACTIONS)


class ProfileError(ValueError):
    """A profile document that cannot be used; the message names the field."""


def _fail(where, why):
    raise ProfileError("%s: %s" % (where, why))


def _keys(obj, allowed, required, where):
    if not isinstance(obj, dict):
        _fail(where, "must be an object")
    extra = sorted(set(obj) - set(allowed))
    if extra:
        _fail(where, "unknown field %s" % ", ".join(map(repr, extra)))
    missing = sorted(set(required) - set(obj))
    if missing:
        _fail(where, "missing field %s" % ", ".join(map(repr, missing)))


def _str(v, rx, where, what):
    if not isinstance(v, str) or not rx.fullmatch(v):
        _fail(where, what)
    return v


def validate_attr_name(name, where="attribute"):
    _str(name, _ATTR_RE, where, "attribute names are letters, digits and '-', starting with a letter")
    low = name.lower()
    if (low in _FORBIDDEN_NAMES or low.startswith(_FORBIDDEN_PREFIXES) or low.endswith(_FORBIDDEN_SUFFIXES)
            or _RAW_ATTR_RE.search(name)):
        _fail(where, "%s cannot be set by a vendor profile" % name)
    return name


def _value(v, list_name, where):
    if isinstance(v, str) and v in PLACEHOLDERS:
        if list_name not in PLACEHOLDERS[v]:
            _fail(where, "%s cannot be used here" % v)
        return v
    return _str(v, _VALUE_RE, where, "values are 1-247 printable characters without \" \\ %% $ ` { }")


def _attr_list(items, list_name, where, with_op):
    if not isinstance(items, list):
        _fail(where, "must be a list")
    if len(items) > MAX_ATTRS:
        _fail(where, "at most %d attributes" % MAX_ATTRS)
    out = []
    for i, it in enumerate(items):
        w = "%s[%d]" % (where, i)
        _keys(it, ("attr", "op", "value") if with_op else ("attr", "value"),
              ("attr", "op", "value") if with_op else ("attr", "value"), w)
        e = {"attr": validate_attr_name(it["attr"], w + ".attr")}
        if with_op:
            if it["op"] not in (":=", "+="):
                _fail(w + ".op", "use := (replace) or += (add)")
            e["op"] = it["op"]
        e["value"] = _value(it["value"], list_name, w + ".value")
        out.append(e)
    return out


def _port_rules(rules, where):
    if not isinstance(rules, list):
        _fail(where, "must be a list")
    if len(rules) > MAX_PORT_RULES:
        _fail(where, "at most %d rules" % MAX_PORT_RULES)
    out = []
    for i, r in enumerate(rules):
        w = "%s[%d]" % (where, i)
        _keys(r, ("match", "ignore_case", "format"), ("match", "format"), w)
        if not isinstance(r["match"], str) or not 1 <= len(r["match"]) <= 200:
            _fail(w + ".match", "a regular expression of 1-200 characters")
        ic = r.get("ignore_case", False)
        if not isinstance(ic, bool):
            _fail(w + ".ignore_case", "true or false")
        try:
            rx = re.compile(r["match"], re.IGNORECASE if ic else 0)
        except re.error as e:
            _fail(w + ".match", "not a valid regular expression (%s)" % e)
        fmt = _str(r["format"], _FORMAT_RE, w + ".format",
                   "letters, digits, / . _ : - and {1}..{9}, optionally {1:lower} or {1:upper}")
        for m in _FORMAT_REF_RE.finditer(fmt):
            if int(m.group(1)) > rx.groups:
                _fail(w + ".format", "{%s} refers to a group the expression does not have" % m.group(1))
        out.append({"match": r["match"], "ignore_case": ic, "format": fmt})
    return out


def validate(doc):
    """The normalized profile, or ProfileError. Never trusts any field of `doc`."""
    _keys(doc, _TOP_KEYS, ("format", "id", "label", "status", "reply", "coa", "snmp"), "profile")
    if doc["format"] != FORMAT or isinstance(doc["format"], bool):
        _fail("format", "this server reads profile format %d" % FORMAT)
    p = {"format": FORMAT,
         "id": _str(doc["id"], _ID_RE, "id", "1-32 lower-case letters, digits and '-'"),
         "label": _str(doc["label"], _LABEL_RE, "label", "1-64 printable characters"),
         "description": _str(doc.get("description", ""), _DESC_RE, "description", "up to 300 printable characters")}
    if doc["status"] not in STATUSES:
        _fail("status", "one of %s" % ", ".join(STATUSES))
    p["status"] = doc["status"]

    _keys(doc["reply"], REPLY_LISTS + OPTIONAL_REPLY_LISTS, REPLY_LISTS, "reply")
    p["reply"] = {n: _attr_list(doc["reply"].get(n, []), n, "reply." + n, True)
                  for n in REPLY_LISTS + OPTIONAL_REPLY_LISTS}
    for n in REPLY_LISTS:       # FreeRADIUS refuses an empty update section
        if not p["reply"][n]:
            _fail("reply." + n, "needs at least one attribute")
    if p["reply"]["role"] and not any(e["value"] == "{role}" for e in p["reply"]["role"]):
        _fail("reply.role", "must place {role} in one attribute")

    mab = doc.get("mab", {"port_types": ["Ethernet"]})
    _keys(mab, ("port_types",), ("port_types",), "mab")
    pt = mab["port_types"]
    if (not isinstance(pt, list) or not pt or len(set(map(str, pt))) != len(pt)
            or any(t not in MAB_PORT_TYPES for t in pt)):
        _fail("mab.port_types", "a list of distinct values from %s" % ", ".join(MAB_PORT_TYPES))
    p["mab"] = {"port_types": [t for t in MAB_PORT_TYPES if t in pt]}
    if not any(e["value"] == "{vlan}" for e in p["reply"]["vlan"]):
        _fail("reply.vlan", "must place {vlan} in one attribute")

    c = doc["coa"]
    _keys(c, _COA_KEYS, _COA_KEYS, "coa")
    if not isinstance(c["port"], int) or isinstance(c["port"], bool) or not 1 <= c["port"] <= 65535:
        _fail("coa.port", "a UDP port from 1 to 65535")
    if c["identify"] not in COA_IDENTIFY:
        _fail("coa.identify", "one of %s" % ", ".join(COA_IDENTIFY))
    if not isinstance(c["send_nas_port_id"], bool):
        _fail("coa.send_nas_port_id", "true or false")
    p["coa"] = {"port": c["port"], "identify": c["identify"], "send_nas_port_id": c["send_nas_port_id"]}
    for a in COA_ACTIONS:
        act = c[a]
        if act is None:         # the device cannot do this; the portal hides the action
            p["coa"][a] = None
            continue
        _keys(act, ("packet", "attrs"), ("packet", "attrs"), "coa." + a)
        if act["packet"] not in COA_PACKETS:
            _fail("coa.%s.packet" % a, "coa or disconnect")
        p["coa"][a] = {"packet": act["packet"], "attrs": _attr_list(act["attrs"], "coa", "coa.%s.attrs" % a, False)}

    _keys(doc["snmp"], ("port_names",), ("port_names",), "snmp")
    p["snmp"] = {"port_names": _port_rules(doc["snmp"]["port_names"], "snmp.port_names")}

    setup = doc.get("setup", {})
    _keys(setup, SETUP_TOPICS, (), "setup")
    p["setup"] = {}
    for t in SETUP_TOPICS:
        v = setup.get(t)
        p["setup"][t] = None if v is None else _str(v, _SETUP_RE, "setup." + t,
                                                    "1-1500 characters of device commands")
    return p


# ---------------------------------------------------------------- loading

_builtin_cache = {}


def valid_id(pid):
    return isinstance(pid, str) and bool(_ID_RE.fullmatch(pid))


def builtin_ids():
    return sorted(f[:-5] for f in os.listdir(BUILTIN_DIR) if f.endswith(".json") and _ID_RE.fullmatch(f[:-5]))


def builtin(pid):
    """A shipped profile by id (validated, cached). ProfileError if there is none."""
    if pid not in _builtin_cache:
        if not isinstance(pid, str) or not _ID_RE.fullmatch(pid) or pid not in builtin_ids():
            raise ProfileError("no built-in vendor profile %r" % (pid,))
        with open(os.path.join(BUILTIN_DIR, pid + ".json"), encoding="utf-8") as fh:
            p = validate(json.load(fh))
        if p["id"] != pid:
            raise ProfileError("vendor_profiles/%s.json declares id %r" % (pid, p["id"]))
        _builtin_cache[pid] = p
    return _builtin_cache[pid]


def default():
    return builtin(DEFAULT_ID)


def is_builtin(pid):
    return valid_id(pid) and pid in builtin_ids()


def custom_profiles(conn=None):
    """{id: profile} stored in ui.vendor_profile, each validated again (a row that no longer
    validates, or that uses a built-in id, is left out)."""
    from . import db
    out = {}
    for r in db.query("SELECT id, doc FROM ui.vendor_profile ORDER BY id", conn=conn):
        try:
            p = validate(r["doc"])
        except ProfileError:
            continue
        if p["id"] == r["id"] and not is_builtin(p["id"]):
            out[p["id"]] = p
    return out


def catalog(conn=None):
    """{id: profile}: the built-in profiles and the custom ones (SPEC section 26)."""
    cat = {i: builtin(i) for i in builtin_ids()}
    cat.update(custom_profiles(conn))
    return cat


def resolve(pid, default_id=None, cat=None):
    """The profile a client uses: its own (`pid`), else the installation's default; looked up
    in `cat` (from catalog()), or among the built-in profiles when no catalog is given."""
    pid = pid or default_id or DEFAULT_ID
    if cat is None:
        return builtin(pid)
    if pid not in cat:
        raise ProfileError("no vendor profile %r" % (pid,))
    return cat[pid]


def choices(cat=None):
    """[(id, label, status)] of the profiles a client can use, default first, then built-in
    ones, then custom ones (labelled so)."""
    cat = cat if cat is not None else {i: builtin(i) for i in builtin_ids()}
    ids = sorted(cat, key=lambda i: (i != DEFAULT_ID, not is_builtin(i), cat[i]["label"].lower()))
    return [(i, cat[i]["label"] + ("" if is_builtin(i) else " (custom)"), cat[i]["status"]) for i in ids]


def load_default_id(conn=None, cat=None):
    """ui.setting default_vendor_profile when it names a usable profile, else DEFAULT_ID."""
    from . import db
    row = db.query_one("SELECT value FROM ui.setting WHERE key = 'default_vendor_profile'", conn=conn)
    pid = row["value"] if row else ""
    cat = cat if cat is not None else catalog(conn)
    return pid if pid in cat else DEFAULT_ID


_REPO_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
ISSUE_TEMPLATE = "device-profile.yml"


def report_url(profile, repo, version):
    """A new-issue link for a problem with a built-in profile (issue form
    .github/ISSUE_TEMPLATE/device-profile.yml, whose fields "profile" and "version" it fills).
    Nothing about the site goes into it. None when `repo` is not owner/name."""
    if not isinstance(repo, str) or not _REPO_RE.fullmatch(repo):
        return None
    query = urllib.parse.urlencode({"template": ISSUE_TEMPLATE, "title": "Device profile %s: " % profile["id"],
                                    "profile": profile["id"], "version": version or ""})
    return "https://github.com/%s/issues/new?%s" % (repo, query)


# ---------------------------------------------------------------- the portal's profile form
# One attribute per line ("Attr := value" / "Attr += value"; CoA: "Attr = value"), one SNMP
# port-name rule per line ("regex => format", optionally followed by "(ignore case)").
_REPLY_LINE = re.compile(r"\s*([A-Za-z][A-Za-z0-9-]*)\s*(:=|\+=)\s*(.*?)\s*")
_COA_LINE = re.compile(r"\s*([A-Za-z][A-Za-z0-9-]*)\s*=\s*(.*?)\s*")
_RULE_LINE = re.compile(r"\s*(.+?)\s+=>\s+(\S+?)(\s+\(ignore case\))?\s*")
FORM_REPLY = {"vlan": "reply_vlan", "admin_full": "reply_admin", "role": "reply_role"}


def _lines(text):
    return [(n, ln) for n, ln in enumerate((text or "").replace("\r\n", "\n").split("\n"), 1) if ln.strip()]


def profile_to_form(p):
    """The form fields of the profile page for profile `p`."""
    f = {"id": p["id"], "label": p["label"], "description": p.get("description", ""),
         "mab_ethernet": "Ethernet" in p["mab"]["port_types"],
         "mab_wireless": "Wireless-802.11" in p["mab"]["port_types"],
         "coa_port": str(p["coa"]["port"]), "coa_identify": p["coa"]["identify"],
         "coa_send_port": p["coa"]["send_nas_port_id"],
         "port_rules": "\n".join("%s => %s%s" % (r["match"], r["format"], " (ignore case)" if r["ignore_case"] else "")
                                 for r in p["snmp"]["port_names"]),
         "setup_accounting": p["setup"]["accounting"] or "", "setup_coa": p["setup"]["coa"] or ""}
    for key, field in FORM_REPLY.items():
        f[field] = "\n".join("%s %s %s" % (e["attr"], e["op"], e["value"]) for e in p["reply"][key])
    for a in COA_ACTIONS:
        act = p["coa"][a]
        f["coa_%s_packet" % a] = act["packet"] if act else ""
        f["coa_%s_attrs" % a] = "\n".join("%s = %s" % (e["attr"], e["value"]) for e in act["attrs"]) if act else ""
    return f


def form_to_profile(f):
    """(profile, errors) from the profile page's fields; errors maps a field to its message.
    The document always goes through validate(); custom profiles are always unverified."""
    errors = {}
    doc = {"format": FORMAT, "id": f.get("id", ""), "label": f.get("label", ""),
           "description": f.get("description", ""), "status": "unverified", "reply": {},
           "mab": {"port_types": [t for t, k in (("Ethernet", "mab_ethernet"), ("Wireless-802.11", "mab_wireless"))
                                  if f.get(k)]},
           "coa": {"identify": f.get("coa_identify", ""), "send_nas_port_id": bool(f.get("coa_send_port"))},
           "snmp": {"port_names": []},
           "setup": {"accounting": (f.get("setup_accounting") or "").replace("\r\n", "\n").strip() or None,
                     "coa": (f.get("setup_coa") or "").replace("\r\n", "\n").strip() or None}}
    port = (f.get("coa_port") or "").strip()
    doc["coa"]["port"] = int(port) if port.isascii() and port.isdigit() and len(port) <= 5 else port
    for key, field in FORM_REPLY.items():
        doc["reply"][key] = []
        for n, ln in _lines(f.get(field)):
            m = _REPLY_LINE.fullmatch(ln)
            if not m:
                errors.setdefault(field, "Line %d: write Attribute := value (replace) or Attribute += value (add)." % n)
                continue
            doc["reply"][key].append({"attr": m.group(1), "op": m.group(2), "value": m.group(3)})
    for a in COA_ACTIONS:
        packet = f.get("coa_%s_packet" % a, "")
        attrs = []
        for n, ln in _lines(f.get("coa_%s_attrs" % a)):
            m = _COA_LINE.fullmatch(ln)
            if not m:
                errors.setdefault("coa_%s" % a, "Line %d: write Attribute = value." % n)
                continue
            attrs.append({"attr": m.group(1), "value": m.group(2)})
        if packet == "":
            if attrs:
                errors.setdefault("coa_%s" % a, "Choose a packet type, or remove the attributes.")
            doc["coa"][a] = None
        else:
            doc["coa"][a] = {"packet": packet, "attrs": attrs}
    for n, ln in _lines(f.get("port_rules")):
        m = _RULE_LINE.fullmatch(ln)
        if not m:
            errors.setdefault("port_rules", "Line %d: write regular-expression => format." % n)
            continue
        doc["snmp"]["port_names"].append({"match": m.group(1), "format": m.group(2), "ignore_case": bool(m.group(3))})
    if errors:
        return None, errors
    try:
        return validate(doc), {}
    except ProfileError as e:
        return None, {form_field(str(e)): str(e)}


_FIELD_OF = (("reply.vlan", "reply_vlan"), ("reply.admin_full", "reply_admin"), ("reply.role", "reply_role"),
             ("mab", "mab"), ("coa.port", "coa_port"), ("coa.identify", "coa_identify"),
             ("coa.send_nas_port_id", "coa_send_port"), ("coa.reauth", "coa_reauth"), ("coa.bounce", "coa_bounce"),
             ("coa.disconnect", "coa_disconnect"), ("snmp", "port_rules"), ("setup.accounting", "setup_accounting"),
             ("setup.coa", "setup_coa"), ("id", "id"), ("label", "label"), ("description", "description"))


def form_field(message):
    """The form field a validate() message is about ("reply.vlan[1].attr: ..." -> reply_vlan)."""
    for prefix, field in _FIELD_OF:
        if message.startswith(prefix):
            return field
    return "form"


# ---------------------------------------------------------------- FreeRADIUS dictionary
_dict_cache = {}


def dictionary_attributes(dict_dir):
    """Attribute names (lower case) defined in the FreeRADIUS dictionary files of `dict_dir`,
    or None when there are none to read. Cached per directory and file times."""
    try:
        files = sorted(os.path.join(dict_dir, f) for f in os.listdir(dict_dir) if f.startswith("dictionary"))
        key = (dict_dir, tuple((f, os.stat(f).st_mtime_ns) for f in files))
    except OSError:
        return None
    if key not in _dict_cache:
        names = set()
        for path in files:
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    for ln in fh:
                        parts = ln.split()
                        if len(parts) >= 3 and parts[0] == "ATTRIBUTE":
                            names.add(parts[1].lower())
            except OSError:
                continue
        _dict_cache.clear()
        _dict_cache[key] = names or None
    return _dict_cache[key]


def unknown_attributes(profile, names):
    """[(form field, attribute)] of attributes the dictionary `names` does not define."""
    out = []
    for key, field in FORM_REPLY.items():
        out += [(field, e["attr"]) for e in profile["reply"][key] if e["attr"].lower() not in names]
    for a in COA_ACTIONS:
        if profile["coa"][a]:
            out += [("coa_" + a, e["attr"]) for e in profile["coa"][a]["attrs"] if e["attr"].lower() not in names]
    return out


def coa_port(client, profile):
    """The UDP port CoA requests go to: the client's own setting, else its profile's."""
    return client.get("coa_port") or profile["coa"]["port"]


def supports(profile, action):
    return action in COA_ACTIONS and profile["coa"].get(action) is not None


def export_json(profile):
    """Shareable JSON text of a profile (re-validated, stable key order)."""
    return json.dumps(validate(profile), indent=2, sort_keys=True) + "\n"


def import_json(text):
    """A profile from shared JSON text, or ProfileError."""
    try:
        doc = json.loads(text)
    except (ValueError, TypeError) as e:
        raise ProfileError("not valid JSON (%s)" % e) from None
    return validate(doc)


# ---------------------------------------------------------------- applying

def port_name(profile, name):
    """The device's SNMP interface name as it appears in RADIUS (NAS-Port-Id)."""
    name = name.strip()
    for r in profile["snmp"]["port_names"]:
        m = re.fullmatch(r["match"], name, re.IGNORECASE if r["ignore_case"] else 0)
        if m:
            def sub(ref):
                g = m.group(int(ref.group(1))) or ""
                return g.lower() if ref.group(2) == "lower" else g.upper() if ref.group(2) == "upper" else g
            return _FORMAT_REF_RE.sub(sub, r["format"])
    return name


def format_value(value, placeholders=None):
    """A validated value as unlang / radclient text: a placeholder's replacement, a bare
    word (enumeration names such as VLAN, IEEE-802), or a double-quoted string."""
    if value in PLACEHOLDERS:
        return (placeholders or {})[value]
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*", value):
        return value
    return '"%s"' % value
