"""Display helpers for the informational 802.1X port list of a RADIUS client.

The stored value is free text as exported from the switch, e.g. "gi1/0/1-20,gi1/0/23".
parse_ports() turns it into display groups; nothing here is used for authentication.
"""
import re

# <prefix><last number>[-<end>]   e.g. gi1/0/1-20, te1/1/4, Gi1/0/1 - 24, po1
_RANGE_RE = re.compile(r"^(?P<prefix>[A-Za-z][A-Za-z\-]*\s?(?:\d+/)*)(?P<start>\d+)\s*(?:-\s*(?P<end>\d+))?$")
_SPLIT_RE = re.compile(r"[,;\s]*,[,;\s]*|;")


def parse_ports(value):
    """Return a list of groups: {"label", "prefix", "start", "end", "count"} (count None
    for tokens that are not recognisable interface names/ranges -- shown as is)."""
    groups = []
    for tok in _SPLIT_RE.split(value or ""):
        tok = " ".join(tok.split())
        if not tok:
            continue
        m = _RANGE_RE.match(tok)
        if not m:
            groups.append({"label": tok, "prefix": None, "start": None, "end": None, "count": None})
            continue
        prefix = m.group("prefix").replace(" ", "")
        start = int(m.group("start"))
        end = int(m.group("end")) if m.group("end") else start
        if end < start:
            groups.append({"label": tok, "prefix": None, "start": None, "end": None, "count": None})
            continue
        label = "%s%d" % (prefix, start) if end == start else "%s%d–%d" % (prefix, start, end)
        groups.append({"label": label, "prefix": prefix, "start": start, "end": end,
                       "count": end - start + 1})
    return groups


def port_summary(value):
    """{"groups": [...], "total": int or None, "unknown": bool} for templates."""
    groups = parse_ports(value)
    counts = [g["count"] for g in groups]
    return {"groups": groups,
            "total": sum(c for c in counts if c is not None),
            "unknown": any(c is None for c in counts)}


def port_set(value):
    """Expand a port list to a set of individual port names (for comparing the CSV
    value with what the switch reports, regardless of formatting). Unrecognised
    tokens are kept as-is."""
    out = set()
    for g in parse_ports(value):
        if g["count"] is None:
            out.add(g["label"].lower())
        else:
            for n in range(g["start"], g["end"] + 1):
                out.add(("%s%d" % (g["prefix"], n)).lower())
    return out


def same_ports(a, b):
    return port_set(a) == port_set(b)
