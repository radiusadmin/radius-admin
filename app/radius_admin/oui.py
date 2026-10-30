"""MAC address vendor names from the IEEE registry, offline.

Reads the CSV files of the Ubuntu package `ieee-data` (/usr/share/ieee-data):
MA-L (24-bit OUI), MA-M (28-bit) and MA-S (36-bit) assignments. The longest match
wins. Loaded once per process on first use (about 40 000 entries, a few MB).

Addresses with the locally-administered bit set are not in any registry: phones and
laptops use them as randomized "private" addresses, and virtual machines use them too.
"""
import csv
import os
import re
import threading

DATA_DIR = "/usr/share/ieee-data"
FILES = (("oui36.csv", 9), ("mam.csv", 7), ("oui.csv", 6))   # file, hex digits of the prefix
PRIVATE = "Private (randomized or locally assigned) address"

_lock = threading.Lock()
_tables = None          # {digits: {prefix: name}}
_HEX12 = re.compile(r"^[0-9A-F]{12}$")


def _load(data_dir):
    tables = {}
    for name, digits in FILES:
        path = os.path.join(data_dir, name)
        t = {}
        try:
            with open(path, newline="", encoding="utf-8", errors="replace") as fh:
                for row in csv.reader(fh):
                    if len(row) < 3 or row[0] == "Registry":
                        continue
                    prefix = row[1].strip().upper()
                    org = " ".join(row[2].split())[:120]
                    if len(prefix) == digits and org:
                        t[prefix] = org
        except OSError:
            pass
        tables[digits] = t
    return tables


def _get_tables():
    global _tables
    if _tables is None:
        with _lock:
            if _tables is None:
                _tables = _load(os.environ.get("RADIUS_ADMIN_IEEE_DATA", DATA_DIR))
    return _tables


def available():
    return any(_get_tables().values())


def normalize(mac):
    """Any common MAC notation -> 12 upper-case hex digits, or None."""
    if not mac:
        return None
    h = re.sub(r"[^0-9A-Fa-f]", "", str(mac)).upper()
    return h if _HEX12.match(h) else None


def vendor(mac):
    """Vendor name, PRIVATE for locally-administered addresses, or '' if unknown."""
    h = normalize(mac)
    if h is None:
        return ""
    first = int(h[:2], 16)
    if first & 0x02:
        return PRIVATE
    tables = _get_tables()
    for _, digits in FILES:
        org = tables.get(digits, {}).get(h[:digits])
        if org:
            # MA-L blocks that IEEE re-sells as MA-M / MA-S are listed as the registration
            # authority; a longer match was already tried first.
            return org
    return ""


def reset_cache():
    global _tables
    with _lock:
        _tables = None
