#!/bin/bash
# Site-data scan: prints every line that may carry data from a real deployment.
# Exit 0 = clean, 1 = hits found.
#
# Generic checks live here. Organization-specific terms (names, domains, address
# prefixes of a real site) must NOT be committed; keep them one per line (extended
# regex) in a file outside the repository and point SITE_TERMS at it:
#   SITE_TERMS=~/.config/radius-admin/site-terms.txt tools/site-scan.sh
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TERMS=${SITE_TERMS:-$HOME/.config/radius-admin/site-terms.txt}
EXCL=(--exclude-dir=.git --exclude-dir=__pycache__ --exclude-dir=.pytest_cache
      --exclude-dir=diffs --exclude=site-scan.sh --exclude=site-scan.allow)
ALLOW="$ROOT/tools/site-scan.allow"   # committed: regexes for known-fake test values
hits=0
report() {
    local out=$1
    [[ -n $out && -r $ALLOW ]] && out=$(grep -vE -f <(grep -vE '^\s*(#|$)' "$ALLOW") <<<"$out")
    if [[ -n $out ]]; then echo "== $2"; echo "$out"; hits=1; fi
}

if [[ -r $TERMS ]]; then
    report "$(grep -rIniE -f <(grep -vE '^\s*(#|$)' "$TERMS") "${EXCL[@]}" "$ROOT")" "site terms ($TERMS)"
else
    echo "warning: no site-terms file at $TERMS; only generic checks run" >&2
fi
# private IPv4 ranges (documentation ranges 192.0.2/198.51.100/203.0.113 and 127/8 are fine)
report "$(grep -rInE '(^|[^0-9.])(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})([^0-9]|$)' \
        "${EXCL[@]}" "$ROOT")" "private IPv4 addresses (add known-fake values to tools/site-scan.allow)"
# domains other than example.* (allow common upstream/public hosts)
report "$(grep -rIoniE '\b[a-z0-9-]+\.(corp|local|lan|internal|int)\b' "${EXCL[@]}" "$ROOT" | grep -viE 'example' | head -50)" "internal-looking domain names"
# secrets
report "$(grep -rInE '(password|secret|identity)\s*=\s*"?[^"R$@{<]' "${EXCL[@]}" "$ROOT/freeradius" "$ROOT/deploy/etc" | grep -viE 'REDACTED|example|^\S+:\s*#' | head -50)" "possible secrets in shipped config"
report "$(find "$ROOT" \( -name __pycache__ -o -name .pytest_cache -o -name '*.pyc' -o -name '*.key' -o -name '*.p12' \) -not -path '*/.git/*' 2>/dev/null)" "build debris or key files"
[[ $hits = 0 ]] && echo "site-data scan: clean"
exit $hits
