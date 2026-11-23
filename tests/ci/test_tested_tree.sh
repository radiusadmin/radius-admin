#!/bin/bash
# CI skips the package and bench jobs for a tree that already passed them (tools/ci/tested-tree.py,
# .github/workflows/ci.yml). Checks which markers the lookup accepts, that it fails open, and that
# the workflow wires it so main pushes and manual runs always run everything. Uses a fake `gh`;
# touches nothing outside a temp directory and needs no network.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
LOOKUP=$ROOT/tools/ci/tested-tree.py
WF=$ROOT/.github/workflows/ci.yml
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
fails=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; fails=$((fails + 1)); }

TREE=0123456789abcdef0123456789abcdef01234567
mkdir -p "$W/bin"
# fake gh: records its arguments, prints $W/reply, exits with $W/rc (default 0)
cat > "$W/bin/gh" <<EOF
#!/bin/bash
printf '%s\n' "\$@" > "$W/args"
cat "$W/reply" 2>/dev/null
exit "\$(cat "$W/rc" 2>/dev/null || echo 0)"
EOF
chmod +x "$W/bin/gh"

# reply SPEC...: one artifact per SPEC "name:age_seconds:expired:run_id:repo:head_repo"
reply() {
    python3 - "$@" > "$W/reply" <<'PY'
import datetime, json, sys
now = datetime.datetime.now(datetime.timezone.utc)
arts = []
for spec in sys.argv[1:]:
    name, age, expired, run, repo, head = spec.split(":")
    t = (now - datetime.timedelta(seconds=int(age))).strftime("%Y-%m-%dT%H:%M:%SZ")
    arts.append({"name": name, "expired": expired == "true", "created_at": t,
                 "workflow_run": {"id": int(run), "repository_id": int(repo), "head_repository_id": int(head)}})
print(json.dumps({"total_count": len(arts), "artifacts": arts}))
PY
}
look() { PATH="$W/bin:$PATH" GITHUB_REPOSITORY=example/radius-admin GITHUB_RUN_ID=500 GH_TOKEN=x \
         python3 "$LOOKUP" "$@" 2>"$W/err"; }
expect() {  # expect LABEL WANT_STDOUT WANT_RC ARGS...
    local label=$1 want=$2 want_rc=$3 out rc
    shift 3
    out=$(look "$@"); rc=$?
    if [[ $out == "$want" && $rc == "$want_rc" ]]; then pass "$label"
    else fail "$label (got '$out' rc $rc, want '$want' rc $want_rc; $(cat "$W/err"))"; fi
}
N=tested-bench-$TREE

# --- which markers count
reply;                                    expect "no marker: run the job"           "" 0 bench "$TREE"
reply "$N:3600:false:400:7:7";            expect "fresh marker from this repo"      400 0 bench "$TREE"
grep -qx "name=$N" "$W/args" && grep -qx "repos/example/radius-admin/actions/artifacts" "$W/args" \
    && pass "asks for the job's marker by exact name" || fail "gh arguments: $(tr '\n' ' ' < "$W/args")"
reply "$N:3600:true:400:7:7";             expect "expired marker is ignored"        "" 0 bench "$TREE"
reply "$N:700000:false:400:7:7";          expect "marker older than 7 days ignored" "" 0 bench "$TREE"
reply "$N:3600:false:400:7:8";            expect "marker from a fork is ignored"    "" 0 bench "$TREE"
reply "$N:3600:false:500:7:7";            expect "marker from this run is ignored"  "" 0 bench "$TREE"
reply "tested-package-$TREE:3600:false:400:7:7"
                                          expect "other job's marker is ignored"    "" 0 bench "$TREE"
reply "$N:3600:false:401:7:8" "$N:60:false:402:7:7"
                                          expect "skips a bad marker, takes a good" 402 0 bench "$TREE"
reply "$N:3600:false:400:7:7"
out=$(TESTED_TREE_MAX_AGE=60 look bench "$TREE")
[[ -z $out ]] && pass "TESTED_TREE_MAX_AGE shortens the window" || fail "max age ignored ($out)"

# --- fails open, refuses bad input
echo 1 > "$W/rc";                         expect "gh failure: exit 1"               "" 1 bench "$TREE"
rm -f "$W/rc"; echo 'not json' > "$W/reply"
                                          expect "bad JSON: exit 1"                 "" 1 bench "$TREE"
reply
expect "unknown job refused"      "" 2 unit "$TREE"
expect "bad tree id refused"      "" 2 bench "${TREE:0:39}"
expect "tree id with newline"     "" 2 bench "$TREE"$'\n'
out=$(PATH="$W/bin:$PATH" GITHUB_REPOSITORY='a/b?x=1' GITHUB_RUN_ID=5 python3 "$LOOKUP" bench "$TREE" 2>/dev/null); rc=$?
[[ $rc == 2 ]] && pass "bad GITHUB_REPOSITORY refused" || fail "bad GITHUB_REPOSITORY: rc $rc"

# --- the workflow
job() { awk -v j="  $1:" '$0==j{p=1;print;next} p&&/^  [a-z_-]+:$/{p=0} p' "$WF"; }
for j in package bench; do
    body=$(job "$j")
    grep -q 'needs: tested' <<<"$body" && pass "$j waits for the lookup" || fail "$j lacks needs: tested"
    grep -q "!cancelled() && needs.tested.outputs.${j}_run == ''" <<<"$body" \
        && pass "$j runs unless a run is found (also when the lookup job failed)" || fail "$j skip condition"
    grep -q "name: tested-$j-\${{ needs.tested.outputs.tree }}" <<<"$body" \
        && pass "$j records its marker" || fail "$j uploads no marker"
    tail -n 12 <<<"$body" | grep -q "name: tested-$j-" \
        && pass "$j records the marker in its last steps" || fail "$j marker is not at the end"
done
body=$(job tested)
grep -q 'actions: read' <<<"$body" && pass "lookup job may read artifacts" || fail "lookup lacks actions: read"
grep -q 'workflow_dispatch' <<<"$body" && grep -q '"$GITHUB_REF_NAME" = main' <<<"$body" \
    && pass "manual runs and pushes to main never skip" || fail "main/manual runs can skip"
grep -q 'for job in package bench; do' <<<"$body" && grep -q 'tools/ci/tested-tree.py "$job" "$tree"' <<<"$body" \
    && pass "lookup runs for both jobs" || fail "lookup does not cover both jobs"

echo
if (( fails )); then echo "$fails check(s) failed"; exit 1; fi
echo "all checks passed"
