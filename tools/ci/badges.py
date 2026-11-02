#!/usr/bin/env python3
"""Write the shields.io endpoint files for the README badges from the CI job results.

    NEEDS='${{ toJSON(needs) }}' tools/ci/badges.py OUTDIR

Writes OUTDIR/tests.json (all suites) and OUTDIR/bench.json (FreeRADIUS bench). A job that
did not succeed turns its badge red even when no test reported a failure (it stopped early).
"""
import json
import os
import sys


def badge(label, message, ok):
    return {"schemaVersion": 1, "label": label, "message": message,
            "color": "brightgreen" if ok else "red"}


def num(outputs, key):
    try:
        return int(outputs.get(key) or 0)
    except ValueError:
        return 0


def main(outdir, needs):
    passed = failed = 0
    all_ok = True
    for job in needs.values():
        out = job.get("outputs") or {}
        passed += num(out, "passed")
        failed += num(out, "failed")
        all_ok = all_ok and job.get("result") == "success"
    if failed:
        tests = badge("tests", "%d failing, %d passing" % (failed, passed), False)
    elif not all_ok:
        tests = badge("tests", "failing", False)
    else:
        tests = badge("tests", "%d passing" % passed, True)

    bench = needs.get("bench") or {}
    out = bench.get("outputs") or {}
    bp, bf = num(out, "bench_passed"), num(out, "bench_failed")
    bench_ok = bench.get("result") == "success" and bf == 0 and bp > 0
    bench_badge = badge("FreeRADIUS bench", "%d/%d" % (bp, bp + bf) if bp + bf else "failing", bench_ok)

    os.makedirs(outdir, exist_ok=True)
    for name, data in (("tests.json", tests), ("bench.json", bench_badge)):
        with open(os.path.join(outdir, name), "w", encoding="utf-8") as f:
            json.dump(data, f)
            f.write("\n")
        print("%s: %s" % (name, data["message"]))


if __name__ == "__main__":
    main(sys.argv[1], json.loads(os.environ["NEEDS"]))
