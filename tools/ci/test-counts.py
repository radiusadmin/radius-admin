#!/usr/bin/env python3
"""Count passed and failed tests in suite logs, for the README badges.

    tools/ci/test-counts.py LOG...      prints passed=N and failed=N (GITHUB_OUTPUT format)

Each log is read in the format its suite prints:
  pytest -q        last summary line, e.g. "3 failed, 373 passed, 1 skipped in 64.9s"
                   (errors count as failed, skipped tests are not counted)
  FreeRADIUS bench "124 passed, 0 failed"
  shell suites     one "PASS: ..." or "FAIL: ..." line per check
A missing log (its step did not run) counts as nothing.
"""
import os
import re
import sys

PYTEST = re.compile(r"^=*\s*((?:\d+ (?:passed|failed|errors?|skipped|deselected|xfailed|xpassed|warnings?),? ?)+)"
                    r"\s+in [0-9.]+s")
BENCH = re.compile(r"^(\d+) passed, (\d+) failed$")


def count(text):
    lines = text.splitlines()
    for line in reversed(lines):
        m = PYTEST.match(line.strip())
        if m:
            n = {w.rstrip("s"): int(c) for c, w in re.findall(r"(\d+) (\w+)", m.group(1))}
            return n.get("passed", 0), n.get("failed", 0) + n.get("error", 0)
    for line in reversed(lines):
        m = BENCH.match(line.strip())
        if m:
            return int(m.group(1)), int(m.group(2))
    return (sum(1 for x in lines if x.startswith("PASS:")),
            sum(1 for x in lines if x.startswith("FAIL:")))


def main(paths):
    passed = failed = 0
    for path in paths:
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8", errors="replace") as f:
            p, fl = count(f.read())
        passed += p
        failed += fl
    print("passed=%d" % passed)
    print("failed=%d" % failed)


if __name__ == "__main__":
    main(sys.argv[1:])
