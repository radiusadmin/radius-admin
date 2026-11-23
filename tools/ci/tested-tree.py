#!/usr/bin/env python3
"""Find an earlier CI run in which a slow job passed on exactly this tree.

    tools/ci/tested-tree.py JOB TREE      prints that run's id, or nothing

JOB is `package` or `bench`; TREE is the tree id of the checked-out commit (`git rev-parse
'HEAD^{tree}'`: the content, whatever history led to it). When the job passes, its last step
uploads an artifact named tested-<JOB>-<TREE>. A squash merge into dev or a promotion to
testing usually has the tree a pull request run already tested, so CI finds the marker and
skips the job. A marker counts only when it
  - has not expired and is younger than TESTED_TREE_MAX_AGE seconds (default 7 days: the
    runner image and the Ubuntu archive change underneath an unchanged tree),
  - comes from a run on this repository's own branches (a pull request from a fork runs the
    fork's copy of the workflow, which could upload any marker),
  - is not from the current run (GITHUB_RUN_ID).
The artifacts are read with `gh api` (GITHUB_REPOSITORY, GH_TOKEN). Exits 2 on bad
arguments and 1 when the lookup fails; the workflow then runs the job.
"""
import datetime
import json
import os
import re
import subprocess
import sys

JOBS = ("package", "bench")


def parse_time(s):
    return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)


def pick(artifacts, name, run_id, max_age, now):
    for a in artifacts:
        w = a.get("workflow_run") or {}
        if (a.get("name") == name and a.get("expired") is False
                and isinstance(w.get("id"), int) and w["id"] != run_id
                and w.get("repository_id") is not None
                and w.get("repository_id") == w.get("head_repository_id")
                and (now - parse_time(a["created_at"])).total_seconds() < max_age):
            return w["id"]
    return None


def main(argv):
    if len(argv) != 2 or argv[0] not in JOBS or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", argv[1]):
        print("usage: tested-tree.py package|bench TREE", file=sys.stderr)
        return 2
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    run = os.environ.get("GITHUB_RUN_ID", "")
    max_age = os.environ.get("TESTED_TREE_MAX_AGE", "604800")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) or not re.fullmatch(r"[0-9]+", run) \
            or not re.fullmatch(r"[0-9]+", max_age):
        print("tested-tree.py: GITHUB_REPOSITORY, GITHUB_RUN_ID or TESTED_TREE_MAX_AGE missing or invalid",
              file=sys.stderr)
        return 2
    name = "tested-%s-%s" % (argv[0], argv[1])
    try:
        out = subprocess.run(["gh", "api", "-X", "GET", "repos/%s/actions/artifacts" % repo,
                              "-f", "name=" + name, "-F", "per_page=100"],
                             check=True, capture_output=True, text=True, timeout=60).stdout
        artifacts = json.loads(out)["artifacts"]
        found = pick(artifacts, name, int(run), int(max_age),
                     datetime.datetime.now(datetime.timezone.utc))
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError) as e:
        print("tested-tree.py: lookup failed: %s" % e, file=sys.stderr)
        return 1
    if found is not None:
        print(found)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
