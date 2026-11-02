#!/usr/bin/env python3
"""Release notes for a build, in Markdown (SPEC section 16).

    tools/release/release-notes.py CHANGELOG VERSION [COMMITS_FILE]

A release (X.Y.Z) gets its "## X.Y.Z" section of CHANGELOG.md. A testing or dev build gets
the "## Unreleased" section, followed by the commit subjects in COMMITS_FILE (one per line)
when given.
"""
import re
import sys


def section(text, heading):
    """Body of the '## <heading>' section (heading may be followed by ' — date')."""
    out, inside = [], False
    pat = re.compile(r"^##\s+" + re.escape(heading) + r"(\s|$)")
    for line in text.splitlines():
        if line.startswith("## "):
            if inside:
                break
            inside = bool(pat.match(line))
            continue
        if inside:
            out.append(line)
    return "\n".join(out).strip()


def notes(changelog, version, commits=()):
    release = re.fullmatch(r"\d+\.\d+\.\d+", version) is not None
    body = section(changelog, version if release else "Unreleased")
    parts = [body] if body else []
    commits = [c.strip() for c in commits if c.strip()]
    if not release and commits:
        parts.append("### Commits\n" + "\n".join("- " + c for c in commits))
    return "\n\n".join(parts) or "No notes for this build."


def main(argv):
    with open(argv[1], encoding="utf-8") as fh:
        changelog = fh.read()
    commits = []
    if len(argv) > 3:
        with open(argv[3], encoding="utf-8") as fh:
            commits = fh.read().splitlines()
    print(notes(changelog, argv[2], commits))


if __name__ == "__main__":
    main(sys.argv)
