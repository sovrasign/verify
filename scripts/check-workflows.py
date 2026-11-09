#!/usr/bin/env python3
"""Workflow hygiene that OpenSSF Scorecard scores (docs/RELEASES.md), checked locally
(python3 scripts/check-workflows.py):

- every `uses:` of another repository's action is pinned to a full commit SHA (Pinned-Dependencies);
- every workflow sets top-level `permissions:` (Token-Permissions), and grants `write` only inside
  a job;
- no workflow runs on `pull_request_target` (Dangerous-Workflow).
"""

import pathlib
import re
import sys

root = pathlib.Path(__file__).resolve().parent.parent
problems = []
for wf in sorted((root / ".github" / "workflows").glob("*.yml")):
    text = wf.read_text(encoding="utf-8")
    name = wf.relative_to(root).as_posix()
    for n, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", line)
        if m:
            ref = m.group(1)
            if not ref.startswith("./") and not re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", ref):
                problems.append(f"{name}:{n}: action not pinned to a commit SHA: {ref}")
    if not re.search(r"^permissions:", text, re.MULTILINE):
        problems.append(f"{name}: no top-level permissions")
    top = re.search(r"^permissions:(.*?)^\S", text, re.MULTILINE | re.DOTALL)
    if top and "write" in top.group(1):
        problems.append(f"{name}: top-level permissions grant write (grant it in the job)")
    if "pull_request_target" in text:
        problems.append(f"{name}: pull_request_target runs untrusted code with a write token")
for p in problems:
    print(p, file=sys.stderr)
print(f"workflow check: {'failed' if problems else 'passed'} ({len(list((root / '.github' / 'workflows').glob('*.yml')))} workflows)")
sys.exit(1 if problems else 0)
