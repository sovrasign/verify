#!/usr/bin/env python3
"""Developer Certificate of Origin check (.github/workflows/dco.yml; CONTRIBUTING.md).

    scripts/check-dco.py BASE HEAD    every non-merge commit in BASE..HEAD must be signed off
    scripts/check-dco.py --self-test  check the rule on made-up commit messages

A commit is signed off when its message has a `Signed-off-by: Name <email>` line whose email is
the commit author's (case-insensitive), as `git commit -s` writes it.
"""

import re
import subprocess
import sys

SIGNOFF = re.compile(r"^Signed-off-by: .+ <([^<>\s]+)>\s*$", re.MULTILINE)


def signed_off(message: str, author_email: str) -> bool:
    return any(m.lower() == author_email.lower() for m in SIGNOFF.findall(message))


def commits(base: str, head: str):
    out = subprocess.run(
        ["git", "log", "--no-merges", "--format=%H%x00%ae%x00%B%x01", f"{base}..{head}"],
        check=True, capture_output=True, text=True,
    ).stdout
    for record in out.split("\x01"):
        record = record.strip("\n")
        if record:
            sha, email, message = record.split("\x00", 2)
            yield sha, email, message


def self_test() -> int:
    ok = "Fix a thing\n\nSigned-off-by: Ada Lovelace <ada@example.org>\n"
    assert signed_off(ok, "ada@example.org")
    assert signed_off(ok, "ADA@example.org")
    assert not signed_off(ok, "bob@example.org"), "another person's sign-off does not count"
    assert not signed_off("Fix\n\nsigned-off-by: Ada <ada@example.org>\n", "ada@example.org")
    assert not signed_off("Fix\n\nCo-Authored-By: Ada <ada@example.org>\n", "ada@example.org")
    print("check-dco self-test passed")
    return 0


def main(argv) -> int:
    if argv == ["--self-test"]:
        return self_test()
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    missing = [(sha, email) for sha, email, msg in commits(*argv) if not signed_off(msg, email)]
    for sha, email in missing:
        print(f"::error::commit {sha[:12]} has no 'Signed-off-by:' line for its author {email} "
              "(commit with `git commit -s`; see CONTRIBUTING.md)")
    if not missing:
        print("every commit is signed off")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
