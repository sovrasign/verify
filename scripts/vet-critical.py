#!/usr/bin/env python3
"""Check cargo vet's policy for the crates on the signing and verification path.

Every crate named in core/supply-chain/critical.txt must be vouched for by cargo vet (that is
`cargo vet --locked`). This adds one rule: when one of them is vouched for only by an exemption,
that exact (crate, version) must be on the frozen baseline recorded when cargo vet was introduced,
core/supply-chain/critical-baseline.txt. A new version of a critical crate therefore
fails here until it is audited, or an audit is imported; what an
exemption's notes say does not matter. The baseline only shrinks: a line for a version that is no
longer exempted (audited since) fails too, so it cannot be reused later.

It also checks that cargo vet's store files have LF line endings (cargo vet compares them byte
for byte; .gitattributes keeps them LF on Windows checkouts) and prints the audit backlog: the
critical crate versions still vouched for by the baseline only.

`--self-test` runs the rule on built-in examples. Needs Python 3.11 (tomllib).
"""
import pathlib
import sys
import tomllib

STORE_FILES = ("config.toml", "audits.toml", "imports.lock")


def read_list(path):
    """Non-empty, non-comment lines of a text file."""
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def parse_baseline(lines):
    pairs = set()
    for line in lines:
        parts = line.split()
        if len(parts) != 2:
            raise ValueError(f"critical-baseline.txt: expected '<crate> <version>', got {line!r}")
        pairs.add((parts[0], parts[1]))
    return pairs


def check(critical, exemptions, baseline):
    """Return (backlog, outside, stale) for the critical crates.

    backlog: exempted critical versions on the baseline; outside: exempted critical versions not
    on it; stale: baseline lines no longer exempted (or no longer critical).
    """
    exempted = set()
    for name in critical:
        for ex in exemptions.get(name, []):
            exempted.add((name, ex["version"]))
    backlog = sorted(exempted & baseline)
    outside = sorted(exempted - baseline)
    stale = sorted(baseline - exempted)
    return backlog, outside, stale


def self_test():
    critical = ["p256", "der"]
    baseline = {("p256", "0.14.0"), ("der", "0.8.3")}
    ok = {"p256": [{"version": "0.14.0"}], "der": [{"version": "0.8.3"}], "rand": [{"version": "1"}]}
    assert check(critical, ok, baseline) == ([("der", "0.8.3"), ("p256", "0.14.0")], [], [])
    # A new version exempted with notes copied from the baseline still fails.
    new = dict(ok, p256=[{"version": "0.14.0"}, {"version": "0.14.1", "notes": "baseline"}])
    assert check(critical, new, baseline)[1] == [("p256", "0.14.1")]
    # An audited version leaves the exemptions; its baseline line is then stale.
    audited = {"p256": [{"version": "0.14.0"}]}
    assert check(critical, audited, baseline)[2] == [("der", "0.8.3")]
    # Non-critical crates are not this script's business.
    assert check(critical, {"rand": [{"version": "9"}]}, set()) == ([], [], [])
    try:
        parse_baseline(["p256"])
        raise AssertionError("a malformed baseline line must be refused")
    except ValueError:
        pass
    print("vet-critical self-test passed.")


def main():
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return
    root = pathlib.Path(__file__).resolve().parent.parent / "core" / "supply-chain"

    crlf = [f for f in STORE_FILES if b"\r\n" in (root / f).read_bytes()]
    if crlf:
        print("cargo vet's store files must have LF line endings; these have CRLF:")
        for f in crlf:
            print(f"  core/supply-chain/{f}")
        print("Check them out again (git rm --cached -r -q core/supply-chain && "
              "git reset -q -- core/supply-chain && git checkout -- core/supply-chain); "
              ".gitattributes keeps them LF.")
        sys.exit(1)

    critical = read_list(root / "critical.txt")
    baseline = parse_baseline(read_list(root / "critical-baseline.txt"))
    config = tomllib.loads((root / "config.toml").read_text(encoding="utf-8"))
    backlog, outside, stale = check(critical, config.get("exemptions", {}), baseline)

    if backlog:
        print(f"Audit backlog ({len(backlog)} critical crate versions on the baseline):")
        for name, version in backlog:
            print(f"  {name} {version}")
    failed = False
    if outside:
        failed = True
        print("A crate on the signing and verification path is exempted outside the baseline:")
        for name, version in outside:
            print(f"  {name} {version}")
        print("Audit it (cargo vet certify) or import an audit; do not exempt it, and do not add it "
              "to critical-baseline.txt. docs/SUPPLY_CHAIN.md")
    if stale:
        failed = True
        print("critical-baseline.txt lists versions that are no longer exempted; remove these lines:")
        for name, version in stale:
            print(f"  {name} {version}")
    if failed:
        sys.exit(1)
    print(f"Critical crates: {len(critical)}; none exempted outside the baseline.")


if __name__ == "__main__":
    main()
