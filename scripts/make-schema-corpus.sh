#!/usr/bin/env bash
# Add envelope-schema compatibility fixtures made by the CLI of an earlier (or the current)
# commit. Builds that commit in a temporary git worktree, runs its `signpdf demo` (prepare, sign,
# sign, plus, from late October 2026, an envelope that takes no signature timestamps, then
# documents with validation data and document timestamps, and from schema v5 an envelope of
# several documents) and one decline, and freezes the outputs under
#
#   core/signpdf-core/tests/corpus/v<N>/<label>/
#
# where N is that commit's SCHEMA_VERSION. Each PDF gets the generating build's own verification
# report (`<name>.report.json`, with --insecure-dev-trust), and the directory gets `trust.json`,
# pinning the test-issuer keys embedded in the fixtures (so later builds can also verify them
# without the insecure dev opt-in) and, when the demo used one (from October 2026), its test
# TSA's certificate, and `SOURCE.txt` saying how it was made.
#
#   scripts/make-schema-corpus.sh <commit> <label>
#
# Fixtures are never regenerated: they record what a past build wrote. The script refuses to
# overwrite an existing directory. Needs git, cargo, and python (3.8+). See
# core/signpdf-core/tests/corpus/README.md.
set -euo pipefail

if [ $# -ne 2 ]; then
  sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi
commit=$1 label=$2
case "$label" in *[!a-z0-9-]*|"") echo "label must be lowercase letters, digits and dashes" >&2; exit 2 ;; esac

root=$(git rev-parse --show-toplevel)
sha=$(git -C "$root" rev-parse --verify "$commit^{commit}")
# The first interpreter that runs (on Windows, `python3` may be a Microsoft Store placeholder).
python=""
for p in python3 python; do
  if command -v "$p" >/dev/null && "$p" -c "import sys" >/dev/null 2>&1; then python=$p; break; fi
done
[ -n "$python" ] || { echo "python 3 is required" >&2; exit 2; }

work=$(mktemp -d)
cleanup() {
  git -C "$root" worktree remove --force "$work/src" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
git -C "$root" worktree add --quiet --detach "$work/src" "$sha"

version=$(sed -n 's/^pub const SCHEMA_VERSION: u32 = \([0-9][0-9]*\);.*/\1/p' \
  "$work/src/core/signpdf-core/src/lib.rs")
[ -n "$version" ] || { echo "cannot find SCHEMA_VERSION at $sha" >&2; exit 1; }
out="$root/core/signpdf-core/tests/corpus/v$version/$label"
if [ -e "$out" ]; then
  echo "$out already exists; corpus fixtures are never regenerated" >&2
  exit 1
fi

echo "Building signpdf-cli at $sha (schema v$version)..."
# CARGO_TARGET_DIR may point at a short path (Windows limits paths to 260 characters) and can be
# shared between runs.
target=${CARGO_TARGET_DIR:-$work/src/core/target}
(cd "$work/src/core" && CARGO_TARGET_DIR="$target" cargo build --quiet --locked --release -p signpdf-cli)
cli="$target/release/signpdf"
[ -x "$cli" ] || cli="$cli.exe"
toolchain=$(cd "$work/src/core" && rustc --version)

demo="$work/demo"
"$cli" demo --out-dir "$demo" >"$work/demo.log"
"$cli" sign --input "$demo/prepared.pdf" --email alice@example.com --decline \
  --reason "Corpus fixture: the first signer declines" --out "$demo/declined.pdf" >"$work/decline.log"

mkdir -p "$out"
names="prepared signed-by-alice signed-final declined"
# Demos from late October 2026 also prepare and sign the NDA with signature_timestamps = none, and
# then seal documents with validation data (DSS) and document timestamps; from schema v5 they
# prepare and sign an envelope of three documents combined into one PDF.
for extra in prepared-no-timestamps signed-no-timestamps signed-optional-timestamps signed-ltv \
  sealed-no-timestamps prepared-documents signed-documents; do
  if [ -f "$demo/$extra.pdf" ]; then names="$names $extra"; fi
done
for name in $names; do
  cp "$demo/$name.pdf" "$out/$name.pdf"
  # The generating build's verdict, frozen. `verify` exits non-zero for a document that is not
  # valid; the report is what matters.
  "$cli" verify --input "$out/$name.pdf" --json --insecure-dev-trust >"$out/$name.report.json" || true
done

# trust.json: pin every test-issuer key the fixtures embed, for the audiences they used.
# tsa.der: the demo's test TSA (demos from October 2026 timestamp the last signature), or from
# 2026-10-27 the root CA that issued it, pinned as a timestamp anchor so the timestamps verify as
# trusted.
tsa_der="$demo/tsa.der"
[ -f "$tsa_der" ] || tsa_der=""
"$python" - "$out" "$tsa_der" <<'PY'
import base64, json, pathlib, sys
out = pathlib.Path(sys.argv[1])
tsa_der = sys.argv[2]
issuers = {}
def pin(iss, jwk, aud):
    entry = issuers.setdefault(iss, {"issuer": iss, "name": "SignPDF test issuer (corpus)",
                                     "keys": [], "audiences": []})
    key = json.loads(jwk)
    if key not in entry["keys"]:
        entry["keys"].append(key)
    if aud and aud not in entry["audiences"]:
        entry["audiences"].append(aud)
for report in sorted(out.glob("*.report.json")):
    env = json.loads(report.read_text(encoding="utf-8"))["envelope"]
    pin(env["created_by_issuer"], env["created_by_idp_jwk"], env["created_by_audience"])
    for r in env["signatures"]:
        pin(r["idp_issuer"], r["idp_jwk"], r["idp_audience"])
anchors = [base64.b64encode(pathlib.Path(tsa_der).read_bytes()).decode()] if tsa_der else []
store = {"issuers": list(issuers.values()), "tsa_anchors": anchors, "allow_insecure_dev_issuer": False}
(out / "trust.json").write_text(json.dumps(store, indent=2) + "\n", encoding="utf-8")
PY

cat >"$out/SOURCE.txt" <<TXT
Envelope schema v$version fixtures, made by scripts/make-schema-corpus.sh. Do not edit or regenerate.

commit:    $sha ($(git -C "$root" show -s --format='%ad, %s' --date=short "$sha"))
toolchain: $toolchain
made:      $(date -u +%Y-%m-%dT%H:%M:%SZ)
commands:  signpdf demo --out-dir DIR    (prepared.pdf, signed-by-alice.pdf, signed-final.pdf,
                                         and any of prepared-no-timestamps.pdf,
                                         signed-no-timestamps.pdf,
                                         signed-optional-timestamps.pdf, signed-ltv.pdf,
                                         sealed-no-timestamps.pdf, prepared-documents.pdf,
                                         signed-documents.pdf the demo wrote)
           signpdf sign --input DIR/prepared.pdf --email alice@example.com --decline
                        --reason "Corpus fixture: the first signer declines"   (declined.pdf)
           signpdf verify --input FILE --json --insecure-dev-trust   (FILE.report.json)
trust.json pins the test-issuer keys embedded in these files (no insecure dev opt-in needed)
           and the demo's test TSA or its root, when it used one (timestamps then verify as
           trusted).
TXT

echo "Wrote $out:"
ls -l "$out"
