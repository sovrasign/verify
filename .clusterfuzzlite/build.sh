#!/bin/bash -eu
# Build every cargo-fuzz target of core/fuzz for ClusterFuzzLite (or OSS-Fuzz), with a seed corpus
# for each from the engine's own test documents: the compatibility corpus (documents of every
# envelope schema version, prepared, signed, declined, with timestamps and validation data) and
# the real-world fixtures. The envelope_json target gets the envelopes those documents embed, read
# from the reports beside them.
cd "$SRC/signpdf/core/fuzz"
cargo fuzz build -O

targets=$(tr -d '\r' <Cargo.toml | sed -n 's/^name = "\(.*\)"$/\1/p' | grep -v '^signpdf-fuzz$')
release=target/x86_64-unknown-linux-gnu/release
for t in $targets; do
  cp "$release/$t" "$OUT/"
done

tests="$SRC/signpdf/core/signpdf-core/tests"
seeds=$(mktemp -d)
mkdir -p "$seeds/pdf" "$seeds/json"
# Named by content: the fixture sets reuse the same file names.
find "$tests/corpus" "$tests/fixtures" -name '*.pdf' | while read -r f; do
  cp "$f" "$seeds/pdf/$(sha256sum "$f" | cut -c1-16).pdf"
done
# Each report's "envelope" is the envelope of its PDF (the model's JSON, which every version's
# decoder reads when it is of that version).
python3 - "$tests/corpus" "$seeds/json" <<'PY'
import json, pathlib, sys
src, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
for i, report in enumerate(sorted(src.rglob("*.report.json"))):
    env = json.loads(report.read_text(encoding="utf-8")).get("envelope")
    if env:
        (out / f"{i:04d}.json").write_text(json.dumps(env, separators=(",", ":")), encoding="utf-8")
PY
for t in $targets; do
  case "$t" in
    envelope_json) dir="$seeds/json" ;;
    id_token|timestamp) continue ;;
    *) dir="$seeds/pdf" ;;
  esac
  (cd "$dir" && zip -q -r "$OUT/${t}_seed_corpus.zip" .)
done
