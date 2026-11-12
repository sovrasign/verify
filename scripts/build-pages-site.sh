#!/usr/bin/env bash
# Assemble the browser verifier as a static site, the way the GitHub Pages mirror publishes it
# (.github/workflows/pages.yml; docs/RELEASES.md):
#
#   scripts/build-pages-site.sh OUT                 build the WebAssembly reproducibly, then OUT
#   scripts/build-pages-site.sh OUT --wasm FILE     use an already built verifier module
#
# OUT receives the page (index.html with integrity hashes, verifier-i18n.js, trust-list.js,
# verifier.js, verifier.css, signpdf_wasm.wasm, integrity.json), the format specification and test vectors as a tarball,
# SHA256SUMS over every file, and BUILD.md: the commit, the toolchain, SOURCE_DATE_EPOCH and the
# commands that rebuild the same bytes. Anyone can rebuild the module with
# `scripts/build-wasm-reproducible.sh --container --check SHA256SUMS-wasm` and compare.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
cd "$here"

out="" wasm=""
while [ $# -gt 0 ]; do
  case "$1" in
    --wasm) wasm=$2; shift ;;
    -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option $1" >&2; exit 2 ;;
    *) [ -z "$out" ] || { echo "one OUT directory only" >&2; exit 2; }; out=$1 ;;
  esac
  shift
done
[ -n "$out" ] || { echo "usage: scripts/build-pages-site.sh OUT [--wasm FILE]" >&2; exit 2; }

if [ -z "$wasm" ]; then
  bash scripts/build-wasm-reproducible.sh >&2
  wasm=core/target/wasm-repro/out/signpdf_verifier.wasm
fi
[ -f "$wasm" ] || { echo "no verifier module at $wasm" >&2; exit 2; }

rm -rf "$out"
mkdir -p "$out"
cp web/verifier/index.template.html web/verifier/verifier-i18n.js web/verifier/trust-list.js web/verifier/verifier.js web/verifier/verifier.css "$out/"
# The signed trust list the page follows (spec/envelope-format.md §9.2): with TRUST_LIST_URL set
# (an https address of a publisher's trust.json), trust-list.js pins the keys of
# tools/archive/trust-list-keys.json, the chain the trust-list archive checks lists with. The pins
# are part of the page and of its integrity hashes. Unset: the engine's own trust-list.js, which
# follows no list.
if [ -n "${TRUST_LIST_URL:-}" ]; then
  TRUST_LIST_URL=$TRUST_LIST_URL node -e '
    const fs = require("fs");
    const url = process.env.TRUST_LIST_URL;
    if (!/^https:\/\/[A-Za-z0-9.-]+(:\d+)?\/[\w.~\/-]*$/.test(url) || url.endsWith(".jws")) throw new Error(`TRUST_LIST_URL: not an https address of trust.json: ${url}`);
    const keys = JSON.parse(fs.readFileSync("tools/archive/trust-list-keys.json", "utf8")).keys;
    if (!Array.isArray(keys) || keys.length === 0) throw new Error("TRUST_LIST_URL is set but tools/archive/trust-list-keys.json pins no key");
    for (const k of keys) {
      if (k.kty !== "EC" || k.crv !== "P-256" || "d" in k || !k.x || !k.y) throw new Error("trust-list-keys.json: public P-256 JWKs only");
    }
    const pins = keys.map((k) => ({ kty: k.kty, crv: k.crv, x: k.x, y: k.y, ...(k.kid ? { kid: k.kid } : {}) }));
    const head = fs.readFileSync("web/verifier/trust-list.js", "utf8").split("globalThis.SignpdfTrustList")[0];
    fs.writeFileSync(process.argv[1], `${head}globalThis.SignpdfTrustList = ${JSON.stringify({ url, keys: pins })};` + String.fromCharCode(10));
  ' "$out/trust-list.js"
  echo "trust list: $TRUST_LIST_URL ($(grep -o '"x":' "$out/trust-list.js" | wc -l) pinned key(s))" >&2
fi
cp "$wasm" "$out/signpdf_wasm.wasm"
node scripts/sri.mjs "$out" >/dev/null
rm "$out/index.template.html"

# The specification and the CC0 test vectors, as one tarball with fixed metadata (the same
# bytes from the same commit).
epoch=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
git ls-files -z -- spec LICENSES REUSE.toml core/signpdf-core/tests/corpus core/signpdf-core/tests/attack \
  | sort -z \
  | tar --null -T - --owner=0 --group=0 --numeric-owner --mtime="@$epoch" --format=gnu -cf - \
  | gzip -n >"$out/signpdf-test-vectors.tar.gz"

commit=$(git rev-parse HEAD)
toolchain=$(tr -d ' \r\n' <scripts/wasm-toolchain)
{
  echo "# SignPDF verifier build"
  echo
  echo "- Commit: \`$commit\`"
  echo "- Rust toolchain: $toolchain (wasm32-unknown-unknown, profile \`wasm\`)"
  echo "- SOURCE_DATE_EPOCH: $epoch"
  echo
  echo "## Rebuild the WebAssembly module"
  echo
  echo '```bash'
  echo "git clone https://github.com/sovrasign/verify && cd verify && git checkout $commit"
  echo "scripts/build-wasm-reproducible.sh --container"
  echo "sha256sum core/target/wasm-repro/out/signpdf_verifier.wasm"
  echo '```'
  echo
  echo "The hash must equal the one of \`signpdf_wasm.wasm\` in SHA256SUMS. The page's other files"
  echo "are the repository's own (\`web/verifier/\`), and index.html carries their integrity hashes"
  echo "(\`scripts/sri.mjs\`)."
} >"$out/BUILD.md"

cd "$out"
find . -type f ! -name SHA256SUMS -printf '%P\n' | LC_ALL=C sort | xargs sha256sum | sed 's/ \*/  /' >SHA256SUMS
cat SHA256SUMS
