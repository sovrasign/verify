#!/usr/bin/env sh
# Build Sovrasign Verify: the page in sovrasign-verify/ next to the engine's verifier module, with
# the Subresource Integrity hash of every script, stylesheet and module written into its
# index.html (scripts/sri.mjs), in a folder you can serve as is with any static file server.
#
#   sh scripts/build-sovrasign-verify.sh [out-dir]       (default: dist/sovrasign-verify)
#
# The module: $WASM when set (for example the reproducible build's
# core/target/wasm-repro/out/signpdf_verifier.wasm), else the one scripts/build-verifier.sh builds
# (built first when it is missing). Needs Node.js for the hashes, and Rust when the module is built.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-"$here/dist/sovrasign-verify"}
wasm=${WASM:-"$here/web/verifier/signpdf_wasm.wasm"}
if [ ! -f "$wasm" ]; then
  [ -z "${WASM:-}" ] || { echo "WASM=$WASM does not exist" >&2; exit 1; }
  sh "$here/scripts/build-verifier.sh"
fi
rm -rf "$out"
mkdir -p "$out"
cp "$here"/sovrasign-verify/*.js "$here"/sovrasign-verify/*.css "$here/sovrasign-verify/index.template.html" "$out/"
cp "$wasm" "$out/signpdf_wasm.wasm"
# The page's ten languages: each catalog sovrasign-verify/l10n/verify_<lang>.arb becomes a module of
# the folder, l10n-<lang>.js, so sri.mjs lists it with the others (as the service's build does).
node - "$here/sovrasign-verify/l10n" "$out" <<'EOF_L10N'
const fs = require("fs"), path = require("path");
const [dir, out] = process.argv.slice(-2);
for (const f of fs.readdirSync(dir)) {
  const m = /^verify_([a-z]{2})\.arb$/.exec(f);
  if (!m) continue;
  const arb = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"));
  const cat = Object.fromEntries(Object.entries(arb).filter(([k]) => !k.startsWith("@")));
  fs.writeFileSync(path.join(out, `l10n-${m[1]}.js`), `export default ${JSON.stringify(cat)};
`);
}
EOF_L10N
node "$here/scripts/sri.mjs" "$out" >/dev/null
rm "$out/index.template.html"
echo "Built $out: serve it with any static file server, e.g. python3 -m http.server -d $out 8080"
