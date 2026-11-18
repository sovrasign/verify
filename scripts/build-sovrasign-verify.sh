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
node "$here/scripts/sri.mjs" "$out" >/dev/null
rm "$out/index.template.html"
echo "Built $out: serve it with any static file server, e.g. python3 -m http.server -d $out 8080"
