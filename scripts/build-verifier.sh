#!/usr/bin/env sh
# Build the browser verifier: compile the Rust core to WebAssembly, place it next to
# web/verifier/index.template.html, then write the page (index.html) and integrity.json with the
# Subresource Integrity hash of every script and module (scripts/sri.mjs, needs Node). Serve that
# directory with any static file server, e.g.
#   python -m http.server -d web/verifier 8080
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
# The pinned toolchain and the flags that make the module reproducible (scripts/wasm-env.sh).
. "$here/scripts/wasm-env.sh"
# Build from inside core/: Cargo reads .cargo/config.toml from the current directory (not the
# manifest's), and that file selects getrandom's custom backend for wasm32. The `wasm` profile
# (core/Cargo.toml) adds LTO and one codegen unit to the release profile.
cd "$here/core"
cargo build --locked -p signpdf-wasm --profile wasm --target wasm32-unknown-unknown
cp "$here/core/target/wasm32-unknown-unknown/wasm/signpdf_wasm.wasm" "$here/web/verifier/"
echo "Built web/verifier/signpdf_wasm.wasm"
cd "$here"
node scripts/sri.mjs web/verifier
