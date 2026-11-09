# Build the browser verifier (Windows): compile the Rust core to WebAssembly, place it next to
# web/verifier/index.template.html, then write the page (index.html) and integrity.json with the
# Subresource Integrity hash of every script and module (scripts/sri.mjs, needs Node). Serve that
# directory with any static file server.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
rustup target add wasm32-unknown-unknown | Out-Null
# Build from inside core/: Cargo reads .cargo/config.toml from the current directory (not the
# manifest's), and that file selects getrandom's custom backend for wasm32. The `wasm` profile
# (core/Cargo.toml) adds LTO and one codegen unit to the release profile.
Push-Location "$root/core"
try {
    cargo build -p signpdf-wasm --profile wasm --target wasm32-unknown-unknown
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
} finally {
    Pop-Location
}
Copy-Item "$root/core/target/wasm32-unknown-unknown/wasm/signpdf_wasm.wasm" "$root/web/verifier/"
Write-Host "Built web/verifier/signpdf_wasm.wasm"
node "$root/scripts/sri.mjs" "$root/web/verifier"
if ($LASTEXITCODE -ne 0) { throw "scripts/sri.mjs failed" }
