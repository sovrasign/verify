# Sourced by the WebAssembly build scripts (build-verifier.sh, build-wasm-signer.sh,
# build-wasm-reproducible.sh) with $here set to the repository root. It makes the build
# reproducible: the same source and toolchain give the same bytes on any machine and in any
# directory (docs/RELEASES.md §1):
#
#   - the Rust toolchain pinned in scripts/wasm-toolchain, installed by rustup on first use;
#   - Cargo.lock as committed (--locked, in the scripts' cargo commands);
#   - the build directory, Cargo's home and rustup's home remapped to fixed names in every path
#     the compiler writes (panic locations), so the machine's own paths never reach the module;
#   - SOURCE_DATE_EPOCH set to the commit's time, for anything that would write a date.
#
# The getrandom backend flag of core/.cargo/config.toml is repeated here, because these flags
# replace that file's flags for the target.
wasm_toolchain=$(tr -d ' \r\n' <"$here/scripts/wasm-toolchain")
if ! rustup run "$wasm_toolchain" rustc --version >/dev/null 2>&1; then
  echo "==> installing Rust $wasm_toolchain (scripts/wasm-toolchain) for the WebAssembly build" >&2
  rustup toolchain install "$wasm_toolchain" --profile minimal >&2
fi
rustup target add --toolchain "$wasm_toolchain" wasm32-unknown-unknown >/dev/null 2>&1
export RUSTUP_TOOLCHAIN="$wasm_toolchain"

# Paths as the compiler sees them (on Windows, D:\... rather than /d/...).
native_path() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}
wasm_cargo_home=${CARGO_HOME:-$HOME/.cargo}
wasm_rustup_home=${RUSTUP_HOME:-$HOME/.rustup}
sep=$(printf '\037')
wasm_flags="--cfg${sep}getrandom_backend=\"custom\""
wasm_flags="$wasm_flags$sep--remap-path-prefix=$(native_path "$here")=/signpdf"
wasm_flags="$wasm_flags$sep--remap-path-prefix=$(native_path "$wasm_cargo_home")=/cargo"
wasm_flags="$wasm_flags$sep--remap-path-prefix=$(native_path "$wasm_rustup_home")=/rustup"
if [ -n "${CARGO_TARGET_DIR:-}" ]; then
  wasm_flags="$wasm_flags$sep--remap-path-prefix=$(native_path "$CARGO_TARGET_DIR")=/target"
fi
export CARGO_ENCODED_RUSTFLAGS="$wasm_flags"
unset RUSTFLAGS
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH=$(git -C "$here" log -1 --format=%ct 2>/dev/null || echo 0)
fi
export SOURCE_DATE_EPOCH
