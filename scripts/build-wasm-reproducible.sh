#!/usr/bin/env bash
# Build both WebAssembly modules the way they ship (the verifier, and the signer with the
# `signing` feature) in a clean target directory, and print their SHA-256. Same commit, same
# hashes, on any machine and in any directory (scripts/wasm-env.sh says how); the engine's CI builds
# them on two different runners and fails when the hashes differ.
#
#   scripts/build-wasm-reproducible.sh               build here (needs rustup)
#   scripts/build-wasm-reproducible.sh --container   build in the pinned Linux container
#                                                    (podman or docker): the bytes CI makes,
#                                                    from any operating system
#   scripts/build-wasm-reproducible.sh --check FILE  also compare with a SHA256SUMS file
#
# Output: core/target/wasm-repro/out/{signpdf_verifier.wasm,signpdf_signer.wasm,SHA256SUMS}.
#
# A native build on Windows or macOS gives other bytes than Linux: panic messages keep the
# separators of the host's paths. Rebuild with --container to compare with a published hash.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
cd "$here"

# rust:1.99.1-slim-bookworm by digest: the toolchain of scripts/wasm-toolchain (move both together).
image="docker.io/library/rust@sha256:24707e70a4f1e23d9a7b25202ec43126d28a52294b96aad5c670df1fd1f1d400"

container=false check=""
while [ $# -gt 0 ]; do
  case "$1" in
    --container) container=true ;;
    --check) check=$2; shift ;;
    -h|--help) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
  shift
done

out=core/target/wasm-repro/out
if $container; then
  engine=$(command -v podman || command -v docker || true)
  [ -n "$engine" ] || { echo "--container needs podman or docker" >&2; exit 2; }
  # The tracked files only, as a fresh checkout has them (no target directories, no local
  # builds), copied into the container's own /signpdf.
  ctx=$(mktemp -d)
  trap 'rm -rf "$ctx"' EXIT
  git ls-files -z --cached --others --exclude-standard -- core scripts | tar --null -T - --owner=0 --group=0 -cf "$ctx/src.tar"
  epoch=$(git log -1 --format=%ct)
  mkdir -p "$out"
  "$engine" run --rm -i -e SOURCE_DATE_EPOCH="$epoch" "$image" bash -euo pipefail -c '
    mkdir /signpdf && cd /signpdf && tar --no-same-owner -xf -
    bash scripts/build-wasm-reproducible.sh >&2
    tar -C core/target/wasm-repro/out -cf - .
  ' <"$ctx/src.tar" | tar -C "$out" --no-same-owner -xf -
else
  export CARGO_TARGET_DIR="$here/core/target/wasm-repro/target"
  # shellcheck source=scripts/wasm-env.sh
  . "$here/scripts/wasm-env.sh"
  cd core
  cargo build --locked -p signpdf-wasm --profile wasm --target wasm32-unknown-unknown
  mkdir -p "$here/$out"
  cp "$CARGO_TARGET_DIR/wasm32-unknown-unknown/wasm/signpdf_wasm.wasm" "$here/$out/signpdf_verifier.wasm"
  cargo build --locked -p signpdf-wasm --profile wasm --target wasm32-unknown-unknown --features signing
  cp "$CARGO_TARGET_DIR/wasm32-unknown-unknown/wasm/signpdf_wasm.wasm" "$here/$out/signpdf_signer.wasm"
  cd "$here/$out"
  # Text mode on every system (sha256sum on Windows marks binary files with "*").
  sha256sum signpdf_signer.wasm signpdf_verifier.wasm | sed 's/ \*/  /' >SHA256SUMS
  cd "$here"
fi

echo "Rust $(tr -d ' \r\n' <scripts/wasm-toolchain), SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
cat "$out/SHA256SUMS"
if [ -n "$check" ]; then
  if diff <(sort "$check") <(sort "$out/SHA256SUMS"); then
    echo "Same bytes as $check"
  else
    echo "The modules differ from $check: the build is not reproducible" >&2
    exit 1
  fi
fi
