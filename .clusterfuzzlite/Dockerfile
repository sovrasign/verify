# The OSS-Fuzz Rust builder: nightly Rust, cargo-fuzz, libFuzzer and the sanitizers. Pinned by
# digest so a fuzzing run builds on exactly this image; Dependabot proposes a new digest when the
# tag moves (.github/dependabot.yml).
FROM gcr.io/oss-fuzz-base/base-builder-rust:v1@sha256:3428d0a90b1e7efbe2ba947bd1d0c9a70594986b4b6553804547f1fb24cfc92f
COPY . $SRC/signpdf
WORKDIR $SRC/signpdf
COPY .clusterfuzzlite/build.sh $SRC/
