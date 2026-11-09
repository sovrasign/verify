# The OSS-Fuzz Rust builder: nightly Rust, cargo-fuzz, libFuzzer and the sanitizers.
FROM gcr.io/oss-fuzz-base/base-builder-rust:v1
COPY . $SRC/signpdf
WORKDIR $SRC/signpdf
COPY .clusterfuzzlite/build.sh $SRC/
