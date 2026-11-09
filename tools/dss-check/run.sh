#!/usr/bin/env bash
# Validate the compatibility corpus (core/signpdf-core/tests/corpus) with EU DSS and compare the
# results with core/signpdf-core/tests/corpus/dss.json. Builds and runs
# tools/dss-check in a pinned Maven container with podman or docker; Maven's downloads are kept in
# the volume signpdf-dss-m2, so later runs need no network for them.
#
#   tools/dss-check/run.sh            check (exit 1 on a broken signature or another result)
#   tools/dss-check/run.sh --update   record this run's results in dss.json (a new corpus file,
#                                     a new DSS version: say why in the pull request)
#
# The scheduled nightly job of the hosted service runs this at the engine commit it ships, and a
# failure blocks its release train.
set -euo pipefail
here=$(cd "$(dirname "$0")/../.." && pwd)
cd "$here"

# maven:3.9-eclipse-temurin-21, by digest.
image="docker.io/library/maven@sha256:80034909d9a9f0b89d3d2c583f07f3b7650309bc4e6b886ad5b860b9e1bfa439"
engine=$(command -v podman || command -v docker || true)
[ -n "$engine" ] || { echo "tools/dss-check/run.sh needs podman or docker" >&2; exit 2; }
update=""
[ "${1:-}" = "--update" ] && update="--update"

corpus=core/signpdf-core/tests/corpus
expected=$corpus/dss.json
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

# The tool and the corpus go in on stdin (no bind mounts: the same on Linux, macOS and Windows);
# the results come back on stdout as a tar of dss.json and the log.
files=$( { git ls-files -- tools/dss-check "$corpus"; git ls-files --others --exclude-standard -- tools/dss-check "$corpus"; } | sort -u)
[ -f "$expected" ] && files=$(printf '%s\n%s\n' "$files" "$expected" | sort -u)
printf '%s\n' $files | tar -T - --owner=0 --group=0 -cf - |
  "$engine" run --rm -i -v signpdf-dss-m2:/root/.m2 "$image" bash -euo pipefail -c '
    mkdir /work && cd /work && tar --no-same-owner -xf -
    cd tools/dss-check
    mvn -B -q -DskipTests package >&2
    set +e
    dss=$(ls target/lib | sed -n "s/^dss-validation-\(.*\)\.jar\$/\1/p")
    java -Ddss.version="$dss" -cp "target/dss-check.jar:target/lib/*" org.signpdf.dsscheck.DssCheck \
      /work/'"$corpus"' /work/'"$expected"' '"$update"' >/work/dss.log 2>&1
    echo $? >/work/dss.exit
    set -e
    cp /work/'"$expected"' /work/dss.json 2>/dev/null || true
    [ -f /work/'"$expected"'.actual ] && cp /work/'"$expected"'.actual /work/dss.actual.json
    tar -C /work -cf - dss.log dss.exit $(cd /work && ls dss.json dss.actual.json 2>/dev/null)
  ' | tar -C "$out" --no-same-owner -xf -

cat "$out/dss.log"
if [ -n "$update" ]; then
  cp "$out/dss.json" "$expected"
elif [ -f "$out/dss.actual.json" ]; then
  cp "$out/dss.actual.json" "$expected.actual"
  diff "$expected" "$expected.actual" || true
fi
exit "$(cat "$out/dss.exit")"
