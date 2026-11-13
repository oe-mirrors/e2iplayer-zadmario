#!/bin/sh
# Build and test the tools for $PLAT on the build host (cross compiled; the
# tests run the target binaries through qemu-user / binfmt).
# Usage: build-all.sh [step ...]   (default: all tool steps)
set -eu
S="$(cd "$(dirname "$0")" && pwd)"
: "${PLAT:?PLAT is not set}"

# run <script>: on failure the end of its log also goes out as one annotation
# (annotations can be read without logging in, the job log cannot)
run() {
    log="${RUNNER_TEMP:-/tmp}/$1-$PLAT.log"
    if ! sh "$S/$1.sh" > "$log" 2>&1; then
        cat "$log"
        printf '::error title=%s failed::%s\n' "$1" "$(tail -n 40 "$log" | sed 's/%/%25/g' | awk '{printf "%s%%0A", $0}')"
        exit 1
    fi
    cat "$log"
}

[ $# -gt 0 ] || set -- toolchain build-libs build-deps build-duk build-qjs build-wget \
    build-rtmpdump build-uchardet build-curlimp test test-curlimp
for s in "$@"; do
    echo "::group::$s"
    run "$s"
    echo "::endgroup::"
done
