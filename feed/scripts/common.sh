# Shared helpers for the feed build scripts (sourced, POSIX sh).
# Environment: PLAT (armv7, ...), optional WORK (scratch dir) and OUT (result dir).
set -eu

FEED=$(cd "$(dirname "$0")/.." && pwd)
. "$FEED/sources.lock"

PLAT=${PLAT:?PLAT is not set}
WORK=${WORK:-/tmp/feed-work}
OUT=${OUT:-$FEED/../out/$PLAT}
JOBS=$(nproc 2>/dev/null || echo 2)

# cross toolchain of the platform (unpacked by toolchain.sh) and the prefix the
# static libraries (zlib, OpenSSL, libcurl) are installed to
TC="$WORK/toolchain-$PLAT"
PREFIX="$WORK/prefix-$PLAT"
eval "OPENSSL_TARGET=\${OPENSSL_TARGET_$PLAT}"
eval "CMAKE_PROCESSOR=\${CMAKE_PROCESSOR_$PLAT}"
if [ -d "$TC/bin" ]; then
    _gcc=$(ls "$TC"/bin/*-linux-*-gcc | head -n 1)
    HOST=$(basename "$_gcc" -gcc)
    CROSS="$TC/bin/$HOST-"
    CC="${CROSS}gcc"
    CXX="${CROSS}g++"
    AR="${CROSS}ar"
    RANLIB="${CROSS}ranlib"
    STRIP="${CROSS}strip"
    export CC CXX AR RANLIB STRIP
    # only the static libraries of the prefix, never the build host's
    export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig"
    export PKG_CONFIG_LIBDIR="$PREFIX/lib/pkgconfig"
fi
# native build (inside a container of the target platform)
CC=${CC:-gcc}
STRIP=${STRIP:-strip}

# every tool is linked statically against musl: it runs on any image of the
# platform, whatever libc / OpenSSL / libcurl the image has
CFLAGS="-Os -ffunction-sections -fdata-sections"
LDFLAGS="-static -Wl,--gc-sections"
export CFLAGS LDFLAGS

mkdir -p "$WORK/dl" "$WORK/src" "$OUT"

log() { printf '\n=== %s\n' "$*"; }

# download <url> <sha256>: into $WORK/dl (cached between runs), checked
download() {
    _f="$WORK/dl/$(basename "$1")"
    [ -f "$_f" ] || curl -fsSL --retry 3 -o "$_f" "$1"
    echo "$2  $_f" | sha256sum -c -
}

# fetch_tar <name> <url> <sha256>: download, check, unpack to $WORK/src/<name>
fetch_tar() {
    download "$2" "$3"
    rm -rf "$WORK/src/$1"
    mkdir -p "$WORK/src/$1"
    tar -xf "$WORK/dl/$(basename "$2")" -C "$WORK/src/$1" --strip-components=1
}

# fetch_git <name> <url> <commit> [mirror url]: check out exactly that commit to
# $WORK/src/<name>; three tries per server (the commit id vouches for any mirror)
fetch_git() {
    for _url in "$2" ${4:-}; do
        for _try in 1 2 3; do
            rm -rf "$WORK/src/$1"
            git init -q "$WORK/src/$1"
            git -C "$WORK/src/$1" remote add origin "$_url"
            # not every server hands out a single commit, then take the whole history
            if { git -C "$WORK/src/$1" fetch -q --depth 1 origin "$3" || git -C "$WORK/src/$1" fetch -q origin; } \
                    && git -C "$WORK/src/$1" checkout -q "$3" \
                    && [ "$(git -C "$WORK/src/$1" rev-parse HEAD)" = "$3" ]; then
                return 0
            fi
            echo "fetch_git: $_url failed (try $_try)"
            sleep 10
        done
    done
    return 1
}

# apply_patches <srcdir> <patchdir>: all *.patch in name order, -p1
apply_patches() {
    for _p in $(ls "$2"/*.patch | sort); do
        echo "patch: $(basename "$_p")"
        patch -d "$1" -p1 --no-backup-if-mismatch < "$_p"
    done
}

# cmake_cross <srcdir> <builddir> [args]: configure a cmake project for the target
cmake_cross() {
    _s=$1 _b=$2
    shift 2
    cmake -S "$_s" -B "$_b" -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR="$CMAKE_PROCESSOR" \
        -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" -DCMAKE_BUILD_TYPE=MinSizeRel \
        -DCMAKE_FIND_ROOT_PATH="$PREFIX" -DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS" "$@"
}

# install_bin <file> [name]: strip and copy to $OUT
install_bin() {
    "$STRIP" -s "$1"
    install -m 0755 "$1" "$OUT/${2:-$(basename "$1")}"
    ls -l "$OUT/${2:-$(basename "$1")}"
}
