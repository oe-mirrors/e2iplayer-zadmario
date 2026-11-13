#!/bin/sh
# uchardet 0.0.8 + the meta-oe cmake 4 patch, command line tool only
. "$(dirname "$0")/common.sh"

log "uchardet $UCHARDET_VERSION"
fetch_tar uchardet "$UCHARDET_URL" "$UCHARDET_SHA256"
apply_patches "$WORK/src/uchardet" "$FEED/patches/uchardet"
(
    cd "$WORK/src/uchardet"
    cmake_cross . build -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC=ON -DBUILD_BINARY=ON
    cmake --build build -j"$JOBS"
    install_bin build/src/tools/uchardet
)
