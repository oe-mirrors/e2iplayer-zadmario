#!/bin/sh
# Unpack the cross toolchain of $PLAT to $WORK/toolchain-$PLAT
. "$(dirname "$0")/common.sh"

eval "URL=\${TOOLCHAIN_URL_$PLAT}"
eval "SHA=\${TOOLCHAIN_SHA256_$PLAT}"
log "toolchain $(basename "$URL")"
download "$URL" "$SHA"
rm -rf "$TC"
mkdir -p "$TC"
tar -xf "$WORK/dl/$(basename "$URL")" -C "$TC" --strip-components=1
# Bootlin toolchains are relocatable once this has run
[ ! -x "$TC/relocate-sdk.sh" ] || "$TC/relocate-sdk.sh" > /dev/null
ls "$TC"/bin/*-linux-*-gcc
