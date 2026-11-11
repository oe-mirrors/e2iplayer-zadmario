#!/bin/sh
# curl-impersonate: the upstream release binary for the platform, checked against
# its sha256, stripped and packed with UPX --lzma (as oe-alliance does with
# upx-compress). Runs on the build host, STRIP may name a cross strip.
. "$(dirname "$0")/common.sh"

eval "URL=\${CURLIMP_URL_$PLAT:-}"
eval "SHA=\${CURLIMP_SHA256_$PLAT:-}"
if [ -z "$URL" ]; then
    echo "no curl-impersonate for $PLAT"
    exit 0
fi

log "curl-impersonate $CURLIMP_VERSION"
F="$WORK/dl/$(basename "$URL")"
[ -f "$F" ] || curl -fsSL --retry 3 -o "$F" "$URL"
echo "$SHA  $F" | sha256sum -c -
rm -rf "$WORK/src/curlimp"
mkdir -p "$WORK/src/curlimp"
tar -xf "$F" -C "$WORK/src/curlimp"
BIN=$(find "$WORK/src/curlimp" -type f -name curl-impersonate | head -n 1)
test -n "$BIN"
${STRIP:-strip} -s "$BIN"
upx -q --best --lzma "$BIN"
install -m 0755 "$BIN" "$OUT/curl-impersonate"
ls -l "$OUT/curl-impersonate"
