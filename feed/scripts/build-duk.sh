#!/bin/sh
# duk: duktape 2.7.0 + oe-alliance iptvplayer.patch (VER_FOR_IPTV: 6, -t / -m limits),
# built with Makefile.cmdline like the duktape_2%.bbappend
. "$(dirname "$0")/common.sh"

log "duktape $DUKTAPE_VERSION"
fetch_tar duktape "$DUKTAPE_URL" "$DUKTAPE_SHA256"
apply_patches "$WORK/src/duktape" "$FEED/patches/duktape"
(
    cd "$WORK/src/duktape"
    make -f Makefile.cmdline CC="$CC" CCLIBS="-lm $LDFLAGS"
    install_bin duk
)
