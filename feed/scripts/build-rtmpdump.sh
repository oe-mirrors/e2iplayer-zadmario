#!/bin/sh
# rtmpdump 2.6 + the three oe-alliance patches (KSV 2015-12-15, OpenSSL fix, movecast).
# meta-multimedia builds it against GnuTLS; the static build uses OpenSSL.
. "$(dirname "$0")/common.sh"

log "rtmpdump $RTMPDUMP_VERSION"
fetch_git rtmpdump "$RTMPDUMP_GIT" "$RTMPDUMP_REV" "$RTMPDUMP_GIT_MIRROR"
apply_patches "$WORK/src/rtmpdump" "$FEED/patches/rtmpdump"
(
    cd "$WORK/src/rtmpdump"
    make -j"$JOBS" CROSS_COMPILE="$CROSS" SYS=posix CRYPTO=OPENSSL SHARED= \
        INC="-I$PREFIX/include" XCFLAGS="$CFLAGS" XLDFLAGS="$LDFLAGS -L$PREFIX/lib" rtmpdump
    install_bin rtmpdump
)
