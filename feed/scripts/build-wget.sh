#!/bin/sh
# wget 1.25.0 with OpenSSL: oe-core wget_1.25.0.bb (patches 1x/2x) and
# oe-alliance wget_1.%.bbappend (patches 3x), configure options of both recipes
. "$(dirname "$0")/common.sh"

log "wget $WGET_VERSION"
fetch_tar wget "$WGET_URL" "$WGET_SHA256"
apply_patches "$WORK/src/wget" "$FEED/patches/wget"
(
    cd "$WORK/src/wget"
    # the patches touch src/Makefile.am, keep the generated files newer so
    # make does not want to rerun automake
    touch aclocal.m4
    sleep 1
    touch configure
    find . -name Makefile.in -exec touch {} +
    PKG_CONFIG="pkg-config --static" ./configure --host="$HOST" --prefix=/usr --sysconfdir=/etc \
        --with-ssl=openssl --with-zlib --disable-nls --disable-iri --disable-pcre \
        --disable-pcre2 --disable-ntlm --disable-rpath --without-libpsl \
        --without-libuuid --without-metalink
    make -j"$JOBS"
    install_bin src/wget
)
