#!/bin/sh
# Static zlib, OpenSSL and libcurl into $PREFIX
. "$(dirname "$0")/common.sh"

log "zlib $ZLIB_VERSION"
fetch_tar zlib "$ZLIB_URL" "$ZLIB_SHA256"
(
    cd "$WORK/src/zlib"
    CHOST="$HOST" ./configure --static --prefix="$PREFIX"
    make -j"$JOBS"
    make install
)

# OPENSSLDIR /etc/ssl: the default CA directory is then /etc/ssl/certs like on the images
log "OpenSSL $OPENSSL_VERSION"
fetch_tar openssl "$OPENSSL_URL" "$OPENSSL_SHA256"
(
    cd "$WORK/src/openssl"
    ./Configure "$OPENSSL_TARGET" no-shared no-tests no-docs no-module \
        --prefix="$PREFIX" --libdir=lib --openssldir=/etc/ssl -Os
    make -j"$JOBS" build_libs
    make install_dev
)

# libcurl for hlsdl and the curl tool: HTTP/HTTPS, OpenSSL, zlib. hlsdl switches
# peer verification off; the CA paths are the ones of OE images
log "libcurl $CURL_VERSION"
fetch_tar curl "$CURL_URL" "$CURL_SHA256"
(
    cd "$WORK/src/curl"
    ./configure --host="$HOST" --prefix="$PREFIX" --disable-shared --enable-static \
        --with-openssl="$PREFIX" --with-zlib="$PREFIX" --without-libpsl --without-libidn2 \
        --without-nghttp2 --without-brotli --without-zstd --without-libssh2 \
        --disable-ldap --disable-ldaps --disable-rtsp --disable-dict --disable-telnet \
        --disable-tftp --disable-pop3 --disable-imap --disable-smtp --disable-gopher \
        --disable-mqtt --disable-smb --disable-manual --disable-docs \
        --with-ca-bundle=/etc/ssl/certs/ca-certificates.crt --with-ca-path=/etc/ssl/certs
    make -j"$JOBS" -C lib
    make -C lib install
    make -C include install
    # the curl command line tool on the same libcurl: a fallback for images without curl
    # (libtool reads -static as "its own libraries static"; fully static is -all-static)
    LDF=$(sed -n 's/^LDFLAGS = //p' src/Makefile)
    make -j"$JOBS" -C src LDFLAGS="$LDF -all-static"
    install_bin src/curl
)
