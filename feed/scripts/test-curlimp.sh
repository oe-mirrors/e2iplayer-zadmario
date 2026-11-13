#!/bin/sh
# curl-impersonate needs glibc: run it in an old Debian of the platform (glibc
# 2.31, older than any current image) through docker + qemu-user.
. "$(dirname "$0")/common.sh"

[ -f "$OUT/curl-impersonate" ] || { echo "no curl-impersonate for $PLAT"; exit 0; }
case "$PLAT" in
    armv7) DOCKER_PLATFORM=linux/arm/v7 ;;
    *) echo "no test image for $PLAT"; exit 1 ;;
esac

docker run --rm --platform "$DOCKER_PLATFORM" -v "$OUT:/out:ro" debian:bullseye-slim sh -euc '
    ldd --version | head -n 1
    /out/curl-impersonate --version | tee /tmp/v
    grep -q IMPERSONATE /tmp/v
    grep -q BoringSSL /tmp/v
    # the profile the plugin tries first (libs/curlimpersonate.py PROFILES)
    /out/curl-impersonate --impersonate chrome150 -k -sS -o /dev/null -w "%{http_code} %{http_version}\n" https://www.example.com/ | tee /tmp/r
    grep -qE "^200 2" /tmp/r
'
