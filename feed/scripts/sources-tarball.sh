#!/bin/sh
# sources-<name>.tar.xz: every source the feed is built from (the pinned tarballs,
# the git sources at their commit) plus feed/ itself (scripts, patches, lock files).
# This is the source offer of a release: it stays even when an upstream vanishes.
# Usage: sources-tarball.sh [name] [output dir]  (defaults: the GitHub Actions ref, release)
PLAT=${PLAT:-armv7}
. "$(dirname "$0")/common.sh"

NAME=${1:-${GITHUB_REF_NAME:?name}}
DEST=${2:-release}
S="$WORK/sources-$NAME"
rm -rf "$S"
mkdir -p "$S" "$DEST"

for v in ZLIB OPENSSL CURL DUKTAPE WGET UCHARDET; do
    eval "url=\${${v}_URL}; sha=\${${v}_SHA256}"
    download "$url" "$sha"
    cp "$WORK/dl/$(basename "$url")" "$S/"
done
# curl-impersonate is shipped as the upstream release binary: its source is the
# lexiforest/curl-impersonate tag named in sources.lock (MIT / BSD-style licenses)
for v in DEPS QUICKJS RTMPDUMP BINCOMP; do
    eval "git=\${${v}_GIT}; rev=\${${v}_REV}; mirror=\${${v}_GIT_MIRROR:-}"
    name=$(basename "$git" .git)
    fetch_git "src-$name" "$git" "$rev" "$mirror"
    git -C "$WORK/src/src-$name" archive --format=tar --prefix="$name-$rev/" "$rev" | xz -9 > "$S/$name-$rev.tar.xz"
done
tar -C "$FEED/.." -cf - feed | xz -9 > "$S/feed.tar.xz"
(cd "$S" && sha256sum * > SHA256SUMS)
tar -C "$WORK" -cf - "sources-$NAME" | xz -0 > "$DEST/sources-$NAME.tar.xz"
ls -l "$DEST/sources-$NAME.tar.xz"
