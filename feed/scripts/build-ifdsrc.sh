#!/bin/sh
# libgstifdsrc.so (GStreamer 1.x source element "ifdsrc", ifd:// - gstplayer
# buffering) from oe-mirrors/iptvplayer-bin-components, autotools like
# oe-alliance gst-ifdsrc_git.bb. Runs natively in a container of the target
# platform with an old GStreamer 1.x and glibc (image in feed-build.yml): a
# plugin built against an older 1.x loads in every newer 1.x.
. "$(dirname "$0")/common.sh"

log "gst-ifdsrc $BINCOMP_REV"
fetch_git bincomp "$BINCOMP_GIT" "$BINCOMP_REV"
(
    cd "$WORK/src/bincomp/gst-ifdsrc/gst-ifdsrc"
    # what configure checks, with pkg-config's own reason when it fails
    pkg-config --print-errors --modversion gstreamer-1.0 gstreamer-base-1.0 gstreamer-controller-1.0
    autoreconf --force --install
    # a loadable plugin: none of the -static of the tool builds
    ./configure --disable-static CFLAGS="-Os" LDFLAGS=""
    make -j"$JOBS"
    "$STRIP" -s src/.libs/libgstifdsrc.so
    install -m 0644 src/.libs/libgstifdsrc.so "$OUT/libgstifdsrc.so"
    ls -l "$OUT/libgstifdsrc.so"

    log "test"
    objdump -T src/.libs/libgstifdsrc.so | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -n 1
    mkdir -p "$WORK/ifdtest"
    cp src/.libs/libgstifdsrc.so "$WORK/ifdtest/"
    GST_PLUGIN_PATH="$WORK/ifdtest" gst-inspect-1.0 ifdsrc > "$WORK/ifdtest/inspect.txt" 2>&1 || true
    cat "$WORK/ifdtest/inspect.txt"
    grep -q 'ifd' "$WORK/ifdtest/inspect.txt"
    grep -q 'Supported URI protocols' "$WORK/ifdtest/inspect.txt"
    # read a file through an open descriptor, as gstplayer does with the buffer file
    # (ifdsrc may wait for the file to grow at its end: the timeout stops it then)
    printf 'e2iplayer ifdsrc test data\n' > "$WORK/ifdtest/in.txt"
    GST_PLUGIN_PATH="$WORK/ifdtest" timeout 60 gst-launch-1.0 -q ifdsrc ifd=3 ! filesink sync=false \
        location="$WORK/ifdtest/out.txt" 3< "$WORK/ifdtest/in.txt" || true
    cmp "$WORK/ifdtest/in.txt" "$WORK/ifdtest/out.txt"
    echo "ifdsrc passes the data through"
)
