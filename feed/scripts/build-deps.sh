#!/bin/sh
# hlsdl, cmdwrap, lsdir, f4mdump, e2ipow from oe-mirrors/e2iplayer-deps.
# Source lists and compiler flags as in do_compile() of oe-alliance-core
# enigma2-plugin-extensions-e2iplayer-deps.bb (SOURCE_FILES2..7), plus -static.
# exteplayer3png.so (SOURCE_FILES8) loads into exteplayer3: build-png.sh.
. "$(dirname "$0")/common.sh"

log "e2iplayer-deps $DEPS_REV"
fetch_git deps "$DEPS_GIT" "$DEPS_REV"
D="$WORK/src/deps"
INC="-I$PREFIX/include"
LIB="-L$PREFIX/lib"

# hlsdl: the recipe's -DWITH_FFMPEG / -lav* are left out, hlsdl uses neither
log "hlsdl"
(
    cd "$D/hlsdl"
    $CC src/main.c src/aes_openssl.c src/curl.c src/hls.c src/misc.c src/msg.c src/mpegts.c \
        -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE -D_LARGEFILE_SOURCE -D_GNU_SOURCE=1 \
        -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations \
        -Wno-deprecated-declarations -Wshadow -Wpointer-arith -Wcast-qual -Wsign-compare \
        -DPREFIX='"/usr"' -DCURL_STATICLIB -std=gnu99 -Isrc $INC $CFLAGS \
        -o hlsdl $LDFLAGS $LIB -lcurl -lssl -lcrypto -lz -lpthread
    install_bin hlsdl
)

log "lsdir"
(
    cd "$D/lsdir"
    $CC src/lsdir.c -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE=1 -D_LARGEFILE_SOURCE \
        -Isrc $CFLAGS -o lsdir $LDFLAGS
    install_bin lsdir
)

log "cmdwrap"
(
    cd "$D/cmdwrap"
    $CC src/cmdwrap.c -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE=1 -D_LARGEFILE_SOURCE \
        -Isrc $CFLAGS -o cmdwrap $LDFLAGS
    install_bin cmdwrap
)

log "e2ipow"
(
    cd "$D/e2ipow"
    $CC src/e2ipow.c -O2 -Wall $CFLAGS -o e2ipow $LDFLAGS
    install_bin e2ipow
)

log "f4mdump"
(
    cd "$D/f4mdump"
    $CC ext/librtmp/amf.c ext/librtmp/hashswf.c ext/librtmp/log.c ext/librtmp/parseurl.c \
        ext/librtmp/rtmp.c -c -fdata-sections -ffunction-sections -Os \
        -Wno-incompatible-pointer-types -Iext/librtmp $INC
    $CXX src/b64.c src/F4mDownloader.cpp src/F4mProcessor.cpp src/ManifestParser.cpp \
        src/RTMPTypes.cpp src/RTMPWrapper.cpp src/SimpleFunctions.cpp src/StreamReader.cpp \
        src/StringHelper.cpp src/UdsDownloader.cpp src/console.cpp src/main.cpp \
        src/parser.cpp src/tinyxml2.cpp \
        -Os -Wno-narrowing -std=c++0x -Iinc -Iext -Iext/librtmp $INC *.o \
        -o f4mdump $LDFLAGS $LIB -lssl -lcrypto -lz
    install_bin f4mdump
)
