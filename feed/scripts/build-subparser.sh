#!/bin/sh
# _subparser.so (Python extension of e2iplayer-deps) for Python $PYVER.
# Runs natively in a container of the target platform with an old glibc
# (images in .github/workflows/feed-build.yml): a Python module cannot be static, it
# needs the libc and the Python ABI of the image. Compiler call as in do_compile()
# of enigma2-plugin-extensions-e2iplayer-deps.bb (SOURCE_FILES1); libpython is not
# linked, its symbols come from the enigma2 process.
# Python 2.7 builds against the container's python2.7-dev and is tested right here;
# Python 3 builds against the headers of the pinned CPython source (the container has
# none of these versions) and is tested by test-subparser.sh in a python:X.Y image.
. "$(dirname "$0")/common.sh"
PYVER=${PYVER:?PYVER is not set}

log "e2isubparser for Python $PYVER"
fetch_git deps "$DEPS_GIT" "$DEPS_REV"

case "$PYVER" in
    2.*)
        # INCLUDEPY: Debian's Python 2 sysconfig paths point to /usr/local
        PYINC="-I$(python$PYVER -c "import sysconfig; print(sysconfig.get_config_var('INCLUDEPY'))")"
        ;;
    *)
        v=$(echo "$PYVER" | tr . _)
        eval "url=\${CPYTHON_URL_$v}; sha=\${CPYTHON_SHA256_$v}"
        fetch_tar cpython "$url" "$sha"
        # configure only writes pyconfig.h for this platform, nothing is built
        (cd "$WORK/src/cpython" && ./configure --quiet --without-ensurepip > /dev/null)
        PYINC="-I$WORK/src/cpython/Include -I$WORK/src/cpython"
        ;;
esac

(
    cd "$WORK/src/deps/e2isubparser"
    EXPAT=src/expat
    [ -d "$EXPAT" ] || EXPAT=src/expat-2.2.0
    EXPAT_RANDOM=""
    [ -f "$EXPAT/random_dev_urandom.c" ] && EXPAT_RANDOM="$EXPAT/random_dev_urandom.c"
    $CC src/subparsermodule.c src/vlc/src/subtitle.c src/ffmpeg/src/htmlsubtitles.c \
        $EXPAT/xmlparse.c $EXPAT/xmlrole.c $EXPAT/xmltok.c $EXPAT/xmltok_impl.c $EXPAT/xmltok_ns.c \
        $EXPAT_RANDOM src/ttml/src/ttmlparser.c src/html/src/htmlcleaner.c \
        -shared -pipe -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE -D_LARGEFILE_SOURCE \
        -D_GNU_SOURCE=1 -DNDEBUG -Os -Wall -Wstrict-prototypes -fPIC \
        -DMAJOR_VERSION=0 -DMINOR_VERSION=2 -DHAVE_EXPAT_CONFIG_H \
        -Isrc -Isrc/vlc/include -Isrc/ffmpeg/include -I$EXPAT -Isrc/ttml/include \
        -Isrc/html/include $PYINC -lm -o _subparser.so -Wl,--gc-sections -Wl,-Bsymbolic
    "$STRIP" -s _subparser.so
    install -m 0644 _subparser.so "$OUT/_subparser.so_py$PYVER"
    ls -l "$OUT/_subparser.so_py$PYVER"
    # needed glibc symbol versions, must stay below the oldest image's glibc
    echo "needs $(objdump -T _subparser.so | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -n 1)"
)

case "$PYVER" in
    2.*)
        log "test"
        mkdir -p "$WORK/subtest"
        cp "$OUT/_subparser.so_py$PYVER" "$WORK/subtest/_subparser.so"
        (cd "$WORK/subtest" && python$PYVER "$FEED/scripts/test-subparser.py")
        ;;
esac
