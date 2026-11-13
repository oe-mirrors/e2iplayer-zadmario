#!/bin/sh
# exteplayer3png.so: the PNG writer plugin exteplayer3 dlopen()s for graphic
# subtitles (PGS / DVB / XSUB) - e2iplayer-deps exteplayer3png/, compiler call of
# enigma2-plugin-extensions-e2iplayer-deps.bb (SOURCE_FILES8). Loads into
# exteplayer3, so it is built natively in a container of the platform with an
# old glibc against libpng16 (soname libpng16.so.16, on every current image).
. "$(dirname "$0")/common.sh"

log "exteplayer3png from e2iplayer-deps $DEPS_REV"
fetch_git deps "$DEPS_GIT" "$DEPS_REV"
(
    cd "$WORK/src/deps/exteplayer3png"
    $CC src/png.c -shared -fPIC -O2 -Wall -Wl,-z,defs -lpng -o exteplayer3png.so
    "$STRIP" --strip-unneeded exteplayer3png.so
    install -m 0644 exteplayer3png.so "$OUT/exteplayer3png.so"
    ls -l "$OUT/exteplayer3png.so"
    echo "needs $(objdump -T exteplayer3png.so | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -n 1)"
    objdump -p exteplayer3png.so | grep NEEDED

    log "test"
    # loaded like exteplayer3 does it (dlopen + SaveRGBAImage), here through ctypes
    T="$WORK/pngtest"
    mkdir -p "$T"
    cp exteplayer3png.so "$T/"
    cd "$T"
    python3 - <<'EOF'
import ctypes, os
from PIL import Image
lib = ctypes.CDLL(os.path.abspath("exteplayer3png.so"))
lib.SaveRGBAImage.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
print("GetVersion: %d" % lib.GetVersion())
px = bytes(bytearray(i * 10 for i in range(3 * 2 * 4)))
assert lib.SaveRGBAImage(b"out.png", px, 3, 2) == 0
assert lib.SaveRGBAImage(b"/nonexistent/dir/x.png", px, 3, 2) == -1
assert lib.SaveRGBAImage(b"bad.png", px, 0, 2) == -1
assert not os.path.exists("bad.png")
im = Image.open("out.png")
assert im.mode == "RGBA" and im.size == (3, 2), (im.mode, im.size)
assert im.tobytes() == px, list(im.tobytes())
print("ok: 3x2 RGBA PNG written and read back")
EOF
)
