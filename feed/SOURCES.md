# Binary feed: sources

Every file of the feed is built by `.github/workflows/feed-build.yml` from the
sources pinned in [`sources.lock`](sources.lock) (sha256 for tarballs, the commit
for git sources) and the patches in [`patches/`](patches). The templates are the
oe-alliance-core 6.0 recipes, so the tools behave like the OE-A packages; the
difference is static linking against musl, which makes them independent of the
libc, OpenSSL and libcurl of the image.

| File | Source | Recipe used as template | Patches | License |
|---|---|---|---|---|
| `hlsdl` | oe-mirrors/e2iplayer-deps `hlsdl/` + curl (HTTP/HTTPS only), OpenSSL, zlib | oe-alliance `enigma2-plugin-extensions-e2iplayer-deps.bb` (`SOURCE_FILES2`), without `-DWITH_FFMPEG -lav*` (unused by the code) | - | MIT (hlsdl), curl, Apache-2.0 (OpenSSL), Zlib |
| `curl` | curl (HTTP/HTTPS only) + OpenSSL, zlib - the same static libcurl hlsdl uses | oe-core `curl` (feature set reduced to what the plugin needs); CA paths of OE images | - | curl, Apache-2.0 (OpenSSL), Zlib |
| `lsdir` | e2iplayer-deps `lsdir/` | same recipe, `SOURCE_FILES3` | - | GPL-2.0 |
| `cmdwrap` | e2iplayer-deps `cmdwrap/` | same recipe, `SOURCE_FILES4` | - | GPL-2.0 |
| `e2ipow` | e2iplayer-deps `e2ipow/` (proof of work solvers, e.g. Byse) | same recipe, `SOURCE_FILES7` | - | GPL-3.0-or-later |
| `exteplayer3png.so` | e2iplayer-deps `exteplayer3png/` (PNG writer exteplayer3 loads for graphic subtitles) | same recipe, `SOURCE_FILES8`; built in a Debian 11 container of the platform (glibc 2.31) against libpng16 (`libpng16.so.16` of the image) | - | GPL-2.0-or-later |
| `f4mdump` | e2iplayer-deps `f4mdump/` (with librtmp 2.6, TinyXML-2) + OpenSSL, zlib | same recipe, `SOURCE_FILES5` + `SOURCE_FILES6` | - | GPL-2.0, LGPL-2.1 (librtmp), Zlib (TinyXML-2) |
| `_subparser.so_py<X.Y>` | e2iplayer-deps `e2isubparser/` (with Expat) | same recipe, `SOURCE_FILES1`; built per Python version (2.7, 3.10, 3.11, 3.12, 3.13, 3.14, 3.15) in a Debian 11 container of the platform (glibc 2.31): 2.7 against python2.7-dev, 3.x against the headers of the pinned CPython source; each 3.x module is tested in the python:3.x image; libpython not linked | - | GPL-2.0, MIT (Expat), LGPL-2.1 (VLC/FFmpeg parts) |
| `libgstifdsrc.so` | oe-mirrors/iptvplayer-bin-components `gst-ifdsrc/` | oe-alliance `gst-ifdsrc_git.bb` (autotools); built in a Debian 11 container of the platform against GStreamer 1.18 (loads in every newer 1.x) | - | LGPL-2.0 |
| `duk` | duktape 2.7.0 | meta-oe `duktape_2.7.0.bb` + oe-alliance `duktape_2%.bbappend` (`Makefile.cmdline`) | `duktape/iptvplayer.patch` (oe-alliance) | MIT |
| `qjs` | quickjs-ng at the oe-alliance SRCREV | oe-alliance `quickjs_0.16.2.bb` (cmake, `BUILD_SHARED_LIBS=OFF`) | - | MIT |
| `wget` | GNU wget 1.25.0 + OpenSSL, zlib | oe-core `wget_1.25.0.bb` + oe-alliance `wget_1.%.bbappend` (`--with-ssl=openssl`) | `wget/1x`, `2x` (oe-core: reproducibility, CVE fixes), `wget/3x` (oe-alliance: short `--version`, OpenSSL 4) | GPL-3.0-or-later |
| `rtmpdump` | rtmpdump 2.6 (git.ffmpeg.org) + OpenSSL, zlib | meta-multimedia `rtmpdump_2.6.bb` + oe-alliance `rtmpdump_2.%.bbappend`; OpenSSL instead of GnuTLS | `rtmpdump/0001..0003` (oe-alliance: KSV 2015-12-15, OpenSSL fix, movecast) | GPL-2.0, LGPL-2.1 (librtmp) |
| `uchardet` | uchardet 0.0.8 | meta-oe `uchardet_0.0.8.bb` | `uchardet/0001` (meta-oe: cmake 4) | MPL-1.1 / GPL-2.0 / LGPL-2.1 |
| `curl-impersonate` | lexiforest/curl-impersonate release binary (dynamic against glibc; runs on VTi 16 / glibc 2.40, crashes on VTi 15 / glibc 2.21 although it only names glibc 2.17 symbols - images that old get no curl-impersonate) | oe-alliance `curl-impersonate_2.2.3.bb` (same version; stripped + UPX `--lzma` like `upx-compress`) | - | MIT, curl, BoringSSL (ISC/OpenSSL), nghttp2/ngtcp2/nghttp3 (MIT), c-ares (MIT), brotli (MIT), zstd (BSD), Zlib |

## Platforms

| Platform | Build | Test |
|---|---|---|
| `armv7` (hard float) | Bootlin `armv7-eabihf--musl` cross toolchain (gcc 15, musl 1.2.6, Cortex-A9 + VFP), static | qemu-user on the build host; curl-impersonate in Debian 11 armhf |
| `mipsel` (hard float) | Bootlin `mips32el--musl` cross toolchain (gcc 15, musl 1.2.6, MIPS32 + FPU), static tools only - no `_subparser.so`, gst-ifdsrc, exteplayer3png (no build container with the glibc of these images) and no curl-impersonate (no upstream build) | qemu-user on the build host; not tested on a box |

zlib, OpenSSL (3.5 LTS) and libcurl are built from the pinned sources and
linked in statically.

## Checking a file

`SHA256SUMS` and `index.json` next to the binaries list the sha256 of every file;
`index.json` also names the source version and the commit of this repo that
built it.
