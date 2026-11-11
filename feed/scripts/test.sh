#!/bin/sh
# Runs the built tools of $OUT on the target architecture (qemu-user through
# binfmt on the build host). curl-impersonate is tested by test-curlimp.sh.
. "$(dirname "$0")/common.sh"

T="$WORK/test"
rm -rf "$T"
mkdir -p "$T"
cd "$T"

fail() { echo "::error::$*"; exit 1; }

log "static, right architecture"
for b in "$OUT"/*; do
    n=$(basename "$b")
    case "$n" in curl-impersonate|SHA256SUMS|index.json) continue ;; esac
    readelf -lW "$b" | grep -q 'program interpreter' && fail "$n is not static"
    case "$PLAT" in
        armv7)
            readelf -hW "$b" | grep -q 'Machine:.*ARM' || fail "$n is no ARM binary"
            readelf -AW "$b" | grep -q 'Tag_ABI_VFP_args: VFP registers' || fail "$n is not hard float"
            ;;
        mipsel)
            readelf -hW "$b" | grep -q 'Machine:.*MIPS' || fail "$n is no MIPS binary"
            readelf -hW "$b" | grep -q "little endian" || fail "$n is not little endian"
            readelf -AW "$b" | grep -qi 'FP ABI:.*hard float' || fail "$n is not hard float"
            ;;
    esac
    echo "ok  $n"
done

log "lsdir"
mkdir -p d/sub
echo x > d/a.txt
"$OUT/lsdir" --version | grep -q '^lsdir v' || fail "lsdir --version"
# lsdir writes its list to stderr; arguments as in hosts/hostlocalmedia.py
"$OUT/lsdir" "$T/d" rdl rd 0 100 '*.txt' '*' > /dev/null 2> lsdir.out || true
cat lsdir.out
grep -q '^a.txt//r//' lsdir.out || fail "lsdir does not list a.txt"
grep -q '^sub//d//' lsdir.out || fail "lsdir does not list sub"

log "cmdwrap"
"$OUT/cmdwrap" | grep -q '^Version: 2' || fail "cmdwrap usage"
printf 'echo|||hello|||world' > cmd.txt
test "$("$OUT/cmdwrap" cmd.txt '|||')" = "hello world" || fail "cmdwrap exec"

log "duk"
"$OUT/duk" --help > duk.out 2>&1 || true
grep -q 'VER_FOR_IPTV: 6' duk.out || fail "duk: no VER_FOR_IPTV: 6"
grep -q 'restrict-memory' duk.out || fail "duk: setup detection needs restrict-memory in --help"
echo 'print(String(1 + 2) + [1, 2].join(""));' > t.js
test "$("$OUT/duk" t.js)" = "312" || fail "duk runs no script"
echo 'while (true) {}' > loop.js
start=$(date +%s)
"$OUT/duk" -t 2 loop.js && fail "duk -t did not stop an endless loop"
test $(( $(date +%s) - start )) -lt 30 || fail "duk -t 2 took too long"

log "qjs"
r=$("$OUT/qjs" -e 'print([1, 2, 3].at(-1), Object.groupBy([1, 2, 3], x => x % 2 ? "o" : "e").o.length, 2n ** 64n)')
echo "$r"
test "$r" = "3 2 18446744073709551616" || fail "qjs"

log "uchardet"
printf 'Gr\303\274\303\237e aus K\303\266ln, sch\303\266ne Gr\303\274\303\237e an alle \303\204rzte\n' > u8.txt
r=$("$OUT/uchardet" u8.txt)
echo "$r"
echo "$r" | grep -qi 'utf-8' || fail "uchardet"

log "rtmpdump"
"$OUT/rtmpdump" --help > rtmp.out 2>&1 || true
head -n 3 rtmp.out
grep -q "RTMPDump $RTMPDUMP_VERSION, KSV patch" rtmp.out || fail "rtmpdump --help"

log "wget"
"$OUT/wget" --version > wget.out
head -n 3 wget.out
grep -q '+https' wget.out || fail "wget without https"
grep -q '+ssl/openssl' wget.out || fail "wget not with openssl"
"$OUT/wget" -q -O gnu.html https://ftp.gnu.org/gnu/wget/ || fail "wget https download"
grep -q 'wget-1.25.0.tar.gz' gnu.html || fail "wget downloaded something else"

log "curl"
"$OUT/curl" --version > curl.out
head -n 3 curl.out
grep -q "^curl $CURL_VERSION " curl.out || fail "curl version"
grep -q 'OpenSSL' curl.out || fail "curl not with OpenSSL"
grep -q 'HTTPS' curl.out || fail "curl without HTTPS"
# certificate check with the CA bundle path built in (same as on the images)
"$OUT/curl" -fsS -o curl.html https://ftp.gnu.org/gnu/wget/ || fail "curl https download"
grep -q 'wget-1.25.0.tar.gz' curl.html || fail "curl downloaded something else"

log "e2ipow"
"$OUT/e2ipow" --version | grep -qE '^e2ipow [0-9]' || fail "e2ipow --version"
"$OUT/e2ipow" --list | grep -qx byse || fail "e2ipow --list has no byse"
# expected results as in the e2ipow job of the e2iplayer-deps CI (= scripts/bysepow.py)
for c in 'e2iplayer-ci-0123456789abcdef 8 0 1|{"solution": "59", "hashes": 60}' \
         '3f9c1a7be05d4e21 12 1 2|{"solution": "15201", "hashes": 7601}'; do
    out=$("$OUT/e2ipow" byse ${c%%|*} 120)
    echo "byse ${c%%|*} -> $out"
    test "$out" = "${c#*|}" || fail "e2ipow byse ${c%%|*}: got $out"
done
rc=0; "$OUT/e2ipow" byse abc 64 0 1 1 > pow.out || rc=$?
test $rc -eq 3 || fail "e2ipow time limit: exit code $rc instead of 3"
grep -qF '"solution": null' pow.out || fail "e2ipow time limit output"

log "f4mdump"
"$OUT/f4mdump" 2>&1 | grep -qE '^F4MDump v[0-9]' || fail "f4mdump version"
mkdir -p hds
cat > hds/manifest.f4m <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<manifest xmlns="http://ns.adobe.com/f4m/1.0">
  <baseURL>http://127.0.0.1:8765</baseURL>
  <bootstrapInfo profile="named" id="boot_low">AAAAAA==</bootstrapInfo>
  <bootstrapInfo profile="named" id="boot_high">AAAAAA==</bootstrapInfo>
  <media streamId="high" url="high" bitrate="1500" bootstrapInfoId="boot_high"/>
  <media streamId="low" url="low" bitrate="500" bootstrapInfoId="boot_low"/>
</manifest>
EOF
(cd hds && python3 -m http.server 8765 --bind 127.0.0.1 >/dev/null 2>&1) &
srv=$!
for i in $(seq 1 60); do wget -q -O /dev/null http://127.0.0.1:8765/manifest.f4m && break; sleep 1; done
out=$("$OUT/f4mdump" "wget -q" "http://127.0.0.1:8765/manifest.f4m" 2>&1 || true)
kill $srv 2>/dev/null || true
echo "$out"
echo "$out" | grep -qF '"qualities":[500, 1500]' || fail "f4mdump manifest"

log "hlsdl"
"$OUT/hlsdl" -h > hlsdl.out 2>&1 || true
head -n 3 hlsdl.out
# same stream and checksum as the hlsdl job of e2iplayer-deps (AES-128 TS over HTTPS)
timeout 900 "$OUT/hlsdl" -b -o test.ts "https://devstreaming-cdn.apple.com/videos/streaming/examples/bipbop_4x3/bipbop_4x3_variant.m3u8" > hlsdl.log 2>&1 \
    || { tail -n 20 hlsdl.log; fail "hlsdl download"; }
echo "6bf11a9a4be02443d4790e43e6569a614128bad453c5cb327ec74031f6ea6382  test.ts" | sha256sum -c - || fail "hlsdl output differs"

log "all tests passed"
