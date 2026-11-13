#!/bin/sh
# Loads $OUT/_subparser.so_py$PYVER with the python of this container (python:X.Y
# image of the platform) and parses SRT / TTML (test-subparser.py).
set -eu
FEED=$(cd "$(dirname "$0")/.." && pwd)
OUT=${OUT:-$FEED/../out/${PLAT:?PLAT is not set}}
PYVER=${PYVER:?PYVER is not set}

T=$(mktemp -d)
cp "$OUT/_subparser.so_py$PYVER" "$T/_subparser.so"
cd "$T"
python3 -c 'import sys; v = "%d.%d" % sys.version_info[:2]; assert v == sys.argv[1], (v, sys.argv[1])' "$PYVER"
ldd --version 2>&1 | head -n 1
python3 "$FEED/scripts/test-subparser.py"
