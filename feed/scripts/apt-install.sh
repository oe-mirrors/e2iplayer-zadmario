#!/bin/sh
# apt-get install <packages> in a Debian / Ubuntu build container; output only
# on failure, then also as an annotation (readable without logging in).
set -eu
export DEBIAN_FRONTEND=noninteractive

quiet() {
    "$@" > /tmp/apt.log 2>&1 && return 0
    cat /tmp/apt.log
    printf '::error title=apt failed::%s\n' "$(tail -n 15 /tmp/apt.log | awk '{printf "%s%%0A", $0}')"
    return 1
}

# Debian 11 is past its LTS: deb.debian.org still lists it but drops the files,
# archive.debian.org has all of it (with expired Release files)
if grep -q '^11' /etc/debian_version 2>/dev/null && ! grep -qi ubuntu /etc/os-release; then
    for f in /etc/apt/sources.list /etc/apt/sources.list.d/*; do
        if [ -f "$f" ]; then sed -i -e 's#deb.debian.org#archive.debian.org#' "$f"; fi
    done
    quiet apt-get -q -o Acquire::Check-Valid-Until=false update
else
    quiet apt-get -q update
fi
quiet apt-get -qy install --no-install-recommends "$@"
