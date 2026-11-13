#!/bin/sh
# Pages site from the feed artifacts: site/resources/bin/<platform>/ (binaries,
# SHA256SUMS, index.json), site/resources/index.json, site/index.html, SOURCES.md.
# Usage: site.sh [dist dir] [site dir] [ref] [commit]  (defaults: dist, site, the
# GitHub Actions ref and commit)
set -eu
DIST=${1:-dist}
SITE=${2:-site}
REF=${3:-${GITHUB_REF_NAME:-local}}
SHA=${4:-${GITHUB_SHA:-0000000000}}
FEED=$(cd "$(dirname "$0")/.." && pwd)

ls -lR "$DIST"
mkdir -p "$SITE/resources/bin"
# one folder per platform, named by its index.json (download-artifact puts a single
# artifact straight into $DIST, several into $DIST/<artifact name>/)
n=0
for idx in $(find "$DIST" -name index.json); do
    d=$(dirname "$idx")
    plat=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["platform"])' "$idx")
    mkdir -p "$SITE/resources/bin/$plat"
    cp "$d"/* "$SITE/resources/bin/$plat/"
    (cd "$SITE/resources/bin/$plat" && sha256sum -c SHA256SUMS)
    n=$((n + 1))
done
test "$n" -gt 0
cp "$FEED/SOURCES.md" "$SITE/"
touch "$SITE/.nojekyll"

python3 - "$SITE" "$REF" "$SHA" <<'EOF'
import html, json, os, sys
site, ref, sha = sys.argv[1:4]
base = os.path.join(site, 'resources', 'bin')
index = {'ref': ref, 'commit': sha, 'platforms': {}}
rows = []
for plat in sorted(os.listdir(base)):
    info = json.load(open(os.path.join(base, plat, 'index.json')))
    index['platforms'][plat] = info
    for name, f in sorted(info['files'].items()):
        rows.append('<tr><td>%s</td><td><a href="resources/bin/%s/%s">%s</a></td><td>%s</td><td>%d</td><td><code>%s</code></td></tr>'
                    % (plat, plat, html.escape(name), html.escape(name), html.escape(f['version']), f['size'], f['sha256']))
json.dump(index, open(os.path.join(site, 'resources', 'index.json'), 'w'), indent=1, sort_keys=True)
with open(os.path.join(site, 'index.html'), 'w') as out:
    out.write('<!doctype html><meta charset="utf-8"><title>E2iPlayer binary feed</title>'
              '<h1>E2iPlayer binary feed</h1><p>%s (%s) - built from <a href="SOURCES.md">these sources</a>; '
              'checksums in resources/bin/&lt;platform&gt;/SHA256SUMS</p>'
              '<table><tr><th>platform</th><th>file</th><th>version</th><th>bytes</th><th>sha256</th></tr>%s</table>\n'
              % (html.escape(ref), sha[:8], ''.join(rows)))
EOF
find "$SITE" -type f | sort
