#!/bin/sh
# Keeps hosts copied by hand (e.g. hostxxx.py from the python3 fork) over an
# internal update: $1 = installed version, $2 = new version (not installed yet).
# A file is copied only when the new version doesn't ship its own.
# More files: add their paths (relative to IPTVPlayer/) to KEEP_FILES.

# the script keeps itself, so it also survives an update to a version without it
KEEP_FILES="hosts/hostxxx.py libs/xxxparser.py iptvupdate/custom/keep_user_hosts.sh"

for file in $KEEP_FILES; do
	if [ -f "$1/$file" ] && [ ! -f "$2/$file" ]; then
		mkdir -p "$(dirname "$2/$file")"
		if cp -f "$1/$file" "$2/$file"; then
			echo "Kept $file from the installed version."
		else
			echo "Could not keep $file."
		fi
	fi
done

exit 0
