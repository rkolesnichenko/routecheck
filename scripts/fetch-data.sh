#!/bin/sh
# Downloads the opt-in real-data set into .data/realdata (git-ignored; never
# committed — RIPE NCC's terms forbid redistributing RIS files):
#
#   scripts/fetch-data.sh
#   GOMAXPROCS=4 memguard.sh 8 6000 env GOWORK=off GOMAXPROCS=4 GOMEMLIMIT=6GiB \
#     ROUTECHECK_REALDATA=$PWD/.data/realdata go test -count=1 -timeout 100m -run TestRealData -v .
#
# (TestRealData runs alone, under a memory guard with an 8 GB cap: about 15
# minutes and 2.6 GB.)
#
# It fetches:
#   - RIPE's split database dumps the policies need: aut-num, as-set,
#     route-set, route, route6, and filter-set, peering-set, inet-rtr and
#     rtr-set (a filter or a peering may name them; without them it would read
#     as a missing set);
#   - the newest route-views2 RIB (bzip2) and the newest RIS rrc00 bview
#     (gzip), found by listing the archive's month directory;
#   - NTT's VRP export (the JSON IRRd reads by default), for the RPKI states.
#     When it cannot be fetched the run goes on without it (RPKI skipped),
#     and the script says so.
#
# Each file is pinned in .data/realdata/MANIFEST (one line per file: local
# name, URL, size in bytes, sha256), which TestRealData reads. A file already
# present is not downloaded again; a new run pins the newest RIBs beside the
# old ones and rewrites MANIFEST to the new set.
set -eu
cd "$(dirname "$0")/.."

RIPE=https://ftp.ripe.net/ripe/dbase/split
RV2=https://archive.routeviews.org/bgpdata
RIS=https://data.ris.ripe.net/rrc00
VRPS=https://rpki.gin.ntt.net/api/export.json
out=.data/realdata
mkdir -p "$out"

if command -v shasum >/dev/null; then
	sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
elif command -v sha256sum >/dev/null; then
	sha256() { sha256sum "$1" | cut -d' ' -f1; }
else
	echo "fetch-data: neither shasum nor sha256sum is installed" >&2
	exit 1
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/fetch-data.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
trap 'exit 130' INT TERM

# This month and the one before (the first hours of a month may have nothing yet).
this=$(date -u +%Y.%m)
prev=$(echo "$this" | awk -F. '{ y = $1; m = $2 - 1; if (m == 0) { y--; m = 12 } printf "%04d.%02d\n", y, m }')

# names URL REGEXP: the file names in the directory listing at URL matching
# REGEXP, sorted; nothing when the directory does not exist.
names() {
	curl -fsS --retry 3 --max-time 120 "$1/" 2>/dev/null | grep -o "$2" | sort -u || true
}

# newest DIR-PATTERN REGEXP: "MONTH NAME" of the newest matching file in this
# month's directory, else last month's. DIR-PATTERN has @ where the month goes.
newest() {
	for month in "$this" "$prev"; do
		n=$(names "$(echo "$1" | sed "s|@|$month|")" "$2" | tail -1)
		if [ -n "$n" ]; then
			echo "$month $n"
			return
		fi
	done
	echo "fetch-data: nothing matching $2 under $1 for $this or $prev" >&2
	exit 1
}

manifest=$tmp/MANIFEST
: >"$manifest"

# download NAME URL: download URL to $out/NAME unless present (bounded
# retries); fails when every try failed.
download() {
	if [ -s "$out/$1" ]; then
		echo "fetch-data: $1 present, not downloaded"
		return 0
	fi
	tries=0
	until curl -fsS --retry 3 --max-time 3600 -o "$out/$1.part" "$2"; do
		tries=$((tries + 1))
		if [ "$tries" -ge 3 ]; then
			rm -f "$out/$1.part"
			echo "fetch-data: $2: failed after $tries attempts" >&2
			return 1
		fi
		sleep 10
	done
	mv "$out/$1.part" "$out/$1"
}

# pin NAME URL: record the file in the manifest.
pin() {
	size=$(wc -c <"$out/$1" | tr -d ' ')
	sum=$(sha256 "$out/$1")
	printf '%s %s %s %s\n' "$1" "$2" "$size" "$sum" >>"$manifest"
	printf '%-32s %12s bytes  %s\n' "$1" "$size" "$2"
}

# get NAME URL: download, then pin; a failure stops the script.
get() {
	download "$1" "$2" || exit 1
	pin "$1" "$2"
}

for c in aut-num as-set route-set route route6 filter-set peering-set inet-rtr rtr-set; do
	get "ripe.db.$c.gz" "$RIPE/ripe.db.$c.gz"
done

# (newest runs in an assignment so that its failure stops the script.)
found=$(newest "$RV2/@/RIBS" 'rib\.[0-9]*\.[0-9]*\.bz2')
set -- $found
get "rv2-$2" "$RV2/$1/RIBS/$2"
found=$(newest "$RIS/@" 'bview\.[0-9]*\.[0-9]*\.gz')
set -- $found
get "rrc00-$2" "$RIS/$1/$2"

# The VRPs are optional: NTT's export carries no date in its name, so it is
# pinned under the day it was fetched.
vrps="vrps-ntt.$(date -u +%Y%m%d).json"
if download "$vrps" "$VRPS"; then
	pin "$vrps" "$VRPS"
else
	echo "fetch-data: no VRPs (NTT's export could not be fetched): RPKI is skipped" >&2
fi

mv "$manifest" "$out/MANIFEST"
echo "fetch-data: pinned in $out/MANIFEST"
