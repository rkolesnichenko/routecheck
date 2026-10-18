#!/bin/sh
# Downloads the opt-in real-data set into .data/realdata (git-ignored; never
# committed — RIPE NCC's terms forbid redistributing RIS files):
#
#   scripts/fetch-data.sh                # everything below
#   scripts/fetch-data.sh --registries   # only the other registries (below)
#   GOMAXPROCS=4 memguard.sh 8 6000 env GOWORK=off GOMAXPROCS=4 GOMEMLIMIT=6GiB \
#     ROUTECHECK_REALDATA=$PWD/.data/realdata go test -count=1 -timeout 100m -run TestRealData -v .
#
# (TestRealData runs alone, under a memory guard with an 8 GB cap: 3m25s and a
# peak RSS of 6,215 MB with every registry, 3m31s and 4,741 MB with
# ROUTECHECK_REALDATA_REGISTRIES=ripe, on 2026-10-18.)
#
# It fetches:
#   - RIPE's split database dumps the policies need: aut-num, as-set,
#     route-set, route, route6, and filter-set, peering-set, inet-rtr and
#     rtr-set (a filter or a peering may name them; without them it would read
#     as a missing set);
#   - the other IRR registries, in the precedence order the real-data run
#     resolves them (first wins): RIPE (above), APNIC (apnic.db.<class>.gz, the
#     same nine classes), ARIN (arin.db.gz), AFRINIC (afrinic.db.gz), LACNIC
#     (lacnic.db.gz), RADB (radb.db.gz), then RADB's mirrors altdb, bboi, bell,
#     canarie, jpirr, nestegg, nttcom, panix, reach, tc (<name>.db.gz). The
#     URLs are those of rpsl's scripts/fetch-irr-dumps.sh. RADB and its mirrors
#     are FTP-only and publish no checksums, so they are fetched
#     unauthenticated and pinned by sha256 on first fetch;
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
#
# --registries adds the registries alone to an existing MANIFEST: every line
# that is not a registry file stays as it is, byte for byte and in order (the
# RIBs and VRPs stay the ones already pinned), and the registry lines follow.
# It needs a MANIFEST, so it refuses to run before the first full run.
# FETCH_DATA_DIR overrides .data/realdata.
set -eu
cd "$(dirname "$0")/.."

mode=all
case $# in
0) ;;
1)
	case $1 in
	--registries) mode=registries ;;
	*) mode= ;;
	esac ;;
*) mode= ;;
esac
if [ -z "$mode" ]; then
	echo "usage: scripts/fetch-data.sh [--registries]" >&2
	exit 2
fi

RIPE=https://ftp.ripe.net/ripe/dbase/split
RV2=https://archive.routeviews.org/bgpdata
RIS=https://data.ris.ripe.net/rrc00
VRPS=https://rpki.gin.ntt.net/api/export.json
# The URLs below are those of rpsl's scripts/fetch-irr-dumps.sh.
APNIC=https://ftp.apnic.net/apnic/whois
RADB=ftp://ftp.radb.net/radb/dbase
mirrors="altdb bboi bell canarie jpirr nestegg nttcom panix reach tc"
out=${FETCH_DATA_DIR:-.data/realdata}

if [ "$mode" = registries ] && [ ! -s "$out/MANIFEST" ]; then
	echo "fetch-data: --registries needs an existing MANIFEST (run scripts/fetch-data.sh first)" >&2
	exit 1
fi
mkdir -p "$out"

# registry_files: "NAME URL" for every registry file, in precedence order after
# RIPE: APNIC, ARIN, AFRINIC, LACNIC, RADB, RADB's mirrors.
registry_files() {
	for c in aut-num as-set route-set route route6 filter-set peering-set inet-rtr rtr-set; do
		echo "apnic.db.$c.gz $APNIC/apnic.db.$c.gz"
	done
	echo "arin.db.gz https://ftp.arin.net/pub/rr/arin.db.gz"
	echo "afrinic.db.gz https://ftp.afrinic.net/pub/dbase/afrinic.db.gz"
	echo "lacnic.db.gz https://ftp.lacnic.net/lacnic/irr/lacnic.db.gz"
	echo "radb.db.gz $RADB/radb.db.gz"
	for m in $mirrors; do
		echo "$m.db.gz $RADB/$m.db.gz"
	done
}

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
if [ "$mode" = registries ]; then
	# Keep every other line exactly as pinned.
	regnames=$(registry_files | cut -d' ' -f1 | tr '\n' ' ')
	awk -v names="$regnames" 'BEGIN { n = split(names, a, " "); for (i = 1; i <= n; i++) s[a[i]] = 1 } !($1 in s)' \
		"$out/MANIFEST" >"$manifest"
fi

# download NAME URL: download URL to $out/NAME unless present (bounded
# retries: five tries for ftp://, whose RADB server often times out, else
# three); fails when every try failed.
download() {
	if [ -s "$out/$1" ]; then
		echo "fetch-data: $1 present, not downloaded"
		return 0
	fi
	max=3
	case $2 in ftp://*) max=5 ;; esac
	tries=0
	until curl -fsS --retry 3 --max-time 3600 -o "$out/$1.part" "$2"; do
		tries=$((tries + 1))
		if [ "$tries" -ge "$max" ]; then
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

# (read from a file, not a pipe: a failure in get must stop the script, not a subshell.)
registry_files >"$tmp/registries"
if [ "$mode" = all ]; then
	for c in aut-num as-set route-set route route6 filter-set peering-set inet-rtr rtr-set; do
		get "ripe.db.$c.gz" "$RIPE/ripe.db.$c.gz"
	done
fi
while read -r name url; do
	get "$name" "$url"
done <"$tmp/registries"

if [ "$mode" = all ]; then
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
fi

mv "$manifest" "$out/MANIFEST"
echo "fetch-data: pinned in $out/MANIFEST"
