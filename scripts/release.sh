#!/bin/sh
# Releases the module at one version, in order:
#
#   scripts/release.sh vX.Y.Z [--yes] [--dry-run] [--no-gh-release]
#
# It refuses to start unless the tree is clean, on main and pushed, and
# CHANGELOG.md has the version dated and linked ("## [X.Y.Z] - YYYY-MM-DD" and
# a "[X.Y.Z]: ..." line; rename "[Unreleased]" when you release). It runs the
# module's own build, vet and tests. Then it prints what it will push and asks:
# the push of the tag is the outward step, so it needs --yes or an interactive
# "yes" typed at the terminal. Then: tag, push the tag, wait for
# proxy.golang.org to serve it (bounded, ending in a SUCCESS or TIMEOUT line),
# verify from an empty module cache that @latest is the version, that the
# published go.mod is the tagged one, and that
# `go install .../cmd/routecheck@vX.Y.Z` builds a binary that prints
# testdata/golden/session.txt byte for byte (with exit status 1: that session
# has Rejected routes, and only the verified-sources note on stderr); build routecheck for five platforms from the published
# module, and create the GitHub release (from the changelog section) with the
# archives and SHA256SUMS attached, using gh.
#
# Adapted from mrt's scripts/release.sh (github.com/rkolesnichenko/mrt).
#
# Each step first checks whether it is done (the tag on the remote, the GitHub
# release), so after a failure the same command resumes where it stopped.
#
# --dry-run prints the steps, with what each would use, and does none of them
# (it reads the tree and changelog to say which precondition would refuse).
#
# The environment changes where it publishes:
#   RELEASE_REMOTE   git remote to push to (origin)
#   RELEASE_PROXY    module proxy to wait on and verify with (https://proxy.golang.org)
#   RELEASE_POLL     seconds between proxy polls (30); RELEASE_WAIT the most to wait (2400)
#   RELEASE_SKIP_CI  1: do not ask GitHub whether CI passed
#   RELEASE_DIST     directory to leave the archives in (a temporary one)
set -eu

usage() {
	echo "usage: scripts/release.sh vX.Y.Z [--yes] [--dry-run] [--no-gh-release]" >&2
	exit 2
}
V=
YES=
DRY=
GH_RELEASE=1
for a in "$@"; do
	case $a in
	--yes) YES=1 ;;
	--dry-run) DRY=1 ;;
	--no-gh-release) GH_RELEASE= ;;
	v[0-9]*.[0-9]*.[0-9]*) V=$a ;;
	*) usage ;;
	esac
done
[ -n "$V" ] || usage
case $V in *[!0-9v.a-zA-Z+-]*) usage ;; esac
X=${V#v} # the version as CHANGELOG.md writes it
M=github.com/rkolesnichenko/routecheck
# The golden the installed binary must print, run from the module's root (it
# prints file names as given), the exit status it must give, and its one
# stderr line (the golden registry holds no verified source).
GOLDEN=testdata/golden/session.txt
GOLDEN_EXIT=1
GOLDEN_ERR='routecheck: route objects: none of the verified sources (RIPE, APNIC, ARIN, AFRINIC, LACNIC) is present; answers are not marked'
golden_run() {
	"$1" -local AS64496 -peer AS64500 -session testdata/session/golden.mrt \
		-dump testdata/irr/golden-policy.txt -vrps testdata/rpki/vrps.json -routes all
}
REMOTE=${RELEASE_REMOTE:-origin}
PROXY=${RELEASE_PROXY:-https://proxy.golang.org}
POLL=${RELEASE_POLL:-30}
WAIT=${RELEASE_WAIT:-2400}
cd "$(dirname "$0")/.."
export GOWORK=off
PLATFORMS="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64"

step() { printf '\n== %s\n' "$*"; }
refuse() {
	echo "release: $*" >&2
	echo "release: nothing was pushed" >&2
	exit 2
}
fail() {
	echo "release: $*" >&2
	echo "release: FAILURE" >&2
	echo "release: fix it and run the same command again: it resumes where it stopped" >&2
	exit 1
}

# remote_tag prints the commit a tag names on the remote, or nothing.
remote_tag() {
	refs=$(git ls-remote --tags "$REMOTE" "refs/tags/$1") || fail "git ls-remote $REMOTE"
	printf '%s\n' "$refs" | cut -f1
}

# problems lists, one per line, what would make the release refuse now,
# reading only the tree and the changelog.
problems() {
	[ "$(git rev-parse --abbrev-ref HEAD)" = main ] || echo "not on main"
	[ -z "$(git status --porcelain)" ] || echo "the tree is not clean"
	grep -Eq "^## \[$X\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$" CHANGELOG.md ||
		echo "CHANGELOG.md has no dated \"## [$X] - YYYY-MM-DD\" section"
	grep -q "^\[$X\]: " CHANGELOG.md || echo "CHANGELOG.md does not link [$X]"
	git remote get-url "$REMOTE" >/dev/null 2>&1 || echo "no git remote named $REMOTE"
}

if [ -n "$DRY" ]; then
	echo "release: dry run for $V: nothing below is done"
	step "preconditions (would refuse on any of these)"
	p=$(problems)
	if [ -n "$p" ]; then echo "$p" | sed 's/^/  would refuse: /'; else echo "  none"; fi
	cat <<PLAN

== the steps
 1. preconditions: on main, clean tree, HEAD == $REMOTE/main, CHANGELOG.md dated and linked for $X,
    CI green on HEAD (gh run list; skipped when RELEASE_SKIP_CI is set)
 2. go build ./... && go vet ./... && go test -count=1 ./...
 3. print the tag $V, the commit $(git rev-parse --short HEAD 2>/dev/null || echo '?') and the remote $REMOTE, and ask
    (--yes or an interactive "yes" is required)
 4. git tag $V; git push $REMOTE $V
 5. wait for $PROXY to serve $M@$V: every ${POLL}s, at most ${WAIT}s;
    prints "proxy: SUCCESS" or "proxy: TIMEOUT"
 6. from an empty module cache (GOMODCACHE in a temporary directory, GOFLAGS=-mod=mod,
    GOPROXY=$PROXY): $M@latest is $V; its go.mod is the tagged go.mod;
    go install $M/cmd/routecheck@$V; the binary, run from the module's root,
    prints $GOLDEN byte for byte and exits $GOLDEN_EXIT
 7. build routecheck from the published module for: $PLATFORMS
    (CGO_ENABLED=0, -trimpath), archive them with LICENSE and a README, write SHA256SUMS,
    check each archive
 8. gh release create $V with the changelog section as notes and the archives attached
    (an existing release only gets the archives; --no-gh-release skips this step)
 9. print "release: SUCCESS"
PLAN
	exit 0
fi

step "preconditions"
p=$(problems)
[ -z "$p" ] || refuse "$(echo "$p" | tr '\n' ';')"
git fetch -q --tags "$REMOTE"
tag_commit=$(remote_tag "$V")
if [ -z "$tag_commit" ]; then
	[ "$(git rev-parse HEAD)" = "$(git rev-parse "$REMOTE/main")" ] ||
		refuse "HEAD is not $REMOTE/main: push first, and let CI run"
	if [ -z "${RELEASE_SKIP_CI:-}" ]; then
		runs=$(gh run list --commit "$(git rev-parse HEAD)" --json status,conclusion \
			--jq '.[] | .status + "/" + .conclusion')
		[ -n "$runs" ] || refuse "no CI run for HEAD"
		echo "$runs" | grep -vqx 'completed/success' && refuse "CI has not passed on HEAD: $(echo $runs)"
	fi
	echo "releasing $V from $(git log -1 --format='%h %s')"
else
	git merge-base --is-ancestor "$tag_commit" HEAD || refuse "tag $V ($tag_commit) is not in HEAD's history"
	echo "resuming $V: the tag is on $REMOTE already ($tag_commit)"
fi

step "1. build, vet, test"
go build ./... && go vet ./... && go test -count=1 ./... >/dev/null ||
	fail "the module does not build, vet or test cleanly (run it by hand to see why)"

step "2. the tag"
if [ -z "$tag_commit" ]; then
	echo "about to push to $REMOTE ($(git remote get-url "$REMOTE")):"
	echo "  tag $V -> $(git log -1 --format='%H %s')"
	echo "  the CHANGELOG section that becomes the release notes:"
	awk -v h="## [$X]" 'index($0, h) == 1 {f = 1; next} /^## \[/ {f = 0} f' CHANGELOG.md | sed -e '/./,$!d' | head -5 | sed 's/^/    /'
	if [ -z "$YES" ]; then
		if [ -t 0 ] || [ -r /dev/tty ]; then
			printf 'push tag %s? type "yes": ' "$V"
			read -r answer </dev/tty || answer=
			[ "$answer" = yes ] || refuse "not confirmed"
		else
			refuse "no terminal to confirm on: pass --yes"
		fi
	fi
	if git rev-parse -q --verify "refs/tags/$V" >/dev/null; then
		[ "$(git rev-parse "$V^{commit}")" = "$(git rev-parse HEAD)" ] ||
			refuse "the local tag $V names $(git rev-parse --short "$V^{commit}"), not HEAD: delete it (git tag -d $V) or check out its commit"
	else
		git tag "$V"
	fi
	git push -q "$REMOTE" "$V"
	echo "pushed $V"
else
	echo "$V is on $REMOTE already"
fi

# ask_proxy asks the proxy for the module query $1, from an empty module cache
# and outside any module, so the answer is the proxy's own.
ask_proxy() {
	d=$(mktemp -d "${TMPDIR:-/tmp}/routecheck-ask.XXXXXX")
	rc=0
	(cd "$d" && GOMODCACHE="$d/modcache" GOPATH="$d/gopath" GOPROXY=$PROXY GOFLAGS=-mod=mod \
		go list -m "$1" >/dev/null 2>&1) || rc=$?
	chmod -R u+w "$d" 2>/dev/null || true
	rm -rf "$d"
	return "$rc"
}

step "3. the proxy"
commit=$(git rev-parse "$V^{commit}")
max=$((WAIT / POLL + 1))
pass=0
served=
while [ "$pass" -lt "$max" ]; do
	pass=$((pass + 1))
	if ask_proxy "$M@$V"; then served=1; break; fi
	[ "$pass" -gt 1 ] || echo "waiting for the proxy to serve $M@$V"
	# Asking by commit makes a proxy that cached a miss (from before the push) fetch the tag again.
	ask_proxy "$M@$commit" || true
	sleep "$POLL"
done
if [ -z "$served" ]; then
	echo "proxy: TIMEOUT"
	fail "$M@$V: the proxy still does not serve it after $pass tries"
fi
echo "proxy: SUCCESS ($M@$V after $pass tries)"

step "4. from an empty module cache"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/routecheck-release.XXXXXX")
trap 'chmod -R u+w "$tmp" 2>/dev/null; rm -rf "$tmp"' EXIT
export GOMODCACHE="$tmp/modcache" GOPATH="$tmp/gopath" GOPROXY="$PROXY" GOFLAGS=-mod=mod
c=$tmp/consumer
mkdir -p "$c"
(
	cd "$c"
	go mod init example.com/consumer >/dev/null 2>&1
	latest=$(go list -m "$M@latest")
	[ "$latest" = "$M $V" ] || fail "$M@latest is $latest, not $V"
	go get "$M@$V" >/dev/null 2>&1 || fail "go get $M@$V"
	echo "$M@latest is $V"
)
dir=$(cd "$c" && go list -m -f '{{.Dir}}' "$M")
# The requirements a consumer gets are the published go.mod's: it must be the
# tagged one (rpsl, rpsl/types, rpsl/resolve and mrt at the versions
# check.sh pins, no replace).
git show "$V:go.mod" >"$tmp/go.mod.tagged" || fail "git show $V:go.mod"
cmp -s "$dir/go.mod" "$tmp/go.mod.tagged" || fail "the published go.mod differs from the one tagged $V"
echo "the published go.mod is the tagged one"
GOBIN=$tmp/bin go install "$M/cmd/routecheck@$V" || fail "go install routecheck@$V"
# check_golden runs a routecheck binary on the golden session from the
# module's root and compares its output and exit status.
check_golden() {
	rc=0
	(cd "$dir" && golden_run "$1") >"$tmp/golden.out" 2>"$tmp/golden.err" || rc=$?
	[ "$rc" -eq "$GOLDEN_EXIT" ] || { cat "$tmp/golden.err" >&2; fail "$2: exit status $rc on the golden session, not $GOLDEN_EXIT"; }
	cmp -s "$tmp/golden.out" "$dir/$GOLDEN" || fail "$2: the output differs from $GOLDEN"
	printf '%s\n' "$GOLDEN_ERR" >"$tmp/golden.err.want"
	cmp -s "$tmp/golden.err" "$tmp/golden.err.want" || { cat "$tmp/golden.err" >&2; fail "$2: wrote to stderr on the golden session other than: $GOLDEN_ERR"; }
}
check_golden "$tmp/bin/routecheck" "the installed routecheck"
echo "routecheck@$V installs and prints $GOLDEN"

step "5. routecheck binaries, built from the published module"
dist=${RELEASE_DIST:-${TMPDIR:-/tmp}/routecheck-release-$V}
mkdir -p "$dist" "$tmp/build"
dist=$(cd "$dist" && pwd)
rm -f "$dist"/routecheck_"${V}"_* "$dist/SHA256SUMS"
command -v zip >/dev/null || fail "zip is needed for the windows archive"
(
	cd "$tmp/build"
	go mod init example.com/routecheck-build >/dev/null 2>&1
	go get "$M@$V" >/dev/null 2>&1 || fail "go get $M@$V"
	license=$dir/LICENSE
	for p in $PLATFORMS; do
		os=${p%/*} arch=${p#*/}
		exe=routecheck
		[ "$os" = windows ] && exe=routecheck.exe
		stage=$tmp/stage-$os-$arch
		mkdir -p "$stage"
		GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$stage/$exe" "$M/cmd/routecheck" ||
			fail "building routecheck for $p"
		cp "$license" "$stage/LICENSE"
		cat >"$stage/README.txt" <<README
routecheck $V ($os/$arch): checks a BGP session's real routes, from MRT
captures or route-collector RIBs, against the IRR's registered import and
export policies. See
https://github.com/rkolesnichenko/routecheck/blob/main/docs/routecheck.md
README
		name=routecheck_${V}_${os}_$arch
		if [ "$os" = windows ]; then
			(cd "$stage" && zip -q -X "$dist/$name.zip" "$exe" LICENSE README.txt)
		else
			tar -czf "$dist/$name.tar.gz" -C "$stage" "$exe" LICENSE README.txt
		fi
		echo "built $name"
	done
)
if command -v sha256sum >/dev/null; then sum="sha256sum"; else sum="shasum -a 256"; fi
(cd "$dist" && $sum routecheck_"${V}"_* >SHA256SUMS)
(cd "$dist" && $sum -c --quiet SHA256SUMS) || fail "SHA256SUMS does not verify"
native=$(go env GOOS)/$(go env GOARCH)
for p in $PLATFORMS; do
	os=${p%/*} arch=${p#*/}
	exe=routecheck a=$dist/routecheck_${V}_${os}_$arch.tar.gz
	[ "$os" = windows ] && exe=routecheck.exe a=$dist/routecheck_${V}_${os}_$arch.zip
	x=$tmp/check-$os-$arch
	mkdir -p "$x"
	if [ "$os" = windows ]; then (cd "$x" && unzip -q "$a"); else tar -xzf "$a" -C "$x"; fi
	[ "$(LC_ALL=C ls "$x" | tr '\n' ' ')" = "LICENSE README.txt $exe " ] || fail "$a holds $(LC_ALL=C ls "$x" | tr '\n' ' ')"
	info=$(go version -m "$x/$exe")
	{ echo "$info" | grep -q "GOOS=$os" && echo "$info" | grep -q "GOARCH=$arch"; } || fail "$a is not built for $p"
	echo "$info" | grep -Eq "(mod|dep)[[:space:]]+$M[[:space:]]+$V[[:space:]]+h1:" ||
		fail "$a is not built from $M $V"
	if [ "$p" = "$native" ]; then
		check_golden "$x/$exe" "$a"
	fi
	echo "checked $(basename "$a"): $p, from $M $V"
done
echo "archives and SHA256SUMS in $dist"

if [ -n "$GH_RELEASE" ]; then
	step "6. the GitHub release, with the binaries"
	assets=$(ls "$dist"/routecheck_"${V}"_* "$dist/SHA256SUMS")
	if gh release view "$V" >/dev/null 2>&1; then
		echo "the GitHub release $V exists: attaching the binaries"
		gh release upload "$V" $assets --clobber
	else
		awk -v h="## [$X]" 'index($0, h) == 1 {f = 1; next} /^## \[/ {f = 0} f' CHANGELOG.md |
			sed -e '/./,$!d' >"$tmp/notes.md"
		[ -s "$tmp/notes.md" ] || fail "no notes for $V in CHANGELOG.md"
		gh release create "$V" --title "$V" --notes-file "$tmp/notes.md" --latest --verify-tag $assets
	fi
fi

step "released $V"
echo "release: SUCCESS"
