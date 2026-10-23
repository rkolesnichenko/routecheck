#!/bin/sh
# Full verification — what CI runs, and what to run before a commit:
#
#   scripts/check.sh                 # gofmt, build, vet, race tests, coverage,
#                                    # api surface, invariants
#   FUZZTIME=15s scripts/check.sh    # ... plus every fuzz target for 15s each
#                                    # (scripts/fuzz.sh, which CI runs as its own job)
#
# staticcheck and govulncheck run when installed (CI installs them).
# The differential tests against bgpq4 run when it is installed;
# ROUTECHECK_ORACLES_REQUIRED=1 makes a missing one a failure (CI sets it).
set -u
cd "$(dirname "$0")/.."
fail=0
step() { printf '\n== %s\n' "$*"; }
bad() { echo "FAIL: $*"; fail=1; }

# gofiles lists the Go files the next commit would hold — tracked or new, not
# ignored — so tool state and .data/ are never scanned.
gofiles() {
	git ls-files -z --cached --others --exclude-standard '*.go' |
		xargs -0 sh -c 'for f; do [ -f "$f" ] && printf "%s\0" "$f"; done' _
}

step gofmt
unformatted=$(gofiles | xargs -0 gofmt -l)
[ -z "$unformatted" ] || bad "not gofmt-clean: $unformatted"

step "build, vet, test -race"
(go build ./... && go vet ./... && go test -race -count=1 ./...) || bad "build, vet or test"

# Coverage is reported, not enforced. It runs without -race, which slows the
# hot loops of the tests about fourfold.
step "coverage"
out=$(go test -count=1 -cover ./... 2>&1) || { printf '%s\n' "$out"; bad "coverage"; out=; }
printf '%s\n' "$out" | grep 'coverage:'

step "no public package imports net"
# Only internal/cli and cmd/routecheck may open sockets. go list's status is
# checked on its own: through a pipe only grep's would count.
if deps=$(go list -deps . ./pathre ./verdict ./observe ./hygiene); then
	if printf '%s\n' "$deps" | grep -qx net; then
		bad "a library package imports net"
	fi
else
	bad "go list"
fi

step "no home-directory path in a committed file"
# Tracked files and new ones not yet added (--untracked); ignored files, such
# as .data/ and .superpowers/, are not searched. In the pattern a slash is
# followed by a group, (Users|home), so the pattern's own text never matches.
git grep -n -I --untracked -E '/(Users|home)/'
case $? in
0) bad "a file holds a home-directory path" ;;
1) ;;
*) bad "git grep" ;;
esac

step "go.mod requires rpsl, rpsl/types, rpsl/resolve and mrt, and nothing else of ours"
# Until a package imports them the four stay "// indirect", so this does not
# run go mod tidy and does not demand the marker be absent.
for req in \
	"github.com/rkolesnichenko/rpsl v0.30.1" \
	"github.com/rkolesnichenko/rpsl/types v0.30.1" \
	"github.com/rkolesnichenko/rpsl/resolve v0.30.1" \
	"github.com/rkolesnichenko/mrt v0.4.0"; do
	grep -Eq "^[[:space:]]*(require[[:space:]]+)?$req([[:space:]]|\$)" go.mod || bad "go.mod does not require $req"
done
if grep -Eq '^[[:space:]]*(replace\b|[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]*=>)' go.mod; then
	bad "go.mod has a replace"
fi
other=$(grep -oE 'github\.com/rkolesnichenko/[^[:space:]]+' go.mod | grep -vx -e 'github.com/rkolesnichenko/routecheck' \
	-e 'github.com/rkolesnichenko/rpsl' -e 'github.com/rkolesnichenko/rpsl/types' \
	-e 'github.com/rkolesnichenko/rpsl/resolve' -e 'github.com/rkolesnichenko/rpsl/ast' \
	-e 'github.com/rkolesnichenko/rpsl/lexer' -e 'github.com/rkolesnichenko/mrt')
[ -z "$other" ] || bad "go.mod names another module of ours: $other"
[ ! -e go.work ] || bad "go.work exists"

step "api surface: api/ matches the public API, and the API conventions hold"
go run ./internal/apisurface -check ||
	bad "api surface (ROUTECHECK_API_UPDATE=1 go run ./internal/apisurface -check rewrites api/; review the diff)"

bin=$(go env GOPATH)/bin
for tool in staticcheck govulncheck; do
	cmd=$(command -v "$tool" || true)
	[ -n "$cmd" ] || { [ -x "$bin/$tool" ] && cmd="$bin/$tool"; }
	if [ -z "$cmd" ]; then
		step "$tool: not installed, skipped"
		continue
	fi
	step "$tool"
	"$cmd" ./... || bad "$tool"
done

if [ -n "${FUZZTIME:-}" ]; then
	scripts/fuzz.sh || bad "fuzz"
fi

echo
if [ "$fail" -ne 0 ]; then echo "check: FAILED"; exit 1; fi
echo "check: ok"
