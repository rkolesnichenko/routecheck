#!/bin/sh
# Runs every fuzz target for FUZZTIME each (default 15s). check.sh runs it when
# FUZZTIME is set; CI runs it as its own job, split into shards:
#
#   scripts/fuzz.sh                      # every target, 15s each
#   FUZZTIME=1m scripts/fuzz.sh          # every target, 1m each
#   FUZZ_SHARD=2/3 scripts/fuzz.sh       # the 2nd of 3 shards (every 3rd target)
set -u
cd "$(dirname "$0")/.."
FUZZTIME=${FUZZTIME:-15s}
FUZZ_SHARD=${FUZZ_SHARD:-1/1}
shard=${FUZZ_SHARD%%/*}
shards=${FUZZ_SHARD#*/}
# Digits, one slash, digits: "2" alone is not shard 2 of 2. No leading zero,
# which $(( )) would read as octal.
case "$FUZZ_SHARD" in
*[!0-9/]* | */*/* | /* | */ | 0* | */0*) echo "fuzz: FUZZ_SHARD must be i/n, not $FUZZ_SHARD"; exit 2 ;;
*/*) ;;
*) echo "fuzz: FUZZ_SHARD must be i/n, not $FUZZ_SHARD"; exit 2 ;;
esac
if [ "$shards" -lt 1 ] || [ "$shard" -lt 1 ] || [ "$shard" -gt "$shards" ]; then
	echo "fuzz: FUZZ_SHARD must be i/n with 1 <= i <= n, not $FUZZ_SHARD"
	exit 2
fi
fail=0
step() { printf '\n== %s\n' "$*"; }
bad() { echo "FAIL: $*"; fail=1; }

# fuzz runs one fuzz target. The Go fuzzing harness sometimes ends a run that
# found nothing with "context deadline exceeded" when a worker is slow to stop
# at -fuzztime; a real crash always prints "Failing input written to". So a run
# that fails that way without a failing input is retried once.
fuzz() {
	out=$(cd "$1" && go test -run='^$' -fuzz="^$3\$" -fuzztime="$FUZZTIME" -fuzzminimizetime=5s "$2" 2>&1)
	rc=$?
	printf '%s\n' "$out"
	if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q "context deadline exceeded" &&
		! printf '%s' "$out" | grep -q "Failing input written"; then
		step "fuzz $3: harness deadline without a failing input; retrying once"
		(cd "$1" && go test -run='^$' -fuzz="^$3\$" -fuzztime="$FUZZTIME" -fuzzminimizetime=5s "$2")
		rc=$?
	fi
	return "$rc"
}

# One target per line: "<dir> <pkg> <FuzzName>".
targets='
. ./pathre FuzzMatch
. ./verdict FuzzDecide
'

# dir package fuzz-target; shard i of n takes targets i, i+n, i+2n, ...
i=0
ran=0
oldifs=$IFS
IFS='
'
for t in $targets; do
	IFS=$oldifs
	i=$((i + 1))
	[ $(((i - 1) % shards + 1)) -eq "$shard" ] || continue
	ran=$((ran + 1))
	set -- $t
	step "fuzz $3 ($FUZZTIME)"
	fuzz "$1" "$2" "$3" || bad "fuzz $3"
done
# A shard past the last target would otherwise pass having fuzzed nothing.
if [ "$ran" -eq 0 ]; then
	echo "fuzz: shard $FUZZ_SHARD runs no target (there are $i)"
	exit 2
fi

echo
if [ "$fail" -ne 0 ]; then echo "fuzz: FAILED"; exit 1; fi
echo "fuzz: ok"
