package pathre_test

import (
	"errors"
	"testing"

	"github.com/rkolesnichenko/routecheck/internal/reoracle"
	"github.com/rkolesnichenko/routecheck/pathre"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// agree compares Match with oracle 2 (internal/reoracle) on one regexp and
// path. Both must refuse a same-AS repetition over a wider operand, or
// neither; when both answer, the answers must be equal. A translation Go
// cannot compile is the only answer the oracle may lack. It reports how the
// pair came out: "true", "false", "not-single-as", "unbound" or
// "oracle-too-complex".
func agree(t testing.TB, re *policy.ASPathRE, sets map[types.SetName]resolve.ASNSet, path []types.ASN) string {
	t.Helper()
	got, err := pathre.Match(re, sets, path)
	want, oerr := reoracle.Match(re, sets, path)
	switch {
	case errors.Is(oerr, reoracle.ErrTooComplex):
		// The oracle refuses an unbound regexp and a wider same-AS operand
		// before it compiles, so Match must answer this one.
		if err != nil {
			t.Errorf("<%s> on %v: Match error %v", re, path, err)
		}
		return "oracle-too-complex"
	case errors.Is(err, pathre.ErrUnbound) || errors.Is(oerr, reoracle.ErrUnbound):
		if !errors.Is(err, pathre.ErrUnbound) || !errors.Is(oerr, reoracle.ErrUnbound) {
			t.Errorf("<%s> on %v: Match error %v, oracle error %v; want both unbound", re, path, err, oerr)
		}
		return "unbound"
	case errors.Is(err, pathre.ErrNotSingleAS) || errors.Is(oerr, reoracle.ErrNotSingleAS):
		if !errors.Is(err, pathre.ErrNotSingleAS) || !errors.Is(oerr, reoracle.ErrNotSingleAS) {
			t.Errorf("<%s> on %v: Match = %v, %v; oracle = %v, %v; want both to refuse", re, path, got, err, want, oerr)
		}
		return "not-single-as"
	case err != nil || oerr != nil:
		t.Errorf("<%s> on %v: Match error %v, oracle error %v", re, path, err, oerr)
		return "error"
	case got != want:
		t.Errorf("<%s> on %v: Match = %v, oracle = %v", re, path, got, want)
	}
	if got {
		return "true"
	}
	return "false"
}

// TestMatchesOracle holds Match to oracle 2 on 20,000 seeded random regexps,
// each against three random paths. One regexp in about fifty has a count
// over 1000, which only the clamped oracle can answer.
func TestMatchesOracle(t *testing.T) {
	const regexps, paths = 20000, 3
	g := reoracle.NewGen(20261016)
	g.BigCounts = true
	sets := reoracle.Sets()
	counts := map[string]int{}
	for i := 0; i < regexps; i++ {
		body := g.Regexp()
		re, err := policy.ParseASPathRegexp(body)
		if err != nil {
			t.Fatalf("generated <%s> does not parse: %v", body, err)
		}
		for j := 0; j < paths; j++ {
			counts[agree(t, re, sets, g.Path())]++
		}
		if t.Failed() {
			t.FailNow()
		}
	}
	t.Logf("%d regexp × path pairs: %v", regexps*paths, counts)
	if counts["true"] < 10000 || counts["false"] < 10000 {
		t.Errorf("answers %v: want at least 10,000 of each", counts)
	}
}
