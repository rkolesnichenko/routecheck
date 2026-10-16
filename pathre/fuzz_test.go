package pathre_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/rkolesnichenko/routecheck/internal/reoracle"
	"github.com/rkolesnichenko/routecheck/pathre"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

// maxFuzzPath caps the path a fuzz input decodes to, past what real BGP
// paths reach; fuzzMaxWork keeps every input fast, so a cost bug shows as
// ErrTooExpensive rather than as a slow run. Oracle 2 is consulted only on
// paths of up to oracleFuzzPath ASes: its clamped counts grow with the path,
// and Go's regexp with them.
const (
	maxFuzzPath    = 300
	fuzzMaxWork    = 1 << 20
	oracleFuzzPath = 64
)

// FuzzMatch runs MatchWith on any regexp the parser accepts and any path
// over six ASes, with a small work budget: it must not panic, and wherever
// both it and oracle 2 answer, they must agree.
func FuzzMatch(f *testing.F) {
	for _, s := range []struct {
		re   string
		path []byte
	}{
		{"^AS64500 .* AS64501$", []byte{0, 3, 3, 1}},
		{"[AS64500 AS64501]~{2}", []byte{0, 1, 1}},
		{"(AS64500 AS64501)~*", []byte{0, 1}},
		{"(AS64500 AS64501)~*", nil},
		{"^(AS64500?){100000}$", []byte{0, 0}},
		{"(^ | AS64501){4000} AS64502$", []byte{1, 1, 2}},
		{"[^AS-A AS64504 - AS64505] AS-ANY~+ AS-MISSING*", []byte{3, 2, 2, 5}},
		{"((AS64500 | $)* ^)+", []byte{0, 0}},
		{"PeerAS AS1:AS-X:PeerAS", []byte{0}},
		{"AS-EMPTY? (AS-A{3,}){0,1001}", []byte{1, 2, 1, 2, 1, 2}},
		{"(((. .){0,999} .){0,999} .){0,999} AS64502", bytes.Repeat([]byte{0, 1, 3}, 100)},
		{"^(AS64500 AS64501)* AS64500~+ .* [^AS-A]{2,9}$", bytes.Repeat([]byte{0, 1}, 150)},
	} {
		f.Add(s.re, s.path)
	}
	sets := reoracle.Sets()
	f.Fuzz(func(t *testing.T, body string, raw []byte) {
		re, err := policy.ParseASPathRegexp(body)
		if err != nil {
			return
		}
		raw = raw[:min(len(raw), maxFuzzPath)]
		path := make([]types.ASN, len(raw))
		for i, b := range raw {
			path[i] = reoracle.FirstAS + types.ASN(b%reoracle.NumASes)
		}
		o := pathre.MatchOptions{MaxWork: fuzzMaxWork}
		if len(path) > oracleFuzzPath {
			_, err := pathre.MatchWith(re, sets, path, o)
			if err != nil && !errors.Is(err, pathre.ErrTooExpensive) &&
				!errors.Is(err, pathre.ErrNotSingleAS) && !errors.Is(err, pathre.ErrUnbound) {
				t.Errorf("<%s> on %d ASes: %v", re, len(path), err)
			}
			return
		}
		agree(t, re, sets, path, o)
	})
}
