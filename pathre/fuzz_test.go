package pathre_test

import (
	"testing"

	"github.com/rkolesnichenko/routecheck/internal/reoracle"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/types"
)

// maxFuzzPath caps the path a fuzz input decodes to: a long path makes every
// input slow (the oracle's clamped counts grow with it) without reaching
// any code a short one does not.
const maxFuzzPath = 64

// FuzzMatch runs Match on any regexp the parser accepts and any path over six
// ASes: it must not panic, and wherever oracle 2 answers, it must agree.
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
		agree(t, re, sets, path)
	})
}
