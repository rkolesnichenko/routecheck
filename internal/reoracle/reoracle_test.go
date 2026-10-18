package reoracle

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

func p(as ...types.ASN) []types.ASN { return as }

func TestMatch(t *testing.T) {
	sets := Sets()
	repeat := func(a types.ASN, n int) []types.ASN { return slices.Repeat([]types.ASN{a}, n) }
	cases := []struct {
		re   string
		path []types.ASN
		want bool
		err  error
	}{
		// RFC 2622 §5.4's examples, with the results it states.
		{"AS3", p(1, 3, 2), true, nil},
		{"AS3", p(1, 2), false, nil},
		{"^AS1", p(1, 2), true, nil},
		{"^AS1", p(2, 1), false, nil},
		{"AS2$", p(1, 2), true, nil},
		{"AS2$", p(2, 1), false, nil},
		{"^AS1 AS2 AS3$", p(1, 2, 3), true, nil},
		{"^AS1 AS2 AS3$", p(1, 2, 3, 4), false, nil},
		{"^AS1 AS2 AS3$", p(0, 1, 2, 3), false, nil},
		{"^AS1 .* AS2$", p(1, 2), true, nil},
		{"^AS1 .* AS2$", p(1, 7, 7, 2), true, nil},
		{"^AS1 .* AS2$", p(1, 7, 7, 3), false, nil},
		{"^[AS1 AS2]{2}$", p(1, 2), true, nil},
		{"^[AS1 AS2]~{2}$", p(1, 2), false, nil},
		{"^[AS1 AS2]~{2}$", p(2, 2), true, nil},
		// Sets.
		{"AS-A", p(64502), true, nil},
		{"AS-A", p(64503), false, nil},
		{"AS-EMPTY", p(64502), false, nil},
		{"AS-MISSING", p(64502), false, nil},
		{"[^AS-MISSING]", p(64502), true, nil},
		{"AS-ANY", p(7), true, nil},
		{"as-any", p(7), true, nil},
		{"[^AS-ANY]", p(7), false, nil},
		{"^AS-ANY~+$", p(7, 7, 7), true, nil},
		{"^AS-ANY~+$", p(7, 7, 8), false, nil},
		// The empty path.
		{"^$", nil, true, nil},
		{".*", nil, true, nil},
		{".", nil, false, nil},
		{"(AS1 AS2)~*", nil, true, nil},
		{"(AS1 AS2)~+", nil, false, nil},
		// Refusals.
		{"(AS1 AS2)~*", p(1, 2), false, ErrNotSingleAS},
		{"AS1 | (AS2 AS3)~*", p(5), false, ErrNotSingleAS},
		{"AS1*~+", p(1), false, ErrNotSingleAS},
		{"PeerAS", p(1), false, ErrUnbound},
		{"[AS1 PeerAS]~*", p(1, 2), false, ErrUnbound},
		{"AS1:AS-X:PeerAS", nil, false, ErrUnbound},
		// Counts over Go's 1000 are clamped to the path's length + 1.
		{"^AS1{5000}$", repeat(1, 5000)[:4], false, nil},
		{"^AS1{3,5000}$", repeat(1, 4), true, nil},
		{"^(AS1?){100000}$", p(1, 1), true, nil},
		{"^(AS1?){100000}$", p(1, 2), false, nil},
		{"^(^ | AS1){4000}$", p(1, 1), true, nil},
		{"^(AS1 | ^){4000} AS2$", p(1, 1, 2), true, nil},
		{"^(AS1 AS1?){3}$", p(1, 1, 1), true, nil},
		{"^(AS1 AS1?){3}$", p(1, 1), false, nil},
		{"(AS1 AS2)~{0}", p(1, 2), false, ErrNotSingleAS},
	}
	for _, c := range cases {
		re, err := policy.ParseASPathRegexp(c.re)
		if err != nil {
			t.Fatalf("parse %q: %v", c.re, err)
		}
		got, err := Match(re, sets, c.path)
		if !errors.Is(err, c.err) || (c.err == nil && err != nil) {
			t.Errorf("Match(<%s>, %v) error = %v, want %v", c.re, c.path, err, c.err)
			continue
		}
		if err == nil && got != c.want {
			t.Errorf("Match(<%s>, %v) = %v, want %v", c.re, c.path, got, c.want)
		}
	}
}

// TestOracleAnySet holds the oracle to a set that reaches AS-ANY (Any is
// true, List empty): any AS, whatever the case its name is written in.
func TestOracleAnySet(t *testing.T) {
	sets := Sets()
	for _, c := range []struct {
		re   string
		path []types.ASN
		want bool
	}{
		{"AS-ALL", p(64501), true},
		{"AS-ALL", p(4200000000), true},
		{"as-all", p(4200000000), true},
		{"AS-ALL", nil, false},
		{"^AS-ALL AS-ALL$", p(1, 2), true},
		{"^AS-ALL AS-ALL$", p(1), false},
		{"[^AS-ALL]", p(64501), false},
		{"[AS-ALL]", p(7), true},
		{"^AS-ALL~+$", p(7, 7, 7), true},
		{"^AS-ALL~+$", p(7, 7, 8), false},
	} {
		re, err := policy.ParseASPathRegexp(c.re)
		if err != nil {
			t.Fatalf("parse %q: %v", c.re, err)
		}
		got, err := Match(re, sets, c.path)
		if err != nil || got != c.want {
			t.Errorf("Match(<%s>, %v) = %v, %v; want %v", c.re, c.path, got, err, c.want)
		}
	}
}

// TestCountsAreClamped shows that the translation never asks Go for more
// repetitions than the path has ASes, plus one.
func TestCountsAreClamped(t *testing.T) {
	re, err := policy.ParseASPathRegexp("AS1{2,5000} AS2~{1001,} (AS3)*")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Translate(re, nil, p(1, 2, 2))
	if err != nil {
		t.Fatal(err)
	}
	for _, big := range []string{"5000", "1001"} {
		if strings.Contains(got, big) {
			t.Errorf("Translate = %q, holds the count %s", got, big)
		}
	}
	if !strings.Contains(got, "{2,4}") || !strings.Contains(got, "{4,}") {
		t.Errorf("Translate = %q, want the counts clamped to {2,4} and {4,}", got)
	}
}

func TestGenDeterministic(t *testing.T) {
	a, b := NewGen(7), NewGen(7)
	for i := 0; i < 200; i++ {
		if x, y := a.Regexp(), b.Regexp(); x != y {
			t.Fatalf("draw %d: %q != %q", i, x, y)
		}
		if x, y := a.Path(), b.Path(); !slices.Equal(x, y) {
			t.Fatalf("draw %d: %v != %v", i, x, y)
		}
	}
	if NewGen(7).Regexp() == NewGen(8).Regexp() && NewGen(7).Regexp() == NewGen(9).Regexp() {
		t.Error("different seeds draw the same first regexp")
	}
}

// TestGenParses holds the generator to its promise: every regexp it writes
// parses, and it writes what the matchers must handle — anchors inside
// groups and alternation branches, same-AS repetitions of atoms and of
// wider operands, every set name.
func TestGenParses(t *testing.T) {
	g := NewGen(1)
	g.BigCounts = true
	seen := map[string]int{}
	for i := 0; i < 20000; i++ {
		body := g.Regexp()
		re, err := policy.ParseASPathRegexp(body)
		if err != nil {
			t.Fatalf("generated %q does not parse: %v", body, err)
		}
		inner := false
		walk(re.Body, false, func(e policy.ASPathExpr, nested bool) {
			switch x := e.(type) {
			case policy.ASPathStart, policy.ASPathEnd:
				if nested {
					inner = true
				}
			case policy.ASPathRepeat:
				if x.Same {
					if oneAS(x.Inner) {
						seen["same over an atom"]++
					} else {
						seen["same over a wider operand"]++
					}
				}
				if x.Min > 1000 || x.Max > 1000 {
					seen["count over 1000"]++
				}
			case policy.ASPathSet:
				seen[x.Name.String()]++
			case policy.ASPathClass:
				if x.Negated {
					seen["negated class"]++
				}
			case policy.ASPathAlt:
				seen["alternation"]++
			}
		})
		if inner {
			seen["anchor inside a group or branch"]++
		}
	}
	for _, k := range []string{"same over an atom", "same over a wider operand", "count over 1000",
		"AS-A", "AS-EMPTY", "AS-ALL", "AS-ANY", "AS-MISSING", "negated class", "alternation",
		"anchor inside a group or branch"} {
		if seen[k] < 50 {
			t.Errorf("%s: %d of 20000 regexps, want at least 50", k, seen[k])
		}
	}
	t.Logf("%v", seen)
}

// walk calls fn on e and every node beneath it; nested is true below an
// alternation, a group that is quantified, or a sequence inside either.
func walk(e policy.ASPathExpr, nested bool, fn func(policy.ASPathExpr, bool)) {
	fn(e, nested)
	switch x := e.(type) {
	case policy.ASPathAlt:
		for _, a := range x.Alts {
			walk(a, true, fn)
		}
	case policy.ASPathSeq:
		for _, a := range x.Terms {
			walk(a, nested, fn)
		}
	case policy.ASPathRepeat:
		walk(x.Inner, true, fn)
	case policy.ASPathClass:
		for _, a := range x.Items {
			walk(a, nested, fn)
		}
	}
}

func TestGenPath(t *testing.T) {
	g := NewGen(3)
	lengths := map[int]bool{}
	runs := 0
	for i := 0; i < 2000; i++ {
		path := g.Path()
		lengths[len(path)] = true
		for j, a := range path {
			if a < FirstAS || a >= FirstAS+NumASes {
				t.Fatalf("path %v holds %v, outside the alphabet", path, a)
			}
			if j > 0 && path[j-1] == a {
				runs++
			}
		}
	}
	for n := 0; n <= 8; n++ {
		if !lengths[n] {
			t.Errorf("no path of length %d in 2000", n)
		}
	}
	if runs < 500 {
		t.Errorf("%d repeated ASes in 2000 paths, want same-AS runs to be common", runs)
	}
}

func TestSets(t *testing.T) {
	s := Sets()
	a, _ := types.ParseSetName(SetA)
	if !s[a].Has(64501) || !s[a].Has(64502) || s[a].Has(64500) {
		t.Errorf("AS-A = %v", s[a])
	}
	if all := s[mustSet(SetAll)]; !all.Any() || !all.Has(4200000000) || all.Len() != 0 {
		t.Errorf("AS-ALL = %v, want a set reaching AS-ANY", all)
	}
	if _, ok := s[mustSet(SetMissing)]; ok {
		t.Error("AS-MISSING is in Sets")
	}
	var empty resolve.ASNSet
	if empty.Has(1) {
		t.Error("zero ASNSet has an AS")
	}
}
