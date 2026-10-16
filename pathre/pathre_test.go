package pathre_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/rkolesnichenko/routecheck/pathre"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

func p(as ...types.ASN) []types.ASN { return as }

func setName(t testing.TB, s string) types.SetName {
	t.Helper()
	n, err := types.ParseSetName(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func parse(t testing.TB, body string) *policy.ASPathRE {
	t.Helper()
	re, err := policy.ParseASPathRegexp(body)
	if err != nil {
		t.Fatalf("parse <%s>: %v", body, err)
	}
	return re
}

func TestMatch(t *testing.T) {
	sets := map[types.SetName]resolve.ASNSet{
		setName(t, "AS-A"):     resolve.NewASNSet(64501, 64502),
		setName(t, "AS-EMPTY"): resolve.NewASNSet(),
		// AS-ANY's members, were anyone to list them, are not consulted.
		setName(t, "AS-ANY"): resolve.NewASNSet(64501),
	}
	ones := func(n int) []types.ASN { return slices.Repeat([]types.ASN{1}, n) }
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
		{"^AS1 AS2 AS3$", p(1, 2), false, nil},
		{"^AS1 AS2 AS3$", p(1, 3, 2), false, nil},
		{"^AS1 .* AS2$", p(1, 2), true, nil},
		{"^AS1 .* AS2$", p(1, 7, 7, 2), true, nil},
		{"^AS1 .* AS2$", p(1, 7, 7, 3), false, nil},
		{"^AS1 .* AS2$", p(2, 1, 2), false, nil},
		// "[AS1 AS2]{2}" matches AS1 AS2, AS2 AS1, AS1 AS1 and AS2 AS2;
		// "[AS1 AS2]~{2}" only AS1 AS1 and AS2 AS2.
		{"^[AS1 AS2]{2}$", p(1, 2), true, nil},
		{"^[AS1 AS2]{2}$", p(2, 1), true, nil},
		{"^[AS1 AS2]{2}$", p(1, 1), true, nil},
		{"^[AS1 AS2]{2}$", p(1, 3), false, nil},
		{"^[AS1 AS2]~{2}$", p(1, 1), true, nil},
		{"^[AS1 AS2]~{2}$", p(2, 2), true, nil},
		{"^[AS1 AS2]~{2}$", p(1, 2), false, nil},
		{"^[AS1 AS2]~{2}$", p(2, 1), false, nil},
		{"^AS1~+ AS2$", p(1, 1, 1, 2), true, nil},
		{"^.~* AS2$", p(1, 1, 3, 2), false, nil},
		{"^.~* .~* AS2$", p(1, 1, 3, 2), true, nil},
		{"^AS1~{0} AS2$", p(2), true, nil},
		{"AS1~{2,}", p(1, 2, 1), false, nil},
		// Classes and ranges.
		{"[AS1 - AS5]", p(7, 3), true, nil},
		{"[AS1 - AS5]", p(7, 6), false, nil},
		{"[^AS1 - AS5 AS7]", p(7, 3), false, nil},
		{"[^AS1 - AS5 AS7]", p(7, 6), true, nil},
		{"[.]", p(9), true, nil},
		{"[^.]", p(9), false, nil},
		// Sets: an expanded set by its members, AS-ANY as any one AS, a set
		// the caller did not expand as no AS.
		{"AS-A", p(64502), true, nil},
		{"AS-A", p(64503), false, nil},
		{"AS-EMPTY", p(64502), false, nil},
		{"AS-ANY", p(7), true, nil},
		{"as-any", p(7), true, nil},
		{"^AS-ANY$", p(7, 8), false, nil},
		{"[AS-ANY]", p(7), true, nil},
		{"[^AS-ANY]", p(7), false, nil},
		{"^AS-ANY~+$", p(7, 7, 7), true, nil},
		{"^AS-ANY~+$", p(7, 7, 8), false, nil},
		{"AS-MISSING", p(64501), false, nil},
		{"[AS-MISSING]", p(64501), false, nil},
		{"[^AS-MISSING]", p(64501), true, nil},
		{"AS-MISSING*", p(64501), true, nil},
		{"^AS-MISSING*$", p(64501), false, nil},
		// The empty path.
		{"^$", nil, true, nil},
		{".*", nil, true, nil},
		{"^.*$", nil, true, nil},
		{".", nil, false, nil},
		{"^", nil, true, nil},
		{"AS1?", nil, true, nil},
		// The empty path holds no AS to make a run of, so a same-AS
		// repetition, over any operand, matches zero repetitions only; one
		// over a wider operand is answered there (as routemodel does).
		{"(AS1 AS2)~*", nil, true, nil},
		{"(AS1 AS2)~+", nil, false, nil},
		{"^(AS1? $)~+", nil, false, nil},
		{"^(AS1? $)~{0,2}$", nil, true, nil},
		{"(.~*)~+", nil, false, nil},
		{"AS1?~+", nil, false, nil},
		{"AS1~+", nil, false, nil},
		// Refusals.
		{"(AS1 AS2)~*", p(1, 2), false, pathre.ErrNotSingleAS},
		{"(AS1 AS2)~*", p(9), false, pathre.ErrNotSingleAS},
		{"AS1 | (AS2 AS3)~*", p(1), false, pathre.ErrNotSingleAS},
		{"AS1*~+", p(1), false, pathre.ErrNotSingleAS},
		{"(AS1 | AS2)~{2}", p(1, 1), false, pathre.ErrNotSingleAS},
		{"PeerAS", p(1), false, pathre.ErrUnbound},
		{"PeerAS", nil, false, pathre.ErrUnbound},
		{"[AS1 PeerAS]", p(1), false, pathre.ErrUnbound},
		{"AS1:AS-X:PeerAS", p(1), false, pathre.ErrUnbound},
		{"(AS1 PeerAS)~*", p(1), false, pathre.ErrUnbound}, // ErrUnbound comes first
		// No count limit (D6), and counts above the path's length cost
		// nothing.
		{"^AS1{5000}$", ones(5000), true, nil},
		{"^AS1{5000}$", ones(4999), false, nil},
		{"^AS1{5000}$", ones(5001), false, nil},
		{"AS1{5000}", ones(5001), true, nil},
		{"^AS1~{5000}$", ones(5000), true, nil},
		{"^(AS1?){100000}$", p(1, 1), true, nil},
		{"^(AS1?){100000}$", p(1, 2), false, nil},
		{"^(AS1?){100000,}$", p(1, 1), true, nil},
		{"^(AS1 AS1?){3}$", p(1, 1, 1), true, nil},
		{"^(AS1 AS1?){3}$", p(1, 1), false, nil},
		{"^(AS1 AS1?){2,3}$", p(1, 1), true, nil},
		{"^((AS1 AS2)*)*$", p(1, 2, 1, 2), true, nil},
		{"^((AS1 AS2)*)*$", p(1, 2, 1), false, nil},
		// Anchors inside a repeated operand are tests at 0 and len(path).
		{"^(^ | AS1){4000}$", p(1, 1), true, nil},
		{"^(AS1 | ^){4000} AS2$", p(1, 1, 2), true, nil},
		{"(AS1 | ^){4000} AS2$", p(3, 1, 1, 2), false, nil}, // "^" holds only at 0
		{"^(AS1 | $)*$", p(1, 2), false, nil},
		{"(AS1 $ | AS2)+", p(2, 1), true, nil},
		{"(AS1 $ AS2)", p(1, 2), false, nil},
		{"AS1 ^", p(1), false, nil},
		{"(^ AS1 | AS2 $)", p(3, 1, 3), false, nil},
		{"(^ AS1 | AS2 $)", p(3, 2), true, nil},
		{"()", p(3), true, nil},
	}
	for _, c := range cases {
		got, err := pathre.Match(parse(t, c.re), sets, c.path)
		if c.err != nil {
			if !errors.Is(err, c.err) {
				t.Errorf("Match(<%s>, %v) = %v, %v; want error %v", c.re, short(c.path), got, err, c.err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("Match(<%s>, %v) = %v, %v; want %v", c.re, short(c.path), got, err, c.want)
		}
	}
}

// short abbreviates a long path in a failure message.
func short(path []types.ASN) any {
	if len(path) > 10 {
		return len(path)
	}
	return path
}

// TestMatchBound holds Match to the regexp Bind returns: PeerAS becomes the
// peer, a template the peer's set.
func TestMatchBound(t *testing.T) {
	re := parse(t, "^PeerAS AS1:AS-X:PeerAS+$")
	if _, err := pathre.Match(re, nil, p(5, 6)); !errors.Is(err, pathre.ErrUnbound) {
		t.Fatalf("unbound: err = %v", err)
	}
	sets := map[types.SetName]resolve.ASNSet{setName(t, "AS1:AS-X:AS5"): resolve.NewASNSet(6, 7)}
	for _, c := range []struct {
		path []types.ASN
		want bool
	}{{p(5, 6), true}, {p(5, 6, 7), true}, {p(5, 8), false}, {p(6, 6), false}} {
		got, err := pathre.Match(re.Bind(5), sets, c.path)
		if err != nil || got != c.want {
			t.Errorf("Match(%s, %v) = %v, %v; want %v", re.Bind(5), c.path, got, err, c.want)
		}
	}
}

// TestMatchHandBuilt covers trees the parser does not write: Match never
// panics on them and answers or refuses.
func TestMatchHandBuilt(t *testing.T) {
	cases := []struct {
		name string
		re   *policy.ASPathRE
		path []types.ASN
		want bool
		err  bool
	}{
		{"nil regexp", nil, p(1), false, true},
		{"nil body", &policy.ASPathRE{}, p(1), false, true},
		{"nil term", &policy.ASPathRE{Body: policy.ASPathSeq{Terms: []policy.ASPathExpr{nil}}}, p(1), false, true},
		{"range alone", &policy.ASPathRE{Body: policy.ASPathASNRange{Lo: 1, Hi: 3}}, p(2), true, false},
		{"empty alternation", &policy.ASPathRE{Body: policy.ASPathAlt{}}, p(2), false, false},
		{"empty class", &policy.ASPathRE{Body: policy.ASPathClass{}}, p(2), false, false},
		{"max below min", &policy.ASPathRE{Body: policy.ASPathRepeat{
			Inner: policy.ASPathASN{AS: 1}, Op: policy.RepeatRange, Min: 3, Max: 2}}, p(1, 1, 1), false, false},
		{"negative min", &policy.ASPathRE{Body: policy.ASPathRepeat{
			Inner: policy.ASPathASN{AS: 1}, Op: policy.RepeatRange, Min: -4, Max: 1}}, p(2), true, false},
		{"quantified anchor", &policy.ASPathRE{Body: policy.ASPathRepeat{
			Inner: policy.ASPathStart{}, Op: policy.RepeatPlus, Min: 1, Max: -1}}, p(2), true, false},
	}
	for _, c := range cases {
		got, err := pathre.Match(c.re, nil, c.path)
		if (err != nil) != c.err || got != c.want {
			t.Errorf("%s: Match = %v, %v; want %v, error %v", c.name, got, err, c.want, c.err)
		}
	}
}
