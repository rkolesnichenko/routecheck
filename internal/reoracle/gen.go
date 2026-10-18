package reoracle

import (
	"math/rand/v2"
	"strconv"
	"strings"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// The generator's alphabet: paths and regexps use the ASes FirstAS to
// FirstAS+NumASes-1, and these set names.
const (
	FirstAS = types.ASN(64500)
	NumASes = 6
)

// Set names the generator writes. SetA, SetEmpty and SetAll are in Sets.
// SetAll is a set that reaches AS-ANY and SetAny is AS-ANY itself: both
// match any AS. SetMissing is in no map, so it matches no AS.
const (
	SetA       = "AS-A"
	SetEmpty   = "AS-EMPTY"
	SetAll     = "AS-ALL"
	SetAny     = "AS-ANY"
	SetMissing = "AS-MISSING"
)

// Sets returns the members of the generator's expanded sets: AS-A holds
// 64501 and 64502, AS-EMPTY nothing, and AS-ALL, a set that reaches AS-ANY,
// every AS (resolve.NewAnyASNSet: Any and Has are true, List is empty).
func Sets() map[types.SetName]resolve.ASNSet {
	return map[types.SetName]resolve.ASNSet{
		mustSet(SetA):     resolve.NewASNSet(FirstAS+1, FirstAS+2),
		mustSet(SetEmpty): resolve.NewASNSet(),
		mustSet(SetAll):   resolve.NewAnyASNSet(),
	}
}

func mustSet(s string) types.SetName {
	n, err := types.ParseSetName(s)
	if err != nil {
		panic(err) // the names above are constants
	}
	return n
}

// Gen draws random regexps and paths from a seeded generator: the same seed
// gives the same sequence on every run.
type Gen struct {
	r *rand.Rand
	// MaxDepth bounds the nesting of groups (default 4).
	MaxDepth int
	// MaxPath bounds a path's length (default 8).
	MaxPath int
	// BigCounts makes a repetition count over 1000 possible (about one count
	// in fifty), beyond what Go's regexp compiles unclamped.
	BigCounts bool
}

// NewGen returns a generator seeded with seed.
func NewGen(seed uint64) *Gen {
	return &Gen{r: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)), MaxDepth: 4, MaxPath: 8}
}

// Path returns a path of 0 to MaxPath ASes; about a third of its ASes repeat
// the one before, so same-AS runs are common.
func (g *Gen) Path() []types.ASN {
	n := g.r.IntN(g.MaxPath + 1)
	path := make([]types.ASN, n)
	for i := range path {
		if i > 0 && g.r.IntN(3) == 0 {
			path[i] = path[i-1]
			continue
		}
		path[i] = g.as()
	}
	return path
}

func (g *Gen) as() types.ASN { return FirstAS + types.ASN(g.r.IntN(NumASes)) }

// Regexp returns the body of a random AS-path regexp (no angle brackets),
// one that policy.ParseASPathRegexp accepts. Anchors appear at the ends and
// inside groups and alternation branches; quantifiers, same-AS ones among
// them, apply to atoms, groups and other quantifiers, never to an anchor.
func (g *Gen) Regexp() string {
	for {
		var b strings.Builder
		if g.r.IntN(4) == 0 {
			b.WriteString("^ ")
		}
		s, _ := g.alt(0)
		b.WriteString(s)
		if g.r.IntN(4) == 0 {
			b.WriteString(" $")
		}
		if out := strings.TrimSpace(b.String()); out != "" { // an empty body does not parse
			return out
		}
	}
}

// alt writes an alternation of one to three branches; anchor reports whether
// it is nothing but one anchor, which the parser refuses to quantify.
func (g *Gen) alt(depth int) (s string, anchor bool) {
	n := 1
	if g.r.IntN(3) == 0 {
		n += 1 + g.r.IntN(2)
	}
	parts := make([]string, n)
	for i := range parts {
		parts[i], anchor = g.seq(depth)
	}
	if n > 1 {
		anchor = false
	}
	return strings.Join(parts, " | "), anchor
}

// seq writes zero to four terms; zero only rarely, as "()" or an empty
// alternation branch.
func (g *Gen) seq(depth int) (s string, anchor bool) {
	n := 1 + g.r.IntN(4)
	if g.r.IntN(25) == 0 {
		n = 0
	}
	parts := make([]string, n)
	for i := range parts {
		parts[i], anchor = g.term(depth)
	}
	if n != 1 {
		anchor = false
	}
	return strings.Join(parts, " "), anchor
}

func (g *Gen) term(depth int) (s string, anchor bool) {
	s, anchor = g.atom(depth)
	if anchor {
		return s, true
	}
	// 0, 1, 2, ... quantifiers, each 40% likely. A same-AS one is likely on
	// an atom, rare on a group or a quantifier (which the matchers refuse on
	// a non-empty path), so most regexps get an answer.
	sameOdds := 3
	if strings.HasPrefix(s, "(") {
		sameOdds = 12
	}
	for g.r.IntN(5) < 2 {
		s += g.quant(g.r.IntN(sameOdds) == 0)
		sameOdds = 12
	}
	return s, false
}

func (g *Gen) atom(depth int) (s string, anchor bool) {
	switch k := g.r.IntN(20); {
	case k < 6:
		return g.as().String(), false
	case k < 8:
		return ".", false
	case k < 10:
		return g.set(), false
	case k < 13:
		return g.class(), false
	case k < 15 && depth < g.MaxDepth:
		inner, anchor := g.alt(depth + 1)
		return "(" + inner + ")", anchor
	case k == 15:
		return "^", true
	case k == 16:
		return "$", true
	default:
		return g.as().String(), false
	}
}

func (g *Gen) set() string {
	switch g.r.IntN(10) {
	case 0, 1, 2:
		return SetA
	case 3:
		return SetEmpty
	case 4, 5:
		return SetAny
	case 6:
		return strings.ToLower(SetAny) // set names are case-insensitive
	case 7:
		return SetAll
	case 8:
		return strings.ToLower(SetAll)
	default:
		return SetMissing
	}
}

func (g *Gen) class() string {
	var b strings.Builder
	b.WriteByte('[')
	if g.r.IntN(3) == 0 {
		b.WriteByte('^')
	}
	n := 1 + g.r.IntN(3)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(' ')
		}
		switch g.r.IntN(6) {
		case 0, 1:
			b.WriteString(g.as().String())
		case 2:
			lo, hi := g.as(), g.as()
			if hi < lo {
				lo, hi = hi, lo
			}
			b.WriteString(lo.String() + " - " + hi.String())
		case 3:
			b.WriteString(g.set())
		case 4:
			b.WriteByte('.')
		default:
			b.WriteString(g.as().String())
		}
	}
	b.WriteByte(']')
	return b.String()
}

func (g *Gen) quant(sameAS bool) string {
	same := ""
	if sameAS {
		same = "~"
	}
	switch g.r.IntN(7) {
	case 0:
		return same + "*"
	case 1:
		return same + "+"
	case 2:
		if same == "" {
			return "?"
		}
		return same + "*" // "~?" is not RFC 2622 syntax
	}
	lo := g.count(0)
	switch g.r.IntN(3) {
	case 0:
		return same + "{" + strconv.Itoa(lo) + "}"
	case 1:
		return same + "{" + strconv.Itoa(lo) + ",}"
	default:
		return same + "{" + strconv.Itoa(lo) + "," + strconv.Itoa(g.count(lo)) + "}"
	}
}

// count is a repetition count of at least lo: mostly lo to lo+4, with
// BigCounts now and then over 1000.
func (g *Gen) count(lo int) int {
	if g.BigCounts && g.r.IntN(50) == 0 {
		return max(lo, 1001+g.r.IntN(4000))
	}
	return lo + g.r.IntN(5)
}
