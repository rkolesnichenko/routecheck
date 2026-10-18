// Package reoracle is a test oracle for RFC 2622 AS-path regexps, and a seeded
// generator of random regexps and paths to run it on. Only tests import it:
// pathre's, which hold pathre.Match to it, and verdict's model test.
//
// The oracle translates a regexp into a Go regexp over a text in which every
// AS of the path is written as the token "<n>", and lets Go's regexp package
// answer. It shares no code with pathre: pathre walks end positions, this
// package compiles a Go regexp, so a bug in one shows up as a disagreement.
//
// Its reading of RFC 2622 §5.4:
//
//   - The alphabet is AS numbers; an atom matches exactly one AS. "." is any
//     AS; an AS number that AS; an as-set any AS in the set (AS-ANY, and a
//     set whose ASNSet.Any is true because it reaches AS-ANY, any AS at all;
//     a set the caller did not expand none); "[...]" any AS one of its items
//     matches, "[^...]" any AS none of them matches.
//   - "^" and "$" are the path's start and end; a regexp with neither
//     matches if it matches some contiguous part of the path.
//   - "*", "+", "?", "{m}", "{m,n}", "{m,}" repeat as in POSIX.
//   - "~*", "~+", "~{m,n}" repeat a single-AS atom with every repetition
//     the same AS: k repetitions are a run of k copies of one AS the atom
//     matches. Any other operand is refused with ErrNotSingleAS on a
//     non-empty path. The empty path holds no AS to make a run of, so there
//     every same-AS repetition, of any operand, is zero repetitions or none.
//
// Go's regexp refuses counts over 1000, so every count is clamped to L+1 for
// a path of L ASes. That keeps the answer: an operand that cannot match the
// empty sequence fits at most L times into the path, and one that can makes
// any count from L+1 up match the same parts of the path as L+1 does (the
// extra repetitions are empty ones, which can be added or dropped where one
// already is).
package reoracle

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// ErrNotSingleAS is the oracle's refusal of a same-AS repetition whose
// operand is not a single-AS atom, on a non-empty path.
var ErrNotSingleAS = errors.New("reoracle: same-AS repetition over more than one AS")

// ErrUnbound is the oracle's refusal of a regexp that still names PeerAS or
// a set template.
var ErrUnbound = errors.New("reoracle: PeerAS not bound")

// ErrTooComplex is returned when Go's regexp package cannot compile the
// translation, even with the counts clamped (nested repetitions multiply).
var ErrTooComplex = errors.New("reoracle: translation too large for Go's regexp")

// Match reports whether re matches path under the reading in the package
// comment, with sets giving the members of the as-sets re names. It refuses
// with ErrUnbound before ErrNotSingleAS, and ErrNotSingleAS before
// ErrTooComplex.
func Match(re *policy.ASPathRE, sets map[types.SetName]resolve.ASNSet, path []types.ASN) (bool, error) {
	expr, err := Translate(re, sets, path)
	if err != nil {
		return false, err
	}
	compiled, err := regexp.Compile(expr)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrTooComplex, err)
	}
	return compiled.MatchString(Tokens(path)), nil
}

// Tokens writes path as the text the translation runs on: "<n>" per AS.
func Tokens(path []types.ASN) string {
	var b strings.Builder
	for _, a := range path {
		b.WriteString(token(a))
	}
	return b.String()
}

func token(a types.ASN) string { return "<" + strconv.FormatUint(uint64(a), 10) + ">" }

// anyToken is one AS, whichever it is.
const anyToken = `<[0-9]+>`

// nothing is a Go regexp that matches no text at all.
const nothing = `[^\x00-\x{10FFFF}]`

// Translate returns the Go regexp Match runs for re on path.
func Translate(re *policy.ASPathRE, sets map[types.SetName]resolve.ASNSet, path []types.ASN) (string, error) {
	if re == nil || re.Body == nil {
		return "", errors.New("reoracle: nil regexp")
	}
	t := translator{sets: sets, n: len(path)}
	seen := map[types.ASN]bool{}
	for _, a := range path {
		if !seen[a] {
			seen[a] = true
			t.alphabet = append(t.alphabet, a)
		}
	}
	if err := t.check(re.Body); err != nil {
		return "", err
	}
	return t.tr(re.Body)
}

type translator struct {
	sets     map[types.SetName]resolve.ASNSet
	n        int         // the path's length
	alphabet []types.ASN // the path's distinct ASes, in order of first use
	notOne   bool        // a same-AS repetition over a non-single operand was seen
}

// check refuses an unbound regexp anywhere in it, then a same-AS repetition
// over an operand that is not one AS, anywhere in it, when the path is not
// empty.
func (t *translator) check(e policy.ASPathExpr) error {
	unbound := false
	var walk func(policy.ASPathExpr)
	walk = func(e policy.ASPathExpr) {
		switch x := e.(type) {
		case policy.ASPathPeerAS, policy.ASPathSetTemplate:
			unbound = true
		case policy.ASPathAlt:
			for _, a := range x.Alts {
				walk(a)
			}
		case policy.ASPathSeq:
			for _, a := range x.Terms {
				walk(a)
			}
		case policy.ASPathClass:
			for _, a := range x.Items {
				walk(a)
			}
		case policy.ASPathRepeat:
			if x.Same && !oneAS(x.Inner) {
				t.notOne = true
			}
			walk(x.Inner)
		}
	}
	walk(e)
	switch {
	case unbound:
		return ErrUnbound
	case t.notOne && t.n > 0:
		return ErrNotSingleAS
	}
	return nil
}

// oneAS reports whether e is an atom that always matches exactly one AS.
func oneAS(e policy.ASPathExpr) bool {
	switch e.(type) {
	case policy.ASPathAny, policy.ASPathASN, policy.ASPathASNRange, policy.ASPathSet, policy.ASPathClass:
		return true
	}
	return false
}

func group(s string) string { return "(?:" + s + ")" }

func (t *translator) tr(e policy.ASPathExpr) (string, error) {
	switch x := e.(type) {
	case policy.ASPathStart:
		return `^`, nil
	case policy.ASPathEnd:
		return `$`, nil
	case policy.ASPathAny:
		return anyToken, nil
	case policy.ASPathASN:
		return token(x.AS), nil
	case policy.ASPathSet:
		if isAny(x.Name) {
			return anyToken, nil
		}
		members, ok := t.sets[x.Name]
		if ok && members.Any() {
			// A set reaching AS-ANY: its List is empty, but it holds every AS.
			return anyToken, nil
		}
		if !ok || members.Len() == 0 {
			return nothing, nil
		}
		parts := make([]string, 0, members.Len())
		for _, a := range members.List() {
			parts = append(parts, token(a))
		}
		return group(strings.Join(parts, "|")), nil
	case policy.ASPathClass, policy.ASPathASNRange:
		// A class, and a range written alone, over the path's own ASes:
		// an AS the path does not hold cannot be matched anyway.
		return t.oneOf(func(a types.ASN) bool { return t.accepts(x, a) }, ""), nil
	case policy.ASPathSeq:
		var b strings.Builder
		for _, term := range x.Terms {
			s, err := t.tr(term)
			if err != nil {
				return "", err
			}
			b.WriteString(group(s))
		}
		return b.String(), nil
	case policy.ASPathAlt:
		parts := make([]string, len(x.Alts))
		for i, a := range x.Alts {
			s, err := t.tr(a)
			if err != nil {
				return "", err
			}
			parts[i] = group(s)
		}
		return group(strings.Join(parts, "|")), nil
	case policy.ASPathRepeat:
		lo, hi := bounds(x)
		count := t.count(lo, hi)
		if x.Same && t.n == 0 {
			// No AS to make a run of: zero repetitions, if they are allowed.
			if lo == 0 {
				return "", nil
			}
			return nothing, nil
		}
		if x.Same && oneAS(x.Inner) {
			// A run of one AS the atom matches, repeated as counted.
			s := t.oneOf(func(a types.ASN) bool { return t.accepts(x.Inner, a) }, count)
			if lo == 0 {
				s = group(s + "|")
			}
			return s, nil
		}
		// A plain repetition (check refused a same-AS one over a wider
		// operand on a non-empty path).
		s, err := t.tr(x.Inner)
		if err != nil {
			return "", err
		}
		return group(s) + count, nil
	}
	return "", fmt.Errorf("reoracle: unexpected regexp node %T", e)
}

// bounds are the repetition counts x allows; hi < 0 is unbounded.
func bounds(x policy.ASPathRepeat) (lo, hi int) {
	switch x.Op {
	case policy.RepeatStar:
		return 0, -1
	case policy.RepeatPlus:
		return 1, -1
	case policy.RepeatQuest:
		return 0, 1
	}
	return x.Min, x.Max
}

// count writes the quantifier {lo,hi} with both bounds clamped to n+1.
func (t *translator) count(lo, hi int) string {
	limit := t.n + 1
	lo = min(lo, limit)
	if hi < 0 {
		return "{" + strconv.Itoa(lo) + ",}"
	}
	hi = min(hi, limit)
	return "{" + strconv.Itoa(lo) + "," + strconv.Itoa(hi) + "}"
}

// oneOf is the alternation of the tokens of the path's ASes that ok accepts,
// each followed by suffix; nothing when ok accepts none of them.
func (t *translator) oneOf(ok func(types.ASN) bool, suffix string) string {
	var parts []string
	for _, a := range t.alphabet {
		if ok(a) {
			parts = append(parts, group(token(a))+suffix)
		}
	}
	if len(parts) == 0 {
		return nothing
	}
	return group(strings.Join(parts, "|"))
}

// accepts reports whether the single-AS atom e matches the AS a.
func (t *translator) accepts(e policy.ASPathExpr, a types.ASN) bool {
	switch x := e.(type) {
	case policy.ASPathAny:
		return true
	case policy.ASPathASN:
		return x.AS == a
	case policy.ASPathASNRange:
		return x.Lo <= a && a <= x.Hi
	case policy.ASPathSet:
		if isAny(x.Name) {
			return true
		}
		members, ok := t.sets[x.Name]
		return ok && members.Has(a)
	case policy.ASPathClass:
		for _, item := range x.Items {
			if t.accepts(item, a) {
				return !x.Negated
			}
		}
		return x.Negated
	}
	return false
}

func isAny(n types.SetName) bool { return strings.EqualFold(n.String(), "AS-ANY") }
