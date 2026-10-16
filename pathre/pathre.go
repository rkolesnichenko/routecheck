package pathre

import (
	"errors"
	"fmt"
	"math/bits"
	"strings"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// ErrNotSingleAS is returned for a same-AS repetition ("~*", "~+",
// "~{m,n}") whose operand is not a single-AS atom (an AS, ".", a class, an
// as-set): k repetitions are a run of k copies of one AS the operand
// accepts, which has a meaning only when the operand is one AS. It is
// returned wherever in the regexp such a repetition is, but only for a
// non-empty path: the empty path holds no AS to make a run of, so there
// every same-AS repetition matches zero repetitions only, and Match answers
// (as rpsl's routemodel does).
var ErrNotSingleAS = errors.New("pathre: same-AS repetition over more than one AS")

// ErrUnbound is returned for a regexp that still names PeerAS or an as-set
// template: bind it to the peer first (policy.ASPathRE.Bind).
var ErrUnbound = errors.New("pathre: PeerAS not bound")

// Match reports whether re matches some contiguous part of path, under RFC
// 2622 §5.4. sets gives the members of every as-set re names (AS-ANY is
// absent and matches any AS). re's PeerAS must already be bound.
//
// An as-set re names that is not in sets matches no AS (its absence is
// already among the expansion's missing sets). Match returns ErrUnbound for
// an unbound regexp, before ErrNotSingleAS for a same-AS repetition over a
// wider operand on a non-empty path.
func Match(re *policy.ASPathRE, sets map[types.SetName]resolve.ASNSet, path []types.ASN) (bool, error) {
	if re == nil || re.Body == nil {
		return false, errors.New("pathre: nil regexp")
	}
	c := compiler{sets: sets}
	root, err := c.compile(re.Body)
	if err != nil {
		return false, err
	}
	switch {
	case c.unbound:
		return false, ErrUnbound
	case c.notOne && len(path) > 0:
		return false, ErrNotSingleAS
	}
	m := newMatcher(c.nodes, path)
	for start := 0; start <= len(path); start++ {
		if !m.ends(root, start).empty() {
			return true, nil
		}
	}
	return false, nil
}

// kind is a compiled node's kind.
type kind uint8

const (
	kindAtom   kind = iota // one AS that accept accepts
	kindStart              // "^": zero-width, at position 0
	kindEnd                // "$": zero-width, at len(path)
	kindSeq                // kids in turn
	kindAlt                // any of kids
	kindRepeat             // kids[0], min to max times (max < 0: unbounded)
	kindRun                // a run of one AS that accept accepts, min to max long
)

// node is one node of a compiled regexp; kids index the compiler's nodes.
type node struct {
	kind     kind
	kids     []int
	min, max int
	accept   func(types.ASN) bool
	// width is the fewest ASes a match consumes, capped at maxWidth: a node
	// is not tried where fewer ASes are left.
	width int
}

// maxWidth caps node.width, so that a large count cannot overflow it.
const maxWidth = 1 << 30

// times is n×w, capped at maxWidth.
func times(n, w int) int {
	if n > 0 && w > maxWidth/n {
		return maxWidth
	}
	return min(n*w, maxWidth)
}

type compiler struct {
	sets    map[types.SetName]resolve.ASNSet
	nodes   []node
	unbound bool // PeerAS or a set template is left in the regexp
	notOne  bool // a same-AS repetition has an operand wider than one AS
}

func (c *compiler) add(n node) int {
	c.nodes = append(c.nodes, n)
	return len(c.nodes) - 1
}

// compile adds e's nodes and returns e's index. It recurses as deep as e is.
func (c *compiler) compile(e policy.ASPathExpr) (int, error) {
	switch x := e.(type) {
	case policy.ASPathStart:
		return c.add(node{kind: kindStart}), nil
	case policy.ASPathEnd:
		return c.add(node{kind: kindEnd}), nil
	case policy.ASPathSeq, policy.ASPathAlt:
		k, terms := kindSeq, []policy.ASPathExpr(nil)
		if s, ok := x.(policy.ASPathSeq); ok {
			terms = s.Terms
		} else {
			k, terms = kindAlt, x.(policy.ASPathAlt).Alts
		}
		kids := make([]int, len(terms))
		width := 0
		if k == kindAlt {
			width = maxWidth // an empty alternation matches nothing
		}
		for i, t := range terms {
			kid, err := c.compile(t)
			if err != nil {
				return 0, err
			}
			kids[i] = kid
			if w := c.nodes[kid].width; k == kindSeq {
				width = min(width+w, maxWidth)
			} else {
				width = min(width, w)
			}
		}
		return c.add(node{kind: k, kids: kids, width: width}), nil
	case policy.ASPathRepeat:
		lo, hi := counts(x)
		if x.Same {
			if accept, ok, err := c.atom(x.Inner); err != nil {
				return 0, err
			} else if ok {
				return c.add(node{kind: kindRun, min: lo, max: hi, accept: accept, width: min(lo, maxWidth)}), nil
			}
			// Refused on a non-empty path. On the empty one, k ≥ 1
			// repetitions would be a run of k copies of one AS and there is
			// none, so only zero repetitions match: a run of an atom that
			// accepts no AS. The operand is still compiled, so that PeerAS
			// in it, or a wider same-AS repetition, is found.
			c.notOne = true
			if _, err := c.compile(x.Inner); err != nil {
				return 0, err
			}
			never := func(types.ASN) bool { return false }
			return c.add(node{kind: kindRun, min: lo, max: hi, accept: never, width: min(lo, maxWidth)}), nil
		}
		kid, err := c.compile(x.Inner)
		if err != nil {
			return 0, err
		}
		return c.add(node{kind: kindRepeat, kids: []int{kid}, min: lo, max: hi, width: times(lo, c.nodes[kid].width)}), nil
	}
	accept, ok, err := c.atom(e)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, fmt.Errorf("pathre: unexpected regexp node %T", e)
	}
	return c.add(node{kind: kindAtom, accept: accept, width: 1}), nil
}

// counts are the repetition counts x allows; hi < 0 is unbounded.
func counts(x policy.ASPathRepeat) (lo, hi int) {
	switch x.Op {
	case policy.RepeatStar:
		return 0, -1
	case policy.RepeatPlus:
		return 1, -1
	case policy.RepeatQuest:
		return 0, 1
	}
	lo, hi = max(x.Min, 0), x.Max
	if hi < 0 {
		hi = -1
	}
	return lo, hi
}

// atom returns the test of a single-AS atom, and ok false when e is not one.
// PeerAS and a set template are atoms that mark the regexp unbound.
func (c *compiler) atom(e policy.ASPathExpr) (accept func(types.ASN) bool, ok bool, err error) {
	switch x := e.(type) {
	case policy.ASPathAny:
		return func(types.ASN) bool { return true }, true, nil
	case policy.ASPathASN:
		return func(a types.ASN) bool { return a == x.AS }, true, nil
	case policy.ASPathASNRange:
		return func(a types.ASN) bool { return x.Lo <= a && a <= x.Hi }, true, nil
	case policy.ASPathSet:
		if strings.EqualFold(x.Name.String(), "AS-ANY") {
			return func(types.ASN) bool { return true }, true, nil
		}
		members, found := c.sets[x.Name]
		if !found {
			return func(types.ASN) bool { return false }, true, nil
		}
		return members.Has, true, nil
	case policy.ASPathPeerAS, policy.ASPathSetTemplate:
		c.unbound = true
		return func(types.ASN) bool { return false }, true, nil
	case policy.ASPathClass:
		items := make([]func(types.ASN) bool, len(x.Items))
		for i, it := range x.Items {
			f, isAtom, err := c.atom(it)
			if err != nil {
				return nil, false, err
			}
			if !isAtom {
				return nil, false, fmt.Errorf("pathre: unexpected %T in an AS-path class", it)
			}
			items[i] = f
		}
		negated := x.Negated
		return func(a types.ASN) bool {
			for _, f := range items {
				if f(a) {
					return !negated
				}
			}
			return negated
		}, true, nil
	}
	return nil, false, nil
}

// matcher evaluates a compiled regexp on one path. Positions are 0 to n:
// position i is before path[i], n is after the last AS.
type matcher struct {
	nodes []node
	path  []types.ASN
	n     int
	words int     // uint64 words in a position set
	memo  [][]set // memo[node][start]: the end positions, nil until computed
	run   []int   // run[i]: how many ASes from path[i] on equal path[i]
	none  set     // the empty set, shared; never modified
}

func newMatcher(nodes []node, path []types.ASN) *matcher {
	n := len(path)
	m := &matcher{nodes: nodes, path: path, n: n, words: n/64 + 1, memo: make([][]set, len(nodes))}
	m.none = m.newSet()
	m.run = make([]int, n)
	for i := n - 1; i >= 0; i-- {
		m.run[i] = 1
		if i+1 < n && path[i+1] == path[i] {
			m.run[i] = m.run[i+1] + 1
		}
	}
	return m
}

// ends returns the positions a match of node id that starts at position i
// can end at. The result is memoized and shared: callers must not modify it.
func (m *matcher) ends(id, i int) set {
	if m.memo[id] == nil {
		m.memo[id] = make([]set, m.n+1)
	}
	if s := m.memo[id][i]; s != nil {
		return s
	}
	s := m.compute(id, i)
	m.memo[id][i] = s
	return s
}

func (m *matcher) compute(id, i int) set {
	nd := &m.nodes[id]
	if nd.width > m.n-i {
		return m.none
	}
	switch nd.kind {
	case kindAtom:
		if i < m.n && nd.accept(m.path[i]) {
			return m.single(i + 1)
		}
		return m.none
	case kindStart:
		if i == 0 {
			return m.single(i)
		}
		return m.none
	case kindEnd:
		if i == m.n {
			return m.single(i)
		}
		return m.none
	case kindSeq:
		cur := m.single(i)
		for _, kid := range nd.kids {
			cur = m.step(kid, cur)
			if cur.empty() {
				break
			}
		}
		return cur
	case kindAlt:
		out := m.newSet()
		for _, kid := range nd.kids {
			out.or(m.ends(kid, i))
		}
		return out
	case kindRun:
		return m.runEnds(nd, i)
	case kindRepeat:
		return m.repeatEnds(nd, i)
	}
	return m.none
}

// runEnds is a same-AS repetition of an atom: k repetitions are a run of k
// copies of one AS the atom accepts, for k from nd.min to nd.max.
func (m *matcher) runEnds(nd *node, i int) set {
	out := m.newSet()
	if nd.min == 0 {
		out.add(i)
	}
	if i < m.n && nd.accept(m.path[i]) {
		longest := m.run[i]
		if nd.max >= 0 {
			longest = min(longest, nd.max)
		}
		for k := max(nd.min, 1); k <= longest; k++ {
			out.add(i + k)
		}
	}
	return out
}

// repeatEnds is a plain repetition, kids[0] from nd.min to nd.max times.
//
// Let S(k) be the ends of k repetitions from i: S(0) = {i}, S(k+1) = the
// ends of one more from each position in S(k). A match of k > n+1
// repetitions spans at most n ASes, so at least two of them are empty; one
// empty repetition can be dropped or another added beside it, so S(k) =
// S(n+1) for every k ≥ n+1. The counts are therefore clamped to n+1, and
// when the upper one reaches n+1 the union is everything reachable from
// S(min) by any number of further repetitions, a closure each position joins
// once. The loop also stops as soon as S(k) is empty or equals S(k-1).
func (m *matcher) repeatEnds(nd *node, i int) set {
	kid := nd.kids[0]
	limit := m.n + 1
	lo, hi := min(nd.min, limit), nd.max
	if hi < 0 || hi > limit {
		hi = limit
	}
	if hi < lo {
		return m.none
	}
	cur := m.single(i)
	k := 0
	for ; k < lo; k++ {
		next := m.step(kid, cur)
		if next.empty() {
			return m.none
		}
		if next.equal(cur) { // S(j) = S(k) for every j ≥ k
			k = lo
			break
		}
		cur = next
	}
	if hi == limit {
		return m.closure(kid, cur)
	}
	out := cur.clone()
	for ; k < hi; k++ {
		next := m.step(kid, cur)
		if next.empty() || next.equal(cur) {
			break
		}
		out.or(next)
		cur = next
	}
	return out
}

// step returns the ends of one match of kid from each position in from.
func (m *matcher) step(kid int, from set) set {
	out := m.newSet()
	from.each(func(p int) { out.or(m.ends(kid, p)) })
	return out
}

// closure returns from with every position reachable from it by any number
// of matches of kid.
func (m *matcher) closure(kid int, from set) set {
	out := from.clone()
	work := make([]int, 0, m.n+1)
	from.each(func(p int) { work = append(work, p) })
	for len(work) > 0 {
		p := work[len(work)-1]
		work = work[:len(work)-1]
		m.ends(kid, p).each(func(q int) {
			if !out.has(q) {
				out.add(q)
				work = append(work, q)
			}
		})
	}
	return out
}

// set is a set of positions 0 to n, as a bitmap.
type set []uint64

func (m *matcher) newSet() set { return make(set, m.words) }

func (m *matcher) single(i int) set {
	s := m.newSet()
	s.add(i)
	return s
}

func (s set) add(i int)      { s[i>>6] |= 1 << (uint(i) & 63) }
func (s set) has(i int) bool { return s[i>>6]&(1<<(uint(i)&63)) != 0 }

func (s set) or(t set) {
	for w := range s {
		s[w] |= t[w]
	}
}

func (s set) clone() set { return append(set(nil), s...) }

func (s set) empty() bool {
	for _, w := range s {
		if w != 0 {
			return false
		}
	}
	return true
}

func (s set) equal(t set) bool {
	for w := range s {
		if s[w] != t[w] {
			return false
		}
	}
	return true
}

func (s set) each(fn func(int)) {
	for w, word := range s {
		for word != 0 {
			fn(w<<6 + bits.TrailingZeros64(word))
			word &= word - 1
		}
	}
}
