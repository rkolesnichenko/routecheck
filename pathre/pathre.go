package pathre

import (
	"errors"
	"fmt"
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
// every same-AS repetition matches zero repetitions only, and Match answers.
var ErrNotSingleAS = errors.New("pathre: same-AS repetition over more than one AS")

// ErrUnbound is returned for a regexp that still names PeerAS or an as-set
// template: bind it to the peer first (policy.ASPathRE.Bind).
var ErrUnbound = errors.New("pathre: PeerAS not bound")

// ErrTooExpensive is returned when matching would take more work than
// MatchOptions.MaxWork allows. The regexp is neither matched nor refused on
// its merits: the answer is unknown.
var ErrTooExpensive = errors.New("pathre: regexp too expensive for this path")

// DefaultMaxWork is the work budget Match uses (see MatchOptions.MaxWork):
// tens of milliseconds of matching and some tens of megabytes allocated. It
// is about 19 times the most any regexp needed among rpsl's routemodel
// vectors, RFC 2622's examples and 40,000 regexps drawn by
// internal/reoracle's generator over paths of up to 255 ASes
// (TestDefaultMaxWorkCovers).
const DefaultMaxWork = 10_000_000

// MatchOptions are MatchWith's options. The zero value gives Match.
type MatchOptions struct {
	// MaxWork bounds the work of one match, in steps. A step is one 64-bit
	// word of a position set (a bitmap of the path's positions) allocated,
	// read or written; one AS tested against one item of an atom; or one
	// node of the regexp compiled. Time and allocated bytes each grow at
	// most in proportion to the steps taken. Past MaxWork steps MatchWith
	// stops and returns ErrTooExpensive. 0 or less means DefaultMaxWork.
	MaxWork int
}

// Match reports whether re matches some contiguous part of path, under RFC
// 2622 §5.4. sets gives the members of every as-set re names (AS-ANY is
// absent and matches any AS). A set whose ASNSet.Any is true, one that
// reaches AS-ANY, matches any AS: Match asks only its Has, true for every
// AS. re's PeerAS must already be bound.
//
// An as-set re names that is not in sets matches no AS (its absence is
// already among the expansion's missing sets). Match returns ErrUnbound for
// an unbound regexp, before ErrNotSingleAS for a same-AS repetition over a
// wider operand on a non-empty path, before ErrTooExpensive for a match
// that needs more than DefaultMaxWork steps.
func Match(re *policy.ASPathRE, sets map[types.SetName]resolve.ASNSet, path []types.ASN) (bool, error) {
	return MatchWith(re, sets, path, MatchOptions{})
}

// MatchWith is Match with options: o.MaxWork bounds its work.
func MatchWith(re *policy.ASPathRE, sets map[types.SetName]resolve.ASNSet, path []types.ASN, o MatchOptions) (bool, error) {
	ok, _, err := match(re, sets, path, o)
	return ok, err
}

// match is MatchWith that also returns the steps taken.
func match(re *policy.ASPathRE, sets map[types.SetName]resolve.ASNSet, path []types.ASN, o MatchOptions) (bool, int, error) {
	if re == nil || re.Body == nil {
		return false, 0, errors.New("pathre: nil regexp")
	}
	c := compiler{sets: sets}
	root, err := c.compile(re.Body)
	if err != nil {
		return false, 0, err
	}
	switch {
	case c.unbound:
		return false, 0, ErrUnbound
	case c.notOne && len(path) > 0:
		return false, 0, ErrNotSingleAS
	}
	budget := o.MaxWork
	if budget <= 0 {
		budget = DefaultMaxWork
	}
	m := &matcher{nodes: c.nodes, path: path, n: len(path), words: len(path)/64 + 1,
		budget: budget, masks: make([]set, len(c.nodes))}
	m.charge(len(c.nodes))
	// Every position is a start: the regexp matches some contiguous part of
	// the path when a match from some position ends anywhere.
	all := m.newSet()
	for i := 0; i <= m.n; i++ {
		all.add(i)
	}
	found := !m.empty(m.eval(root, all))
	if m.over {
		return false, m.work, ErrTooExpensive
	}
	return found, m.work, nil
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
	cost     int // the steps one call of accept is charged: its items
	// width is the fewest ASes a match consumes, capped at maxWidth: a node
	// is not tried where fewer ASes are left.
	width int
}

// maxWidth caps node.width and node.cost, so that neither can overflow.
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
			if accept, cost, ok, err := c.atom(x.Inner); err != nil {
				return 0, err
			} else if ok {
				return c.add(node{kind: kindRun, min: lo, max: hi, accept: accept, cost: cost, width: min(lo, maxWidth)}), nil
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
			return c.add(node{kind: kindRun, min: lo, max: hi, accept: never, cost: 1, width: min(lo, maxWidth)}), nil
		}
		kid, err := c.compile(x.Inner)
		if err != nil {
			return 0, err
		}
		return c.add(node{kind: kindRepeat, kids: []int{kid}, min: lo, max: hi, width: times(lo, c.nodes[kid].width)}), nil
	}
	accept, cost, ok, err := c.atom(e)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, fmt.Errorf("pathre: unexpected regexp node %T", e)
	}
	return c.add(node{kind: kindAtom, accept: accept, cost: cost, width: 1}), nil
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

// atom returns the test of a single-AS atom and the steps one test is
// charged (1, or 1 plus a class's items' own), and ok false when e is not
// one. PeerAS and a set template are atoms that mark the regexp unbound.
func (c *compiler) atom(e policy.ASPathExpr) (accept func(types.ASN) bool, cost int, ok bool, err error) {
	switch x := e.(type) {
	case policy.ASPathAny:
		return func(types.ASN) bool { return true }, 1, true, nil
	case policy.ASPathASN:
		return func(a types.ASN) bool { return a == x.AS }, 1, true, nil
	case policy.ASPathASNRange:
		return func(a types.ASN) bool { return x.Lo <= a && a <= x.Hi }, 1, true, nil
	case policy.ASPathSet:
		if strings.EqualFold(x.Name.String(), "AS-ANY") {
			return func(types.ASN) bool { return true }, 1, true, nil
		}
		members, found := c.sets[x.Name]
		if !found {
			return func(types.ASN) bool { return false }, 1, true, nil
		}
		return members.Has, 1, true, nil
	case policy.ASPathPeerAS, policy.ASPathSetTemplate:
		c.unbound = true
		return func(types.ASN) bool { return false }, 1, true, nil
	case policy.ASPathClass:
		items := make([]func(types.ASN) bool, len(x.Items))
		cost = 1
		for i, it := range x.Items {
			f, itemCost, isAtom, err := c.atom(it)
			if err != nil {
				return nil, 0, false, err
			}
			if !isAtom {
				return nil, 0, false, fmt.Errorf("pathre: unexpected %T in an AS-path class", it)
			}
			items[i] = f
			cost = min(cost+itemCost, maxWidth)
		}
		negated := x.Negated
		return func(a types.ASN) bool {
			for _, f := range items {
				if f(a) {
					return !negated
				}
			}
			return negated
		}, cost, true, nil
	}
	return nil, 0, false, nil
}

// matcher evaluates a compiled regexp on one path. Positions are 0 to n:
// position i is before path[i], n is after the last AS.
//
// It evaluates a node on a set of start positions at once: eval(id, S) is
// the set of positions a match of node id from some position in S can end
// at. That is the union, over S, of the ends from each start alone, since
// a match from one start never depends on another; so the unanchored
// search is one evaluation of the root from every position.
type matcher struct {
	nodes  []node
	path   []types.ASN
	n      int
	words  int   // uint64 words in a position set
	masks  []set // masks[id]: the positions whose AS atom id accepts; nil until needed
	same   set   // the positions p, 0 < p < n, with path[p] == path[p-1]; nil until needed
	budget int
	work   int
	over   bool // work passed budget: every result since is meaningless
}

// charge records k steps.
func (m *matcher) charge(k int) {
	m.work += k
	if m.work > m.budget {
		m.over = true
	}
}

// eval returns the ends of node id's matches from the starts in in. It
// recurses as deep as the regexp is. The result may be shared: callers
// modify only a set they made.
func (m *matcher) eval(id int, in set) set {
	nd := &m.nodes[id]
	if m.over || nd.width > m.n {
		return m.newSet()
	}
	if nd.width > 0 {
		// A match needs width ASes: drop the starts with fewer left.
		in = m.upTo(in, m.n-nd.width)
	}
	if m.empty(in) {
		return in
	}
	switch nd.kind {
	case kindAtom:
		return m.shift(m.and(in, m.mask(id)))
	case kindStart, kindEnd:
		at := 0
		if nd.kind == kindEnd {
			at = m.n
		}
		out := m.newSet()
		if in.has(at) {
			out.add(at)
		}
		return out
	case kindSeq:
		cur := in
		for _, kid := range nd.kids {
			if cur = m.eval(kid, cur); m.empty(cur) {
				break
			}
		}
		return cur
	case kindAlt:
		out := m.newSet()
		for _, kid := range nd.kids {
			m.orInto(out, m.eval(kid, in))
		}
		return out
	case kindRun:
		return m.run(id, in)
	case kindRepeat:
		return m.repeat(nd, in)
	}
	return m.newSet()
}

// run is a same-AS repetition of an atom: k repetitions are a run of k
// copies of one AS the atom accepts, for k from min to max. A(k), the ends
// of such runs of k ASes from in, is the position after an accepted AS for
// k = 1, and A(k) followed by an AS equal to the one before it for k + 1.
func (m *matcher) run(id int, in set) set {
	nd := &m.nodes[id]
	out := m.newSet()
	if nd.min == 0 {
		m.orInto(out, in)
	}
	hi := nd.max
	if hi < 0 || hi > m.n {
		hi = m.n
	}
	a := m.shift(m.and(in, m.mask(id)))
	for k := 1; k <= hi && !m.over && !m.empty(a); k++ {
		if k >= nd.min {
			m.orInto(out, a)
		}
		a = m.shift(m.and(a, m.sameMask()))
	}
	return out
}

// repeat is a plain repetition, kids[0] from min to max times.
//
// Let S(k) be the ends of k repetitions from in: S(0) = in, S(k+1) =
// eval(kid, S(k)). From one start, a match of k > n+1 repetitions spans at
// most n ASes, so at least two of them are empty; one empty repetition can
// be dropped or another added beside it, so S(k) = S(n+1) for every
// k ≥ n+1. The counts are therefore clamped to n+1, and when the upper one
// reaches n+1 the union is everything reachable from S(min) by further
// repetitions: a closure, which a position joins once. Since S(k+1)
// depends on S(k) alone, the loops also stop as soon as S(k) is empty or
// equals S(k-1).
func (m *matcher) repeat(nd *node, in set) set {
	kid := nd.kids[0]
	limit := m.n + 1
	lo, hi := min(nd.min, limit), nd.max
	if hi < 0 || hi > limit {
		hi = limit
	}
	if hi < lo {
		return m.newSet()
	}
	cur := in
	for k := 0; k < lo && !m.over; k++ {
		next := m.eval(kid, cur)
		if m.empty(next) {
			return next
		}
		if m.equal(next, cur) { // S(j) = S(k) for every j ≥ k
			break
		}
		cur = next
	}
	out := m.clone(cur)
	if hi == limit {
		// The closure: add what one more repetition reaches from the
		// positions added last, until nothing new is reached.
		frontier := cur
		for !m.over {
			fresh := m.andNot(m.eval(kid, frontier), out)
			if m.empty(fresh) {
				break
			}
			m.orInto(out, fresh)
			frontier = fresh
		}
		return out
	}
	for k := lo; k < hi && !m.over; k++ {
		next := m.eval(kid, cur)
		if m.empty(next) || m.equal(next, cur) {
			break
		}
		m.orInto(out, next)
		cur = next
	}
	return out
}

// mask returns the positions whose AS node id's atom accepts.
func (m *matcher) mask(id int) set {
	if m.masks[id] == nil {
		nd := &m.nodes[id]
		s := m.newSet()
		m.charge(times(m.n, nd.cost))
		if m.over {
			return s
		}
		for i, a := range m.path {
			if nd.accept(a) {
				s.add(i)
			}
		}
		m.masks[id] = s
	}
	return m.masks[id]
}

// sameMask returns the positions p, 0 < p < n, with path[p] == path[p-1].
func (m *matcher) sameMask() set {
	if m.same == nil {
		m.same = m.newSet()
		m.charge(m.n)
		for i := 1; i < m.n; i++ {
			if m.path[i] == m.path[i-1] {
				m.same.add(i)
			}
		}
	}
	return m.same
}

// set is a set of positions 0 to n, as a bitmap; bits past n are zero.
type set []uint64

func (s set) add(i int)      { s[i>>6] |= 1 << (uint(i) & 63) }
func (s set) has(i int) bool { return s[i>>6]&(1<<(uint(i)&63)) != 0 }

// keepTo clears the bits past p in s, for 0 ≤ p.
func (s set) keepTo(p int) {
	w := p >> 6
	if w >= len(s) {
		return
	}
	s[w] &= 2<<(uint(p)&63) - 1 // all ones when p&63 == 63
	clear(s[w+1:])
}

func (m *matcher) newSet() set {
	m.charge(m.words)
	return make(set, m.words)
}

func (m *matcher) clone(s set) set {
	m.charge(m.words)
	return append(set(nil), s...)
}

func (m *matcher) empty(s set) bool {
	m.charge(m.words)
	for _, w := range s {
		if w != 0 {
			return false
		}
	}
	return true
}

func (m *matcher) equal(s, t set) bool {
	m.charge(m.words)
	for w := range s {
		if s[w] != t[w] {
			return false
		}
	}
	return true
}

// orInto adds t's positions to s, a set the caller made.
func (m *matcher) orInto(s, t set) {
	m.charge(m.words)
	for w := range s {
		s[w] |= t[w]
	}
}

func (m *matcher) and(s, t set) set {
	out := m.newSet()
	m.charge(m.words)
	for w := range out {
		out[w] = s[w] & t[w]
	}
	return out
}

func (m *matcher) andNot(s, t set) set {
	out := m.newSet()
	m.charge(m.words)
	for w := range out {
		out[w] = s[w] &^ t[w]
	}
	return out
}

// shift returns s with every position moved on by one; one moved past n is
// dropped.
func (m *matcher) shift(s set) set {
	out := m.newSet()
	m.charge(m.words)
	var carry uint64
	for w := range out {
		out[w] = s[w]<<1 | carry
		carry = s[w] >> 63
	}
	out.keepTo(m.n)
	return out
}

// upTo returns s without the positions past p (0 <= p).
func (m *matcher) upTo(s set, p int) set {
	if p >= m.n {
		return s
	}
	out := m.clone(s)
	out.keepTo(p)
	return out
}
