package verdict

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"sync"

	"github.com/rkolesnichenko/routecheck/pathre"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

// Route is one route as X announced it (spec §6.1).
type Route struct {
	Prefix      netip.Prefix
	Path        []types.ASN // X first, origin last; AS_SEQUENCE segments only
	PathKnown   bool        // false: the path had an AS_SET, a confederation segment or AS_TRANS
	OriginSet   bool        // the path's last segment was an AS_SET; Path's last AS is not the origin (for hygiene; Decide does not read it)
	Communities []uint32    // RFC 1997 standard communities
	CommsKnown  bool        // false in collector mode
}

// Outcome is what a policy does with a route.
type Outcome uint8

// The outcomes. The zero Outcome is none of them.
const (
	Accepted Outcome = iota + 1
	Rejected
	Undecided
)

// String returns "accepted", "rejected" or "undecided", or "Outcome(n)" for
// any other value.
func (o Outcome) String() string {
	switch o {
	case Accepted:
		return "accepted"
	case Rejected:
		return "rejected"
	case Undecided:
		return "undecided"
	}
	return "Outcome(" + strconv.Itoa(int(o)) + ")"
}

// MarshalText writes o as String does, so that JSON names it.
func (o Outcome) MarshalText() ([]byte, error) { return []byte(o.String()), nil }

// Verdict is a route's outcome against a policy, with what decided it. A
// clause is named by its position in Policy.Clauses (Pos), not by its
// peval Index: one attribute with REFINE or EXCEPT flattens to several
// clauses of one Index.
type Verdict struct {
	Outcome          Outcome
	Clause           int   // Accepted: Pos of the first clause that said yes
	EarlierUndecided []int // Accepted: Pos of undecided clauses before it
	// AnySets is, for Accepted, the canonical names (types.SetName.String),
	// sorted and deduplicated, of the sets reaching AS-ANY (in an AS-path
	// regexp: any one AS) that the AS-path tests, either polarity, of the
	// conjunct that accepted the route name; nil when there are none, and
	// for Rejected and Undecided.
	AnySets []string
	Fails   []Fail // Rejected: one per clause, in order
	// Reasons is, for Undecided, every reason, deduplicated. For Accepted it
	// is the ReasonPeval reasons of the undecided terms at or before the
	// accepting clause (Index at most its Index: within one attribute peval
	// does not record which flattened term came first, so an equal Index is
	// listed), each of which the route may take, and so its actions,
	// instead; nil when there are none.
	Reasons []Reason
}

// Fail is why one clause said no to a route.
type Fail struct {
	Clause int // Pos in Policy.Clauses
	// Test is the first test that said no, as filter text: of the clause's
	// first conjunct, its tests read in the order prefix (FailPrefixNotIn),
	// NOT prefix (FailPrefixInNot), AS-path regexps ("<^ AS1 .* $>") and
	// community tests ("community(65000:100)", "community == {…}"), each
	// as rpsl renders it and with "NOT " before a negated one. A clause
	// whose filter has no conjunct is FailNoConjunct. The text holds nothing
	// of the route, so routes group by it.
	Test string
	// Missing lists the sets the clause's filter could not find (D4: a
	// route rejected because a set is missing reads as such). It is shared
	// by every verdict of the clause: do not modify it.
	Missing []types.SetRef
}

// The prefix tests' Fail.Test texts, and the text for a clause whose filter
// has no conjunct (such as one naming only a missing set).
const (
	FailPrefixNotIn = "prefix not in filter"
	FailPrefixInNot = "prefix in NOT"
	FailNoConjunct  = "filter matches nothing"
)

// Reason is one reason a route is Undecided.
type Reason struct {
	Kind string // one of the Reason* constants
	// Why is, for ReasonPeval, peval's Undecided.Why as given (a peval Why*
	// constant, possibly with a suffix: WhyProtocol and WhyInto add the
	// protocol); for ReasonUnevaluable, the text of the error peval
	// returned; empty otherwise.
	Why string
	// Clause is a filter reason's Pos in Policy.Clauses; -1 for ReasonPeval
	// and ReasonUnevaluable.
	Clause int
	// Index is the attribute's position (peval's Clause.Index or
	// Undecided.Index); -1 for ReasonUnevaluable.
	Index int
	// Term is, for a filter reason, the undecided test's text (as
	// Fail.Test); for ReasonPeval, the undecided term (policy.Term.String),
	// or empty for an attribute peval skipped whole; empty for
	// ReasonUnevaluable.
	Term string
}

// The reason kinds, Reason.Kind. They are stable, for a consumer to compare.
const (
	// ReasonPathNotSequence: an AS-path test, and the route's path had an
	// AS_SET, a confederation segment or AS_TRANS (Route.PathKnown false).
	ReasonPathNotSequence = "path-not-sequence"
	// ReasonCommsUnknown: a community test, and the route's communities are
	// not known (Route.CommsKnown false: collector mode).
	ReasonCommsUnknown = "communities-unknown"
	// ReasonCommInternet: a community test names internet, which RFC 2622
	// gives no value.
	ReasonCommInternet = "community-internet"
	// ReasonCommValue: a community test names a value that is not a 4-byte
	// integer, hi:lo with halves to 65535, no_export, no_advertise,
	// local_as or no_export_subconfed.
	ReasonCommValue = "community-value"
	// ReasonSameASRun: a same-AS repetition ("~*", "~+", "~{m,n}") over
	// more than one AS (pathre.ErrNotSingleAS).
	ReasonSameASRun = "same-as-run"
	// ReasonPathTooExpensive: the regexp needs more than pathre's default
	// work budget on this path (pathre.ErrTooExpensive).
	ReasonPathTooExpensive = "path-too-expensive"
	// ReasonPathUnbound: the regexp still names PeerAS or a set template,
	// or is missing, so pathre cannot match it. peval always binds PeerAS,
	// so this is a caller's bug, reported rather than guessed past.
	ReasonPathUnbound = "path-unbound"
	// ReasonPeval: a term peval could not decide for the session
	// (Policy.Undecided); Why says why.
	ReasonPeval = "peval"
	// ReasonUnevaluable: peval could not evaluate the policy at all because
	// it names AS-ANY or RS-ANY where rpsl cannot expand it (a
	// *resolve.AnySetError), so no route of that policy is decided. Decide
	// never gives it: routecheck.Check gives it, as the only reason, to
	// every route of such a report, with Why the error's text (it names the
	// term and the set), Clause and Index -1.
	ReasonUnevaluable = "unevaluable"
)

// tri is a test's three-valued answer.
type tri uint8

const (
	no tri = iota
	yes
	undecidedT
)

// Compiled is a policy prepared for deciding many routes: each conjunct's
// prefix tests indexed, each community value read, and a memo of AS-path
// answers by (regexp, path), since many routes share a path. It is safe
// for concurrent use.
type Compiled struct {
	policy  peval.Policy
	clauses []clause
	peval   []Reason
	memo    pathMemo
}

type clause struct {
	index   int
	conj    []conj
	missing []types.SetRef
}

type conj struct {
	prefixes, not *prefixIndex
	paths         []pathTest
	comms         []commTest
	anySets       []string // Verdict.AnySets when this conjunct accepts
}

// pathTest is a compiled PathMatch.
type pathTest struct {
	negated bool
	re      *policy.ASPathRE
	sets    map[types.SetName]resolve.ASNSet
	unbound bool   // nil, or names PeerAS or a set template
	id      uint32 // the memo's name for (re, sets)
	text    string // Fail.Test and Reason.Term
}

// Compile prepares p for Decide. It builds each conjunct's prefix index
// once, here.
func Compile(p peval.Policy) *Compiled {
	c := &Compiled{policy: p, clauses: make([]clause, len(p.Clauses))}
	c.memo.limit = memoKeyBytes
	type reKey struct {
		re   *policy.ASPathRE
		sets uintptr
	}
	ids := map[reKey]uint32{}
	for pos, pc := range p.Clauses {
		cl := clause{index: pc.Index, missing: pc.Filter.Missing(), conj: make([]conj, len(pc.Filter.Conjuncts))}
		if len(cl.missing) == 0 {
			cl.missing = nil
		}
		for i, pj := range pc.Filter.Conjuncts {
			cj := conj{
				prefixes: newPrefixIndex(pj.Prefixes.List()),
				not:      newPrefixIndex(pj.NotPrefixes.List()),
			}
			for _, m := range pj.Paths {
				k := reKey{m.RE, reflect.ValueOf(m.Sets).Pointer()}
				id, ok := ids[k]
				if !ok {
					id = uint32(len(ids))
					ids[k] = id
				}
				t := pathTest{negated: m.Negated, re: m.RE, sets: m.Sets, id: id,
					unbound: m.RE == nil || m.RE.UsesPeer(), text: "<" + m.RE.String() + ">"}
				if m.Negated {
					t.text = "NOT " + t.text
				}
				cj.paths = append(cj.paths, t)
				if m.RE != nil {
					for _, name := range m.RE.SetNames() {
						if set, ok := m.Sets[name]; ok && set.Any() {
							cj.anySets = append(cj.anySets, name.String())
						}
					}
				}
			}
			slices.Sort(cj.anySets)
			cj.anySets = slices.Compact(cj.anySets)
			for _, m := range pj.Communities {
				cj.comms = append(cj.comms, compileComm(m))
			}
			cl.conj[i] = cj
		}
		c.clauses[pos] = cl
	}
	for _, u := range p.Undecided {
		c.peval = append(c.peval, Reason{Kind: ReasonPeval, Why: u.Why, Clause: -1, Index: u.Index, Term: termText(u.Term)})
	}
	return c
}

// termText renders a term, or "" for the zero term (an attribute peval
// skipped whole), which policy.Term.String would render as " | ".
func termText(t policy.Term) string {
	if t.Via == nil && t.Peering == nil && len(t.Actions) == 0 && t.Filter == nil {
		return ""
	}
	return t.String()
}

// Policy returns the policy c was compiled from.
func (c *Compiled) Policy() peval.Policy { return c.policy }

// Decide decides r against p. It holds no state; p's filters may be shared.
// It is Compile(p).Decide(r): to decide many routes, Compile once.
func Decide(p peval.Policy, r Route) Verdict { return Compile(p).Decide(r) }

// Decide decides r against c's policy (spec §6.4).
//
// Every test is three-valued. A conjunct is the AND of its tests (any no:
// no; else any undecided: undecided; else yes); a clause the OR of its
// conjuncts. Over the clauses in order, the route is Accepted by the first
// that says yes, naming the undecided clauses before it, the undecided
// terms at or before its Index (in Reasons) and the sets reaching AS-ANY
// of its first conjunct that says yes (AnySets); Rejected when every
// clause says no and the policy has no undecided term; otherwise Undecided,
// with the reasons of every undecided test of every undecided clause and
// each undecided term. A policy with no clause and no undecided term (the
// caller's "no policy" case, which gives no per-route verdicts) is
// Undecided with no reason, never Rejected.
func (c *Compiled) Decide(r Route) Verdict {
	if len(c.clauses) == 0 && len(c.peval) == 0 {
		return Verdict{Outcome: Undecided}
	}
	s := state{r: &r, prefix: r.Prefix.Masked()}
	var undecided []int
	for pos := range c.clauses {
		switch t, _, i := c.clause(pos, &s, nil); t {
		case yes:
			cl := &c.clauses[pos]
			// A copy: the verdict is the caller's, the compiled names are
			// shared by every route.
			return Verdict{Outcome: Accepted, Clause: pos, EarlierUndecided: undecided,
				AnySets: slices.Clone(cl.conj[i].anySets), Reasons: c.pevalUpTo(cl.index)}
		case undecidedT:
			undecided = append(undecided, pos)
		}
	}
	if len(undecided) == 0 && len(c.peval) == 0 {
		fails := make([]Fail, len(c.clauses))
		for pos := range c.clauses {
			_, test, _ := c.clause(pos, &s, nil)
			fails[pos] = Fail{Clause: pos, Test: test, Missing: c.clauses[pos].missing}
		}
		return Verdict{Outcome: Rejected, Fails: fails}
	}
	var reasons []Reason
	for _, pos := range undecided {
		c.clause(pos, &s, &reasons)
	}
	reasons = append(reasons, c.peval...)
	return Verdict{Outcome: Undecided, Reasons: dedup(reasons)}
}

// pevalUpTo returns the ReasonPeval reasons of the undecided terms whose
// Index is at most index, deduplicated, in a slice of the caller's own.
func (c *Compiled) pevalUpTo(index int) []Reason {
	var out []Reason
	for _, r := range c.peval {
		if r.Index <= index {
			out = append(out, r)
		}
	}
	return dedup(out)
}

// state is one Decide call's: the route, its masked prefix, and its path as
// a memo key, built on the first path test that needs it.
type state struct {
	r      *Route
	prefix netip.Prefix
	key    []byte // 4 bytes of a pathTest.id, then 4 per AS of the path
}

// clause decides clause pos. It returns the first failing test's text when
// the answer is no, the position of the first conjunct that said yes when
// the answer is yes, and appends to reasons, when given, every undecided
// test of the clause's undecided conjuncts.
func (c *Compiled) clause(pos int, s *state, reasons *[]Reason) (tri, string, int) {
	cl := &c.clauses[pos]
	if len(cl.conj) == 0 {
		return no, FailNoConjunct, -1
	}
	answer, fail := no, ""
	for i := range cl.conj {
		mark := 0
		if reasons != nil {
			mark = len(*reasons)
		}
		t, test := c.conjunct(&cl.conj[i], s, reasons, pos, cl.index)
		switch t {
		case yes:
			return yes, "", i
		case no:
			if reasons != nil {
				*reasons = (*reasons)[:mark]
			}
			if fail == "" {
				fail = test
			}
		case undecidedT:
			answer = undecidedT
		}
	}
	if answer == undecidedT {
		return undecidedT, "", -1
	}
	return no, fail, -1
}

// conjunct decides one conjunct: no at its first failing test, with that
// test's text; otherwise undecided if any test was, each such test appended
// to reasons when given.
func (c *Compiled) conjunct(cj *conj, s *state, reasons *[]Reason, pos, index int) (tri, string) {
	if !cj.prefixes.contains(s.prefix) {
		return no, FailPrefixNotIn
	}
	if cj.not.contains(s.prefix) {
		return no, FailPrefixInNot
	}
	answer := yes
	undecided := func(kind, text string) {
		answer = undecidedT
		if reasons != nil {
			*reasons = append(*reasons, Reason{Kind: kind, Clause: pos, Index: index, Term: text})
		}
	}
	for i := range cj.paths {
		pt := &cj.paths[i]
		switch t, kind := c.path(pt, s); t {
		case no:
			return no, pt.text
		case undecidedT:
			undecided(kind, pt.text)
		}
	}
	for i := range cj.comms {
		ct := &cj.comms[i]
		switch t, kind := ct.eval(s.r); t {
		case no:
			return no, ct.text
		case undecidedT:
			undecided(kind, ct.text)
		}
	}
	return answer, ""
}

// The memoized answers of pathre for one (regexp, path).
const (
	matchNo uint8 = iota
	matchYes
	matchSameASRun
	matchTooExpensive
	matchUnbound
)

// path decides one AS-path test: undecided for an unbound regexp (a
// caller's bug), a path that is not a plain sequence, or pathre declining;
// otherwise pathre's answer, flipped when negated.
func (c *Compiled) path(pt *pathTest, s *state) (tri, string) {
	if pt.unbound {
		return undecidedT, ReasonPathUnbound
	}
	if !s.r.PathKnown {
		return undecidedT, ReasonPathNotSequence
	}
	if s.key == nil {
		s.key = make([]byte, 4+4*len(s.r.Path))
		for i, as := range s.r.Path {
			binary.BigEndian.PutUint32(s.key[4+4*i:], uint32(as))
		}
	}
	binary.BigEndian.PutUint32(s.key, pt.id)
	m, ok := c.memo.get(s.key)
	if !ok {
		m = match(pt, s.r.Path)
		c.memo.put(s.key, m)
	}
	switch m {
	case matchYes, matchNo:
		if (m == matchYes) != pt.negated {
			return yes, ""
		}
		return no, ""
	case matchSameASRun:
		return undecidedT, ReasonSameASRun
	case matchTooExpensive:
		return undecidedT, ReasonPathTooExpensive
	}
	return undecidedT, ReasonPathUnbound
}

// match asks pathre, with its default work budget. An error other than
// ErrNotSingleAS and ErrTooExpensive means the regexp was not usable
// (ErrUnbound, or one pathre refuses), which Compile already catches for
// PeerAS: it is reported as ReasonPathUnbound, never as a no.
func match(pt *pathTest, path []types.ASN) uint8 {
	ok, err := pathre.MatchWith(pt.re, pt.sets, path, pathre.MatchOptions{})
	switch {
	case err == nil && ok:
		return matchYes
	case err == nil:
		return matchNo
	case errors.Is(err, pathre.ErrNotSingleAS):
		return matchSameASRun
	case errors.Is(err, pathre.ErrTooExpensive):
		return matchTooExpensive
	}
	return matchUnbound
}

// defaultMemoKeyBytes is the most key bytes (4 per AS of a path, plus 4)
// a Compiled's path memo holds: 64 MiB, some 2.8 million answers for paths
// of five ASes. Past it the memo is cleared and fills again, which changes
// no answer. Map overhead comes on top of the key bytes.
const defaultMemoKeyBytes = 64 << 20

// memoKeyBytes is the bound Compile gives a memo; tests lower it.
var memoKeyBytes = defaultMemoKeyBytes

// pathMemo holds pathre's answers by (pathTest.id, path), bounded by the
// bytes of its keys.
type pathMemo struct {
	mu    sync.Mutex
	m     map[string]uint8
	bytes int // the key bytes m holds
	limit int // the most key bytes m may hold
}

func (p *pathMemo) get(k []byte) (uint8, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	v, ok := p.m[string(k)]
	return v, ok
}

func (p *pathMemo) put(k []byte, v uint8) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.m == nil {
		p.m = map[string]uint8{}
	}
	if _, ok := p.m[string(k)]; ok {
		return // another call stored it meanwhile
	}
	if p.bytes+len(k) > p.limit {
		clear(p.m)
		p.bytes = 0
		if len(k) > p.limit {
			return // a key over the whole bound is not kept
		}
	}
	p.m[string(k)] = v
	p.bytes += len(k)
}

// memoBytes returns the key bytes c's memo holds, recounted from its keys.
func (c *Compiled) memoBytes() (counted, held int) {
	c.memo.mu.Lock()
	defer c.memo.mu.Unlock()
	for k := range c.memo.m {
		held += len(k)
	}
	return c.memo.bytes, held
}

// dedup keeps the first of each equal reason, in order.
func dedup(rs []Reason) []Reason {
	if len(rs) < 2 {
		return rs
	}
	seen := make(map[Reason]bool, len(rs))
	out := rs[:0]
	for _, r := range rs {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}
