package verdict_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/rkolesnichenko/routecheck/internal/reoracle"
	"github.com/rkolesnichenko/routecheck/verdict"
	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

// The model test holds Decide to a naive evaluator. Each seed writes a small
// registry (routes, as-sets, route-sets) and an aut-num of one to four import
// terms with random filters, has peval evaluate the aut-num's import from
// the peer in each family, and decides random routes twice: by
// verdict.Compile(p).Decide, over peval's normal form, and by the naive
// evaluator below, over each clause's filter as written (Clause.Term.Filter).
//
// The naive evaluator shares no code with package verdict (this file is in
// package verdict_test and uses only its exported API, to call Decide). It
// recurses over the unnormalized policy.Filter with Kleene's three-valued
// AND, OR and NOT; reads a prefix test from the generator's own record of
// the route objects and from the Expander's set expansions, with each range
// operator applied by types.RangeOperator.Apply; answers an AS-path test with
// oracle 2 (internal/reoracle, a Go-regexp translation, not pathre); and
// compares community values as numbers it reads itself. Its undecided cases
// are spec §6.4's and nothing else: a path test on a path that is not a plain
// sequence, or a same-AS repetition over a wider operand; a community test
// when the route's communities are not known, or a value that is internet or
// does not read. The one thing it cannot do, a translation too large for Go's
// regexp package, is not a §6.4 case: such a route is skipped and counted.

const (
	modelPolicies = 2000 // seeds; a quarter under -race
	modelRoutes   = 50   // routes per policy and family
	modelLocal    = types.ASN(64496)
	modelPeer     = reoracle.FirstAS
)

// modelSeeds returns how many seeds the model test draws from n: a quarter
// under the race detector, which slows this CPU-bound loop about fourfold
// (scripts/check.sh's coverage pass runs it again without -race, drawing
// all n), and all n otherwise.
func modelSeeds(n int) int {
	if raceEnabled {
		return max(n/4, 1)
	}
	return n
}

type modelFamily struct {
	name string
	af   types.AddrFamily
	v6   bool
}

func modelFamilies(t testing.TB) []modelFamily {
	t.Helper()
	var out []modelFamily
	for _, s := range []string{"ipv4.unicast", "ipv6.unicast"} {
		af, err := types.ParseAddrFamily(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, modelFamily{name: s, af: af, v6: strings.HasPrefix(s, "ipv6")})
	}
	return out
}

// modelStats counts what the model test compared.
type modelStats struct {
	policies, decisions, skipped, noPolicy int
	outcomes                               map[verdict.Outcome]int
	reasons                                map[string]int // Undecided verdicts' reason kinds
	earlier, pevalOnAccept                 int            // Accepted verdicts with EarlierUndecided, with Reasons
	sameIndex                              int            // Accepted verdicts naming an undecided term of the clause's own Index
}

func TestDecideModel(t *testing.T) {
	ctx := context.Background()
	fams := modelFamilies(t)
	st := modelStats{outcomes: map[verdict.Outcome]int{}, reasons: map[string]int{}}
	seeds := modelSeeds(modelPolicies)
	for seed := 0; seed < seeds; seed++ {
		g := newModelGen(uint64(seed))
		world := g.world()
		aut, expect := g.autNum()
		l := &resolve.DumpLoader{KeepPolicy: true}
		if err := l.Read(strings.NewReader(world + aut)); err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		src := l.Corpus().Source()
		ev := peval.Evaluator{Src: src}
		st.policies++
		for _, fam := range fams {
			p, err := ev.Import(ctx, peval.Session{Local: modelLocal, Peer: modelPeer, AF: fam.af})
			if err != nil {
				t.Fatalf("seed %d, %s: Import: %v\n%s", seed, fam.name, err, aut)
			}
			// A structural check of the generator's own reading of peval:
			// each written term (two in a braced attribute) is one clause
			// or one undecided term.
			if e := expect[fam.v6]; len(p.Clauses) != e.clauses || len(p.Undecided) != e.undecided {
				t.Fatalf("seed %d, %s: peval gave %d clauses and %d undecided terms, the generator expects %d and %d\n%s",
					seed, fam.name, len(p.Clauses), len(p.Undecided), e.clauses, e.undecided, aut)
			}
			if len(p.Clauses) == 0 && len(p.Undecided) == 0 {
				st.noPolicy++
			}
			nv := &naive{t: t, ctx: ctx, exp: resolve.Expander{Src: src}, routes: g.routes, memo: map[string]tri{}}
			clauses := make([]*nnode, len(p.Clauses))
			for i, c := range p.Clauses {
				clauses[i] = nv.compile(c.Term.Filter)
			}
			compiled := verdict.Compile(p)
			for range modelRoutes {
				r := g.route(fam.v6)
				want, skip := nv.decide(p, clauses, r)
				if skip {
					st.skipped++
					continue
				}
				got := compiled.Decide(r)
				st.decisions++
				st.outcomes[got.Outcome]++
				switch got.Outcome {
				case verdict.Accepted:
					if len(got.EarlierUndecided) > 0 {
						st.earlier++
					}
					if len(got.Reasons) > 0 {
						st.pevalOnAccept++
					}
					for _, rs := range got.Reasons {
						if rs.Index == p.Clauses[got.Clause].Index {
							st.sameIndex++
							break
						}
					}
				case verdict.Undecided:
					for _, rs := range got.Reasons {
						st.reasons[rs.Kind]++
					}
				}
				if msg := want.differs(got, p); msg != "" {
					t.Errorf("seed %d, %s: %s\nroute %s path %v (known %v) communities %v (known %v)\nnaive per clause %v; verdict %+v\nclauses (normal form):\n%s\naut-num:\n%s\nregistry:\n%s",
						seed, fam.name, msg, r.Prefix, r.Path, r.PathKnown, r.Communities, r.CommsKnown,
						want.answers, got, clauseTexts(p), aut, world)
					t.FailNow()
				}
			}
		}
	}
	t.Logf("%d seeds (%d policies, both families), %d decisions compared, %d skipped (oracle 2 too complex), %d (policy, family) pairs with no policy",
		seeds, st.policies, st.decisions, st.skipped, st.noPolicy)
	t.Logf("outcomes: Accepted %d (%d with EarlierUndecided, %d with peval Reasons, %d of them at the clause's own Index), Rejected %d, Undecided %d",
		st.outcomes[verdict.Accepted], st.earlier, st.pevalOnAccept, st.sameIndex, st.outcomes[verdict.Rejected], st.outcomes[verdict.Undecided])
	kinds := make([]string, 0, len(st.reasons))
	for k := range st.reasons {
		kinds = append(kinds, k)
	}
	slices.Sort(kinds)
	var b strings.Builder
	for _, k := range kinds {
		fmt.Fprintf(&b, " %s=%d", k, st.reasons[k])
	}
	t.Logf("reasons of the Undecided verdicts, by kind (an entry each):%s", b.String())

	// The generator must reach every outcome often, and the oracle's limit
	// must stay rare, or the comparison above proves little.
	for _, o := range []verdict.Outcome{verdict.Accepted, verdict.Rejected, verdict.Undecided} {
		if st.outcomes[o]*10 < st.decisions {
			t.Errorf("outcome %d in %d of %d decisions, under a tenth", o, st.outcomes[o], st.decisions)
		}
	}
	if st.skipped*100 > st.decisions {
		t.Errorf("%d routes skipped against %d decided, over 1%%", st.skipped, st.decisions)
	}
	for _, k := range []string{verdict.ReasonPathNotSequence, verdict.ReasonCommsUnknown, verdict.ReasonCommInternet,
		verdict.ReasonCommValue, verdict.ReasonSameASRun, verdict.ReasonPeval} {
		if st.reasons[k] == 0 {
			t.Errorf("no Undecided verdict gave reason %s", k)
		}
	}
	if st.earlier == 0 || st.pevalOnAccept == 0 || st.sameIndex == 0 {
		t.Errorf("Accepted with EarlierUndecided %d times, with peval Reasons %d times, at the clause's own Index %d times; want all three",
			st.earlier, st.pevalOnAccept, st.sameIndex)
	}
}

func clauseTexts(p peval.Policy) string {
	var b strings.Builder
	for i, c := range p.Clauses {
		fmt.Fprintf(&b, "  %d (index %d): %s\n      as written: %s\n", i, c.Index, c.Filter.String(), c.Term.Filter)
	}
	for _, u := range p.Undecided {
		fmt.Fprintf(&b, "  undecided (index %d): %s: %s\n", u.Index, u.Why, u.Term.String())
	}
	return b.String()
}

// tri is the naive evaluator's three-valued answer.
type tri uint8

const (
	tNo tri = iota
	tYes
	tUnd
)

func (x tri) String() string { return [...]string{"no", "yes", "undecided"}[x] }

func and3(a, b tri) tri {
	switch {
	case a == tNo || b == tNo:
		return tNo
	case a == tUnd || b == tUnd:
		return tUnd
	}
	return tYes
}

func or3(a, b tri) tri {
	switch {
	case a == tYes || b == tYes:
		return tYes
	case a == tUnd || b == tUnd:
		return tUnd
	}
	return tNo
}

func not3(a tri) tri {
	switch a {
	case tYes:
		return tNo
	case tNo:
		return tYes
	}
	return tUnd
}

// naive is the model's evaluator for one registry and session.
type naive struct {
	t      testing.TB
	ctx    context.Context
	exp    resolve.Expander
	routes map[types.ASN][]netip.Prefix // the generator's record of the route objects
	memo   map[string]tri               // path answers by regexp and path
	skip   bool                         // the current route met a translation oracle 2 cannot compile
}

type nkind uint8

const (
	nAny nkind = iota
	nPrefixes
	nPath
	nComm
	nNot
	nAnd
	nOr
)

// nnode is a filter node with its set references already expanded.
type nnode struct {
	kind   nkind
	kids   []*nnode
	ranges []types.PrefixRange // nPrefixes
	re     *policy.ASPathRE    // nPath
	sets   map[types.SetName]resolve.ASNSet
	comm   policy.FilterCommunity // nComm
}

func (n *naive) compile(f policy.Filter) *nnode {
	n.t.Helper()
	switch x := f.(type) {
	case policy.FilterAny:
		return &nnode{kind: nAny}
	case policy.FilterPrefixList:
		return &nnode{kind: nPrefixes, ranges: x.Ranges}
	case policy.FilterASExpr:
		switch a := x.AS.(type) {
		case policy.ASNum:
			return &nnode{kind: nPrefixes, ranges: n.originRanges([]types.ASN{a.AS}, x.Op)}
		case policy.ASSetRef:
			return &nnode{kind: nPrefixes, ranges: n.originRanges(n.expandAS(a.Name), x.Op)}
		}
	case policy.FilterPeerAS:
		return &nnode{kind: nPrefixes, ranges: n.originRanges([]types.ASN{modelPeer}, x.Op)}
	case policy.FilterSetRef:
		rs, err := n.exp.ExpandPrefixRanges(n.ctx, types.Ref(x.Name))
		if err != nil && !errors.Is(err, resolve.ErrNotFound) {
			n.t.Fatalf("ExpandPrefixRanges(%s): %v", x.Name, err)
		}
		return &nnode{kind: nPrefixes, ranges: applyOp(x.Op, rs.List())}
	case policy.FilterPathRE:
		re := x.Regexp
		if re == nil {
			n.t.Fatalf("regexp <%s> did not parse", x.Raw)
		}
		if re.UsesPeer() {
			re = re.Bind(modelPeer)
		}
		sets := map[types.SetName]resolve.ASNSet{}
		for _, name := range re.SetNames() {
			if strings.EqualFold(name.String(), reoracle.SetAny) {
				continue // the oracle reads AS-ANY itself
			}
			s, err := n.exp.ExpandAS(n.ctx, types.Ref(name))
			switch {
			case errors.Is(err, resolve.ErrNotFound):
				continue // a missing set matches no AS
			case err != nil:
				n.t.Fatalf("ExpandAS(%s): %v", name, err)
			}
			sets[name] = s
		}
		return &nnode{kind: nPath, re: re, sets: sets}
	case policy.FilterCommunity:
		return &nnode{kind: nComm, comm: x}
	case policy.FilterNot:
		return &nnode{kind: nNot, kids: []*nnode{n.compile(x.Inner)}}
	case policy.FilterAnd:
		nd := &nnode{kind: nAnd}
		for _, k := range x.Terms {
			nd.kids = append(nd.kids, n.compile(k))
		}
		return nd
	case policy.FilterOr:
		nd := &nnode{kind: nOr}
		for _, k := range x.Terms {
			nd.kids = append(nd.kids, n.compile(k))
		}
		return nd
	}
	n.t.Fatalf("the model does not generate %T (%v)", f, f)
	return nil
}

// expandAS returns the members of an as-set; a missing one has none.
func (n *naive) expandAS(name types.SetName) []types.ASN {
	n.t.Helper()
	s, err := n.exp.ExpandAS(n.ctx, types.Ref(name))
	if errors.Is(err, resolve.ErrNotFound) {
		return nil
	}
	if err != nil {
		n.t.Fatalf("ExpandAS(%s): %v", name, err)
	}
	return s.List()
}

// originRanges returns the routes the ASes originate, each as an exact
// range with op applied.
func (n *naive) originRanges(asns []types.ASN, op types.RangeOperator) []types.PrefixRange {
	var out []types.PrefixRange
	for _, a := range asns {
		for _, p := range n.routes[a] {
			r, ok := types.NewPrefixRange(p, p.Bits(), p.Bits())
			if !ok {
				n.t.Fatalf("NewPrefixRange(%s)", p)
			}
			out = append(out, r)
		}
	}
	return applyOp(op, out)
}

func applyOp(op types.RangeOperator, rs []types.PrefixRange) []types.PrefixRange {
	if op.IsZero() {
		return rs
	}
	var out []types.PrefixRange
	for _, r := range rs {
		if a, ok := op.Apply(r); ok {
			out = append(out, a)
		}
	}
	return out
}

func (n *naive) eval(nd *nnode, r verdict.Route) tri {
	switch nd.kind {
	case nAny:
		return tYes
	case nPrefixes:
		for _, rg := range nd.ranges {
			if rg.Contains(r.Prefix) {
				return tYes
			}
		}
		return tNo
	case nPath:
		return n.path(nd, r)
	case nComm:
		return commTest(nd.comm, r)
	case nNot:
		return not3(n.eval(nd.kids[0], r))
	case nAnd:
		out := tYes
		for _, k := range nd.kids {
			out = and3(out, n.eval(k, r))
		}
		return out
	case nOr:
		out := tNo
		for _, k := range nd.kids {
			out = or3(out, n.eval(k, r))
		}
		return out
	}
	panic("unreachable")
}

func (n *naive) path(nd *nnode, r verdict.Route) tri {
	if !r.PathKnown {
		return tUnd
	}
	key := nd.re.String() + "|" + reoracle.Tokens(r.Path)
	if v, ok := n.memo[key]; ok {
		return v
	}
	ok, err := reoracle.Match(nd.re, nd.sets, r.Path)
	var v tri
	switch {
	case err == nil && ok:
		v = tYes
	case err == nil:
		v = tNo
	case errors.Is(err, reoracle.ErrNotSingleAS):
		v = tUnd
	case errors.Is(err, reoracle.ErrTooComplex):
		n.skip = true
		return tUnd
	default:
		n.t.Fatalf("oracle 2 on <%s>, path %v: %v", nd.re, r.Path, err)
	}
	n.memo[key] = v
	return v
}

// commValue reads one community value as RFC 1997 and RFC 2622 write it:
// hi:lo with 16-bit halves, a 32-bit decimal, or a well-known name. It
// reports false for internet, which has no value, and for anything else.
func commValue(s string) (uint32, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "no_export":
		return 0xFFFFFF01, true
	case "no_advertise":
		return 0xFFFFFF02, true
	case "local_as", "no_export_subconfed":
		return 0xFFFFFF03, true
	case "internet":
		return 0, false
	}
	if hi, lo, ok := strings.Cut(s, ":"); ok {
		h, err1 := strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
		l, err2 := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
		if err1 != nil || err2 != nil {
			return 0, false
		}
		return uint32(h<<16 | l), true
	}
	v, err := strconv.ParseUint(s, 10, 32)
	return uint32(v), err == nil
}

func commTest(c policy.FilterCommunity, r verdict.Route) tri {
	want := map[uint32]bool{}
	for _, s := range c.Values {
		v, ok := commValue(s)
		if !ok {
			return tUnd
		}
		want[v] = true
	}
	if !r.CommsKnown {
		return tUnd
	}
	have := map[uint32]bool{}
	for _, v := range r.Communities {
		have[v] = true
	}
	for v := range want {
		if !have[v] {
			return tNo
		}
	}
	if c.Op == policy.CommunityEquals && len(have) != len(want) {
		return tNo
	}
	return tYes
}

// naiveVerdict is the naive evaluator's decision.
type naiveVerdict struct {
	outcome  verdict.Outcome
	clause   int
	earlier  []int
	pevalUp  int   // Accepted: undecided terms at or before the clause's Index
	noPolicy bool  // no clause and no undecided term
	answers  []tri // per clause
}

// decide applies §6.4's rules over the clauses' answers. skip reports a
// route oracle 2 could not translate.
func (n *naive) decide(p peval.Policy, clauses []*nnode, r verdict.Route) (v naiveVerdict, skip bool) {
	n.skip = false
	v.answers = make([]tri, len(clauses))
	for i, c := range clauses {
		v.answers[i] = n.eval(c, r)
	}
	if n.skip {
		return v, true
	}
	if len(clauses) == 0 && len(p.Undecided) == 0 {
		v.outcome, v.noPolicy = verdict.Undecided, true
		return v, false
	}
	undecided := len(p.Undecided) > 0
	for pos, a := range v.answers {
		switch a {
		case tYes:
			v.outcome, v.clause = verdict.Accepted, pos
			for _, u := range p.Undecided {
				if u.Index <= p.Clauses[pos].Index {
					v.pevalUp++
				}
			}
			return v, false
		case tUnd:
			v.earlier = append(v.earlier, pos)
			undecided = true
		}
	}
	v.earlier = nil
	if undecided {
		v.outcome = verdict.Undecided
	} else {
		v.outcome = verdict.Rejected
	}
	return v, false
}

// differs compares the naive decision with Decide's verdict; "" when they
// agree.
func (v naiveVerdict) differs(got verdict.Verdict, p peval.Policy) string {
	if got.Outcome != v.outcome {
		return fmt.Sprintf("outcome: naive %d, verdict %d", v.outcome, got.Outcome)
	}
	switch v.outcome {
	case verdict.Accepted:
		if got.Clause != v.clause {
			return fmt.Sprintf("accepting clause: naive %d, verdict %d", v.clause, got.Clause)
		}
		if !slices.Equal(got.EarlierUndecided, v.earlier) {
			return fmt.Sprintf("EarlierUndecided: naive %v, verdict %v", v.earlier, got.EarlierUndecided)
		}
		if len(got.Reasons) != v.pevalUp {
			return fmt.Sprintf("Accepted Reasons: naive %d peval terms, verdict %v", v.pevalUp, got.Reasons)
		}
		for _, r := range got.Reasons {
			if r.Kind != verdict.ReasonPeval {
				return fmt.Sprintf("Accepted with a %s reason", r.Kind)
			}
		}
	case verdict.Rejected:
		if len(got.Fails) != len(p.Clauses) {
			return fmt.Sprintf("Rejected with %d Fails for %d clauses", len(got.Fails), len(p.Clauses))
		}
	case verdict.Undecided:
		if v.noPolicy != (len(got.Reasons) == 0) {
			return fmt.Sprintf("no policy %v, reasons %v", v.noPolicy, got.Reasons)
		}
		for _, r := range got.Reasons {
			if r.Kind == verdict.ReasonPathTooExpensive || r.Kind == verdict.ReasonPathUnbound {
				return fmt.Sprintf("Undecided by %s, which these short paths and bound regexps never need", r.Kind)
			}
		}
	}
	return ""
}

// modelGen draws one seed's registry, aut-num and routes.
type modelGen struct {
	r      *rand.Rand
	re     *reoracle.Gen
	routes map[types.ASN][]netip.Prefix
	probes [2][]netip.Prefix // per family (v6 = 1): prefixes the registry names
}

func newModelGen(seed uint64) *modelGen {
	g := &modelGen{
		r:      rand.New(rand.NewPCG(seed, seed^0x5eed5eed5eed5eed)),
		re:     reoracle.NewGen(seed),
		routes: map[types.ASN][]netip.Prefix{},
	}
	g.re.MaxDepth = 3
	return g
}

var (
	modelV4 = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24")}
	modelV6 = []netip.Prefix{netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2001:db8:1::/48")}
)

func fam(v6 bool) int {
	if v6 {
		return 1
	}
	return 0
}

// freshPrefix draws a prefix near one of the family's documentation blocks:
// up to two bits shorter, up to eight longer, the new bits random.
func (g *modelGen) freshPrefix(v6 bool) netip.Prefix {
	bases := modelV4
	if v6 {
		bases = modelV6
	}
	b := bases[g.r.IntN(len(bases))]
	bits := min(b.Bits()-2+g.r.IntN(11), b.Addr().BitLen())
	raw := b.Addr().AsSlice()
	for i := b.Bits(); i < bits; i++ {
		if g.r.IntN(2) == 1 {
			raw[i/8] |= 0x80 >> (i % 8)
		}
	}
	a, _ := netip.AddrFromSlice(raw)
	p, err := a.Prefix(bits)
	if err != nil {
		panic(err)
	}
	return p
}

// prefix is freshPrefix, recorded as a probe for the routes.
func (g *modelGen) prefix(v6 bool) netip.Prefix {
	p := g.freshPrefix(v6)
	g.probes[fam(v6)] = append(g.probes[fam(v6)], p)
	return p
}

// literal is a prefix with a random range operator, as a route-set member or
// a prefix list writes it.
func (g *modelGen) literal(v6 bool) string {
	p := g.prefix(v6)
	maxLen, l := p.Addr().BitLen(), p.Bits()
	switch g.r.IntN(6) {
	case 0:
		if l < maxLen {
			return p.String() + "^-"
		}
	case 1:
		return p.String() + "^+"
	case 2:
		return p.String() + "^" + strconv.Itoa(l+g.r.IntN(min(8, maxLen-l)+1))
	case 3:
		n := l + g.r.IntN(min(8, maxLen-l)+1)
		m := n + g.r.IntN(min(6, maxLen-n)+1)
		return p.String() + "^" + strconv.Itoa(n) + "-" + strconv.Itoa(m)
	}
	return p.String()
}

// setOp is a range operator after an AS or a set: lengths near either
// family's blocks.
func (g *modelGen) setOp() string {
	n := 22 + g.r.IntN(11)
	if g.r.IntN(2) == 0 {
		n = 30 + g.r.IntN(27)
	}
	switch g.r.IntN(8) {
	case 0:
		return "^-"
	case 1:
		return "^+"
	case 2:
		return "^" + strconv.Itoa(n)
	case 3:
		return "^" + strconv.Itoa(n) + "-" + strconv.Itoa(n+g.r.IntN(6))
	}
	return ""
}

func (g *modelGen) as() types.ASN { return reoracle.FirstAS + types.ASN(g.r.IntN(reoracle.NumASes)) }

// world writes the registry: routes of the generator's ASes, AS-A and AS-B
// (each may name the other, and a missing set), AS-EMPTY, RS-A and RS-B.
// AS-MISSING and RS-MISSING are never written.
func (g *modelGen) world() string {
	var b strings.Builder
	for i := range reoracle.NumASes {
		as := reoracle.FirstAS + types.ASN(i)
		for range g.r.IntN(4) {
			v6 := g.r.IntN(5) < 2
			p := g.prefix(v6)
			class := "route"
			if v6 {
				class = "route6"
			}
			fmt.Fprintf(&b, "%s: %s\norigin: %s\nsource: TEST\n\n", class, p, as)
			g.routes[as] = append(g.routes[as], p)
		}
	}
	set := func(class, name string, attrs ...[2]string) {
		fmt.Fprintf(&b, "%s: %s\n", class, name)
		for _, a := range attrs {
			fmt.Fprintf(&b, "%s: %s\n", a[0], a[1])
		}
		b.WriteString("source: TEST\n\n")
	}
	asMembers := func(n int, extra ...string) [][2]string {
		var out [][2]string
		for range g.r.IntN(n + 1) {
			out = append(out, [2]string{"members", g.as().String()})
		}
		for _, e := range extra {
			if g.r.IntN(3) == 0 {
				out = append(out, [2]string{"members", e})
			}
		}
		return out
	}
	set("as-set", reoracle.SetA, asMembers(3, "AS-B", "AS-NOWHERE")...)
	set("as-set", "AS-B", asMembers(2, reoracle.SetA)...)
	set("as-set", reoracle.SetEmpty)
	var rsA [][2]string
	for range g.r.IntN(3) {
		rsA = append(rsA, [2]string{"members", g.literal(false)})
	}
	for range g.r.IntN(3) {
		rsA = append(rsA, [2]string{"mp-members", g.literal(true)})
	}
	if g.r.IntN(2) == 0 {
		rsA = append(rsA, [2]string{"members", g.as().String() + g.setOp()})
	}
	for _, ref := range []string{"AS-B", "RS-B", "RS-NOWHERE"} {
		if g.r.IntN(3) == 0 {
			rsA = append(rsA, [2]string{"members", ref + g.setOp()})
		}
	}
	set("route-set", "RS-A", rsA...)
	rsB := [][2]string{{"members", g.literal(false)}}
	if g.r.IntN(2) == 0 {
		rsB = append(rsB, [2]string{"mp-members", g.literal(true)})
	}
	set("route-set", "RS-B", rsB...)
	return b.String()
}

// expected is how many clauses and undecided terms peval should give the
// generated aut-num in one family.
type expected struct{ clauses, undecided int }

// autNum writes AS64496's aut-num: one to four import terms, most of them
// from the peer in one family or both, some from another AS, some naming
// routers the session does not give, some for another protocol. It returns
// what peval should make of it per family (false: IPv4, true: IPv6). A few
// attributes hold two terms, one clause and one undecided term, so that an
// undecided term can share the accepting clause's Index.
func (g *modelGen) autNum() (string, map[bool]expected) {
	exp := map[bool]expected{false: {}, true: {}}
	var b strings.Builder
	fmt.Fprintf(&b, "aut-num: %s\nas-name: MODEL\n", modelLocal)
	add := func(v4, v6 bool, clause bool) {
		for _, f := range []struct {
			on bool
			v6 bool
		}{{v4, false}, {v6, true}} {
			if !f.on {
				continue
			}
			e := exp[f.v6]
			if clause {
				e.clauses++
			} else {
				e.undecided++
			}
			exp[f.v6] = e
		}
	}
	peer := modelPeer.String()
	for range 1 + g.r.IntN(4) {
		f := g.filter(0)
		switch k := g.r.IntN(100); {
		case k < 25:
			fmt.Fprintf(&b, "import: from %s accept %s\n", peer, f)
			add(true, false, true)
		case k < 40:
			fmt.Fprintf(&b, "mp-import: afi ipv6.unicast from %s accept %s\n", peer, f)
			add(false, true, true)
		case k < 70:
			fmt.Fprintf(&b, "mp-import: afi any.unicast from %s accept %s\n", peer, f)
			add(true, true, true)
		case k < 77:
			fmt.Fprintf(&b, "mp-import: afi ipv4.unicast from %s accept %s\n", peer, f)
			add(true, false, true)
		case k < 82:
			fmt.Fprintf(&b, "mp-import: afi any.unicast from %s accept %s\n", g.otherAS(), f)
		case k < 87:
			// One attribute, two terms of one Index: a clause and an
			// undecided term, in either order.
			terms := []string{"from " + peer + " accept " + f, "from " + peer + " 192.0.2.1 at 192.0.2.2 accept " + g.filter(0)}
			if g.r.IntN(2) == 0 {
				terms[0], terms[1] = terms[1], terms[0]
			}
			fmt.Fprintf(&b, "mp-import: afi any.unicast { %s; %s; }\n", terms[0], terms[1])
			add(true, true, true)
			add(true, true, false)
		case k < 94:
			fmt.Fprintf(&b, "mp-import: afi any.unicast from %s 192.0.2.1 at 192.0.2.2 accept %s\n", peer, f)
			add(true, true, false)
		default:
			fmt.Fprintf(&b, "import: protocol OSPF from %s accept %s\n", peer, f)
			add(true, false, false)
		}
	}
	b.WriteString("source: TEST\n\n")
	return b.String(), exp
}

func (g *modelGen) otherAS() types.ASN {
	return modelPeer + 1 + types.ASN(g.r.IntN(reoracle.NumASes-1))
}

// filter writes a random filter: NOT, AND and OR (explicit or implicit)
// over prefix lists, AS numbers, as-sets, route-sets, PeerAS, ANY, AS-path
// regexps and community tests.
func (g *modelGen) filter(depth int) string {
	s, _ := g.node(depth)
	return s
}

// node writes a filter and reports whether it is a single leaf, which needs
// no parentheses as an operand.
func (g *modelGen) node(depth int) (string, bool) {
	if depth >= 3 || g.r.IntN(100) < 45 {
		return g.leaf(), true
	}
	child := func() string {
		s, leaf := g.node(depth + 1)
		if !leaf {
			return "(" + s + ")"
		}
		return s
	}
	k := g.r.IntN(20)
	if k < 3 {
		return "NOT " + child(), false
	}
	op := " AND "
	if k >= 11 {
		op = " OR "
		if g.r.IntN(4) == 0 {
			op = " "
		}
	}
	parts := make([]string, 2+g.r.IntN(2))
	for i := range parts {
		parts[i] = child()
	}
	return strings.Join(parts, op), false
}

var (
	modelComms    = []string{"65000:1", "65000:2", "64500:100", "no_export", "NO_ADVERTISE", "local_as", "no_export_subconfed", "4259840001"}
	modelOddComms = []string{"internet", "70000:1", "bogus"}
	// modelRouteComms are what routes carry: 65000:1, 65000:2, 64500:100,
	// no_export, no_advertise, local_as, 65001:7.
	modelRouteComms = []uint32{65000<<16 | 1, 65000<<16 | 2, 64500<<16 | 100, 0xFFFFFF01, 0xFFFFFF02, 0xFFFFFF03, 65001<<16 | 7}
)

func (g *modelGen) leaf() string {
	switch k := g.r.IntN(100); {
	case k < 22:
		parts := make([]string, 1+g.r.IntN(3))
		for i := range parts {
			parts[i] = g.literal(g.r.IntN(5) < 2)
		}
		s := "{" + strings.Join(parts, ", ") + "}"
		switch g.r.IntN(8) {
		case 0:
			s += "^+"
		case 1:
			s += "^-"
		}
		return s
	case k < 32:
		return g.as().String() + g.setOp()
	case k < 44:
		return []string{reoracle.SetA, "AS-B", reoracle.SetEmpty, reoracle.SetMissing}[g.r.IntN(4)] + g.setOp()
	case k < 56:
		return []string{"RS-A", "RS-B", "RS-MISSING"}[g.r.IntN(3)] + g.setOp()
	case k < 61:
		return "PeerAS" + g.setOp()
	case k < 65:
		return "ANY"
	case k < 83:
		return "<" + g.re.Regexp() + ">"
	}
	vals := make([]string, 1+g.r.IntN(3))
	for i := range vals {
		if g.r.IntN(12) == 0 {
			vals[i] = modelOddComms[g.r.IntN(len(modelOddComms))]
		} else {
			vals[i] = modelComms[g.r.IntN(len(modelComms))]
		}
	}
	list := strings.Join(vals, ", ")
	switch g.r.IntN(3) {
	case 0:
		return "community(" + list + ")"
	case 1:
		return "community.contains(" + list + ")"
	}
	return "community == {" + list + "}"
}

// route draws a route of one family: half the time a prefix the registry
// names, its covering prefix or one of its halves, else a fresh one; a path
// from oracle 2's generator; a few communities. A tenth of routes have a
// path that is not a plain sequence, a tenth unknown communities.
func (g *modelGen) route(v6 bool) verdict.Route {
	var p netip.Prefix
	if probes := g.probes[fam(v6)]; len(probes) > 0 && g.r.IntN(2) == 0 {
		p = probes[g.r.IntN(len(probes))]
		switch g.r.IntN(4) {
		case 0:
			if p.Bits() > 0 {
				p, _ = p.Addr().Prefix(p.Bits() - 1)
			}
		case 1:
			if p.Bits() < p.Addr().BitLen() {
				raw := p.Addr().AsSlice()
				if g.r.IntN(2) == 1 {
					raw[p.Bits()/8] |= 0x80 >> (p.Bits() % 8)
				}
				a, _ := netip.AddrFromSlice(raw)
				p = netip.PrefixFrom(a, p.Bits()+1)
			}
		}
	} else {
		p = g.freshPrefix(v6)
	}
	r := verdict.Route{Prefix: p, Path: g.re.Path(), PathKnown: g.r.IntN(10) != 0, CommsKnown: g.r.IntN(10) != 0}
	for range g.r.IntN(4) {
		r.Communities = append(r.Communities, modelRouteComms[g.r.IntN(len(modelRouteComms))])
	}
	return r
}
