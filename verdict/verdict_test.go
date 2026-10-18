package verdict

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

// fixture is the registry the tests' filters are normalized over, so their
// normal forms are rpsl's own (resolve.Expander.NormalizeFilter).
const fixture = `as-set: AS-CUST
members: AS64501, AS64502
source: TEST

route: 192.0.2.0/24
origin: AS64501
source: TEST

route: 198.51.100.0/24
origin: AS64502
source: TEST

route6: 2001:db8::/32
origin: AS64501
source: TEST
`

// peer is the AS PeerAS is bound to.
const peer = 64500

func source(t testing.TB) *resolve.MemSource {
	t.Helper()
	src, err := resolve.LoadDump(strings.NewReader(fixture))
	if err != nil {
		t.Fatal(err)
	}
	return src
}

// normal normalizes the filter text over the fixture for afi, with PeerAS
// bound to peer.
func normal(t testing.TB, afi types.AFI, text string) resolve.NormalFilter {
	t.Helper()
	f, diags := policy.ParseFilter(text)
	if len(diags) > 0 {
		t.Fatalf("ParseFilter(%q): %v", text, diags)
	}
	e := resolve.Expander{Src: source(t), Peer: peer, AFI: afi}
	nf, err := e.NormalizeFilter(context.Background(), f)
	if err != nil {
		t.Fatalf("NormalizeFilter(%q): %v", text, err)
	}
	return nf
}

func parseRE(t testing.TB, body string) *policy.ASPathRE {
	t.Helper()
	re, err := policy.ParseASPathRegexp(body)
	if err != nil {
		t.Fatalf("ParseASPathRegexp(%q): %v", body, err)
	}
	return re
}

func setRef(t testing.TB, s string) types.SetRef {
	t.Helper()
	r, err := types.ParseSetRef(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func pclause(index int, f resolve.NormalFilter) peval.Clause {
	return peval.Clause{Index: index, Filter: f}
}

func pol(cs ...peval.Clause) peval.Policy { return peval.Policy{Clauses: cs} }

func route(prefix string, path ...types.ASN) Route {
	return Route{Prefix: netip.MustParsePrefix(prefix), Path: path, PathKnown: true, CommsKnown: true}
}

func (r Route) comms(cs ...uint32) Route { r.Communities = cs; return r }
func (r Route) pathUnknown() Route       { r.PathKnown = false; return r }
func (r Route) commsUnknown() Route      { r.CommsKnown = false; return r }

func comm(hi, lo uint16) uint32 { return uint32(hi)<<16 | uint32(lo) }

func cycle(n int) []types.ASN {
	path := make([]types.ASN, n)
	for i := range path {
		path[i] = types.ASN(i%7 + 3)
	}
	return path
}

func accepted(pos int, earlier ...int) Verdict {
	return Verdict{Outcome: Accepted, Clause: pos, EarlierUndecided: earlier}
}

func rejected(fails ...Fail) Verdict { return Verdict{Outcome: Rejected, Fails: fails} }

func undecided(reasons ...Reason) Verdict { return Verdict{Outcome: Undecided, Reasons: reasons} }

// norm makes an empty slice nil, so a verdict compares by content.
func norm(v Verdict) Verdict {
	if len(v.EarlierUndecided) == 0 {
		v.EarlierUndecided = nil
	}
	if len(v.Fails) == 0 {
		v.Fails = nil
	} else {
		fs := make([]Fail, len(v.Fails))
		for i, f := range v.Fails {
			if len(f.Missing) == 0 {
				f.Missing = nil
			}
			fs[i] = f
		}
		v.Fails = fs
	}
	if len(v.Reasons) == 0 {
		v.Reasons = nil
	}
	return v
}

func sameVerdict(a, b Verdict) bool { return reflect.DeepEqual(norm(a), norm(b)) }

type decideCase struct {
	name string
	p    peval.Policy
	r    Route
	want Verdict
}

// decideCases is spec §6.4, rule by rule; each name starts with the rule.
func decideCases(t testing.TB) []decideCase {
	v4, any := types.AFIv4, types.AFIAny
	cust := normal(t, v4, "AS-CUST")
	anyV4 := normal(t, v4, "ANY")
	pathCust := normal(t, v4, "<^PeerAS AS-CUST$>")
	pathX := normal(t, v4, "<AS64501>")

	unbound := resolve.NormalFilter{Conjuncts: []resolve.Conjunct{{
		Prefixes: anyV4.Conjuncts[0].Prefixes,
		Paths:    []resolve.PathMatch{{RE: parseRE(t, "^PeerAS")}},
	}}}
	nilRE := resolve.NormalFilter{Conjuncts: []resolve.Conjunct{{
		Prefixes: anyV4.Conjuncts[0].Prefixes,
		Paths:    []resolve.PathMatch{{}},
	}}}
	expensive := "(((. .){0,999} .){0,999} .){0,999} AS2"

	peerRtr := policy.Term{Filter: policy.FilterAny{}}
	if pe, diags := policy.ParsePeering("AS64500 192.0.2.1 at 192.0.2.2"); len(diags) == 0 {
		peerRtr.Peering = pe
	} else {
		t.Fatal(diags)
	}

	return []decideCase{
		// Prefix tests: yes when some range of Prefixes holds the prefix and
		// no range of NotPrefixes does; never undecided.
		{"prefix/in", pol(pclause(0, cust)), route("192.0.2.0/24", peer, 64501), accepted(0)},
		{"prefix/host bits ignored", pol(pclause(0, cust)), route("192.0.2.1/24", peer, 64501), accepted(0)},
		{"prefix/more specific not in", pol(pclause(0, cust)), route("192.0.2.0/25", peer, 64501),
			rejected(Fail{Clause: 0, Test: FailPrefixNotIn})},
		{"prefix/in with operator", pol(pclause(0, normal(t, v4, "AS-CUST^+"))), route("192.0.2.128/25", peer, 64501), accepted(0)},
		{"prefix/in NOT", pol(pclause(0, normal(t, v4, "{10.0.0.0/8^+} AND NOT {10.1.0.0/16^+}"))), route("10.1.2.0/24", peer),
			rejected(Fail{Clause: 0, Test: FailPrefixInNot})},
		{"prefix/beside NOT", pol(pclause(0, normal(t, v4, "{10.0.0.0/8^+} AND NOT {10.1.0.0/16^+}"))), route("10.2.0.0/16", peer), accepted(0)},
		{"prefix/AnyPrefix", pol(pclause(0, anyV4)), route("203.0.113.0/24", peer), accepted(0)},
		{"prefix/AnyPrefix v6 over both", pol(pclause(0, normal(t, any, "ANY"))), route("2001:db8:1::/48", peer), accepted(0)},
		{"prefix/AnyPrefix v4 is not v6", pol(pclause(0, anyV4)), route("2001:db8::/32", peer),
			rejected(Fail{Clause: 0, Test: FailPrefixNotIn})},
		{"prefix/v6 range", pol(pclause(0, normal(t, any, "AS-CUST"))), route("2001:db8::/32", peer), accepted(0)},
		{"prefix/invalid route prefix", pol(pclause(0, anyV4)), Route{PathKnown: true, CommsKnown: true},
			rejected(Fail{Clause: 0, Test: FailPrefixNotIn})},
		{"prefix/empty Prefixes matches nothing", pol(pclause(0, resolve.NormalFilter{Conjuncts: []resolve.Conjunct{{}}})), route("192.0.2.0/24", peer),
			rejected(Fail{Clause: 0, Test: FailPrefixNotIn})},
		{"prefix/no conjuncts", pol(pclause(0, normal(t, v4, "NOT ANY"))), route("192.0.2.0/24", peer),
			rejected(Fail{Clause: 0, Test: FailNoConjunct})},

		// D4: a reject caused by a missing set names it.
		{"missing/only a missing set", pol(pclause(0, normal(t, v4, "AS-MISSING"))), route("192.0.2.0/24", peer),
			rejected(Fail{Clause: 0, Test: FailNoConjunct, Missing: []types.SetRef{setRef(t, "AS-MISSING")}})},
		{"missing/beside a range", pol(pclause(0, normal(t, v4, "AS-MISSING OR {192.0.2.0/24}"))), route("198.51.100.0/24", peer),
			rejected(Fail{Clause: 0, Test: FailPrefixNotIn, Missing: []types.SetRef{setRef(t, "AS-MISSING")}})},

		// Path tests: pathre's answer, flipped when Negated.
		{"path/yes", pol(pclause(0, pathCust)), route("192.0.2.0/24", peer, 64501), accepted(0)},
		{"path/no", pol(pclause(0, pathCust)), route("192.0.2.0/24", peer, 64999),
			rejected(Fail{Clause: 0, Test: "<^ AS64500 AS-CUST $>"})},
		{"path/negated yes", pol(pclause(0, normal(t, v4, "NOT <AS64666>"))), route("192.0.2.0/24", peer, 64501), accepted(0)},
		{"path/negated no", pol(pclause(0, normal(t, v4, "NOT <AS64666>"))), route("192.0.2.0/24", peer, 64666, 64501),
			rejected(Fail{Clause: 0, Test: "NOT <AS64666>"})},
		{"path/empty path", pol(pclause(0, normal(t, v4, "<^$>"))), route("192.0.2.0/24"), accepted(0)},
		{"path/not known", pol(pclause(0, pathX)), route("192.0.2.0/24", peer, 64501).pathUnknown(),
			undecided(Reason{Kind: ReasonPathNotSequence, Clause: 0, Index: 0, Term: "<AS64501>"})},
		{"path/not known negated", pol(pclause(0, normal(t, v4, "NOT <AS64666>"))), route("192.0.2.0/24", peer, 64501).pathUnknown(),
			undecided(Reason{Kind: ReasonPathNotSequence, Term: "NOT <AS64666>"})},
		{"path/not known, a clause without path tests accepts", pol(pclause(0, pathX), pclause(1, cust)), route("192.0.2.0/24", peer, 64501).pathUnknown(),
			accepted(1, 0)},
		{"path/not known, a clause without path tests rejects", pol(pclause(0, pathX), pclause(1, cust)), route("203.0.113.0/24", peer, 64501).pathUnknown(),
			undecided(Reason{Kind: ReasonPathNotSequence, Clause: 0, Index: 0, Term: "<AS64501>"})},
		{"path/not known, the prefix test says no", pol(pclause(0, normal(t, v4, "AS-CUST AND <AS64501>"))), route("203.0.113.0/24", peer, 64501).pathUnknown(),
			rejected(Fail{Clause: 0, Test: FailPrefixNotIn})},
		{"path/same-AS run over a sequence", pol(pclause(0, normal(t, v4, "<(AS64500 AS64501)~+>"))), route("192.0.2.0/24", peer, 64501),
			undecided(Reason{Kind: ReasonSameASRun, Term: "<(AS64500 AS64501)~+>"})},
		{"path/too expensive", pol(pclause(0, normal(t, v4, "<"+expensive+">"))), Route{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Path: cycle(1000), PathKnown: true, CommsKnown: true},
			undecided(Reason{Kind: ReasonPathTooExpensive, Term: "<" + parseRE(t, expensive).String() + ">"})},
		{"path/unbound", pol(pclause(0, unbound)), route("192.0.2.0/24", peer),
			undecided(Reason{Kind: ReasonPathUnbound, Term: "<^ PeerAS>"})},
		{"path/nil regexp", pol(pclause(0, nilRE)), route("192.0.2.0/24", peer),
			undecided(Reason{Kind: ReasonPathUnbound, Term: "<>"})},

		// Community tests.
		{"community/contains hi:lo and a 4-byte integer", pol(pclause(0, normal(t, v4, "community(65000:100, 65001)"))),
			route("192.0.2.0/24", peer).comms(65001, comm(1, 1), comm(65000, 100)), accepted(0)},
		{"community/contains a missing value", pol(pclause(0, normal(t, v4, "community(65000:100, 65001)"))),
			route("192.0.2.0/24", peer).comms(comm(65000, 100)),
			rejected(Fail{Clause: 0, Test: "community(65000:100, 65001)"})},
		{"community/integer equals hi:lo", pol(pclause(0, normal(t, v4, "community(4259840100)"))),
			route("192.0.2.0/24", peer).comms(comm(65000, 100)), accepted(0)},
		{"community/no_export", pol(pclause(0, normal(t, v4, "community(no_export)"))),
			route("192.0.2.0/24", peer).comms(0xFFFFFF01), accepted(0)},
		{"community/no_advertise any case", pol(pclause(0, normal(t, v4, "community(NO_ADVERTISE)"))),
			route("192.0.2.0/24", peer).comms(0xFFFFFF02), accepted(0)},
		{"community/local_as", pol(pclause(0, normal(t, v4, "community(local_as)"))),
			route("192.0.2.0/24", peer).comms(0xFFFFFF03), accepted(0)},
		{"community/local_as is not no_export", pol(pclause(0, normal(t, v4, "community(local_as)"))),
			route("192.0.2.0/24", peer).comms(0xFFFFFF01),
			rejected(Fail{Clause: 0, Test: "community(local_as)"})},
		{"community/spaces around the colon", pol(pclause(0, normal(t, v4, "community(65000 : 100)"))),
			route("192.0.2.0/24", peer).comms(comm(65000, 100)), accepted(0)},
		{"community/equals", pol(pclause(0, normal(t, v4, "community == {65000:100, no_export}"))),
			route("192.0.2.0/24", peer).comms(0xFFFFFF01, comm(65000, 100), comm(65000, 100)), accepted(0)},
		{"community/equals with one more", pol(pclause(0, normal(t, v4, "community == {65000:100, no_export}"))),
			route("192.0.2.0/24", peer).comms(0xFFFFFF01, comm(65000, 100), comm(1, 1)),
			rejected(Fail{Clause: 0, Test: "community == {65000:100, no_export}"})},
		{"community/equals with one fewer", pol(pclause(0, normal(t, v4, "community == {65000:100, no_export}"))),
			route("192.0.2.0/24", peer).comms(comm(65000, 100)),
			rejected(Fail{Clause: 0, Test: "community == {65000:100, no_export}"})},
		{"community/negated yes", pol(pclause(0, normal(t, v4, "NOT community(65000:100)"))),
			route("192.0.2.0/24", peer), accepted(0)},
		{"community/negated no", pol(pclause(0, normal(t, v4, "NOT community(65000:100)"))),
			route("192.0.2.0/24", peer).comms(comm(65000, 100)),
			rejected(Fail{Clause: 0, Test: "NOT community(65000:100)"})},
		{"community/internet", pol(pclause(0, normal(t, v4, "community(internet)"))),
			route("192.0.2.0/24", peer).comms(comm(1, 1)),
			undecided(Reason{Kind: ReasonCommInternet, Term: "community(internet)"})},
		{"community/internet negated", pol(pclause(0, normal(t, v4, "NOT community(INTERNET)"))),
			route("192.0.2.0/24", peer),
			undecided(Reason{Kind: ReasonCommInternet, Term: "NOT community(INTERNET)"})},
		{"community/not known", pol(pclause(0, normal(t, v4, "community(65000:100)"))),
			route("192.0.2.0/24", peer).comms(comm(65000, 100)).commsUnknown(),
			undecided(Reason{Kind: ReasonCommsUnknown, Term: "community(65000:100)"})},
		{"community/not known negated", pol(pclause(0, normal(t, v4, "NOT community(65000:100)"))),
			route("192.0.2.0/24", peer).commsUnknown(),
			undecided(Reason{Kind: ReasonCommsUnknown, Term: "NOT community(65000:100)"})},
		{"community/a half over 65535", pol(pclause(0, normal(t, v4, "community(65536:1)"))),
			route("192.0.2.0/24", peer),
			undecided(Reason{Kind: ReasonCommValue, Term: "community(65536:1)"})},
		{"community/an integer over 32 bits", pol(pclause(0, normal(t, v4, "community(4294967296)"))),
			route("192.0.2.0/24", peer),
			undecided(Reason{Kind: ReasonCommValue, Term: "community(4294967296)"})},
		{"community/no_export_subconfed is local_as", pol(pclause(0, normal(t, v4, "community(No_Export_SubConfed)"))),
			route("192.0.2.0/24", peer).comms(0xFFFFFF03), accepted(0)},
		{"community/a word", pol(pclause(0, normal(t, v4, "community(no_peer)"))),
			route("192.0.2.0/24", peer).comms(0xFFFFFF03),
			undecided(Reason{Kind: ReasonCommValue, Term: "community(no_peer)"})},
		{"community/value reason before not known", pol(pclause(0, normal(t, v4, "community(65536:1)"))),
			route("192.0.2.0/24", peer).commsUnknown(),
			undecided(Reason{Kind: ReasonCommValue, Term: "community(65536:1)"})},

		// A conjunct is the three-valued AND of its tests.
		{"and/no beats undecided", pol(pclause(0, normal(t, v4, "<AS64501> AND community(1:1)"))),
			route("192.0.2.0/24", peer, 64501).pathUnknown(),
			rejected(Fail{Clause: 0, Test: "community(1:1)"})},
		{"and/undecided", pol(pclause(0, normal(t, v4, "<AS64501> AND community(1:1)"))),
			route("192.0.2.0/24", peer, 64501).pathUnknown().comms(comm(1, 1)),
			undecided(Reason{Kind: ReasonPathNotSequence, Term: "<AS64501>"})},
		{"and/every undecided test is a reason", pol(pclause(0, normal(t, v4, "<AS64501> AND community(internet)"))),
			route("192.0.2.0/24", peer, 64501).pathUnknown(),
			undecided(Reason{Kind: ReasonPathNotSequence, Term: "<AS64501>"}, Reason{Kind: ReasonCommInternet, Term: "community(internet)"})},
		{"and/first failing test is the first in order", pol(pclause(0, normal(t, v4, "<AS64666> AND community(1:1)"))),
			route("192.0.2.0/24", peer, 64501),
			rejected(Fail{Clause: 0, Test: "<AS64666>"})},

		// A clause's filter is the three-valued OR of its conjuncts.
		{"or/yes beats undecided", pol(pclause(0, normal(t, v4, "<AS64501> OR AS-CUST"))),
			route("192.0.2.0/24", peer, 64501).pathUnknown(), accepted(0)},
		{"or/undecided beats no", pol(pclause(0, normal(t, v4, "<AS64501> OR AS-CUST"))),
			route("203.0.113.0/24", peer, 64501).pathUnknown(),
			undecided(Reason{Kind: ReasonPathNotSequence, Term: "<AS64501>"})},
		{"or/no", pol(pclause(0, normal(t, v4, "<AS64666> OR AS-CUST"))),
			route("203.0.113.0/24", peer, 64501),
			rejected(Fail{Clause: 0, Test: FailPrefixNotIn})},

		// Over the clauses in order: the first yes.
		{"clauses/first match", pol(pclause(0, cust), pclause(1, anyV4)), route("192.0.2.0/24", peer, 64501), accepted(0)},
		{"clauses/second match", pol(pclause(0, cust), pclause(1, anyV4)), route("203.0.113.0/24", peer, 64501), accepted(1)},
		{"clauses/earlier undecided", pol(pclause(0, pathX), pclause(1, normal(t, v4, "community(internet)")), pclause(2, cust), pclause(3, anyV4)),
			route("192.0.2.0/24", peer, 64501).pathUnknown(), accepted(2, 0, 1)},
		{"clauses/a later undecided is not earlier", pol(pclause(0, cust), pclause(1, pathX)),
			route("192.0.2.0/24", peer, 64501).pathUnknown(), accepted(0)},
		{"clauses/every clause no", pol(pclause(0, cust), pclause(1, normal(t, v4, "<AS64666>"))),
			route("203.0.113.0/24", peer, 64502),
			rejected(Fail{Clause: 0, Test: FailPrefixNotIn}, Fail{Clause: 1, Test: "<AS64666>"})},

		// Policy.Undecided: Rejected needs it empty.
		{"peval/turns a reject into undecided", peval.Policy{Clauses: []peval.Clause{pclause(0, cust)},
			Undecided: []peval.Undecided{{Index: 2, Term: peerRtr, Why: peval.WhyPeerRouter}}},
			route("203.0.113.0/24", peer, 64501),
			undecided(Reason{Kind: ReasonPeval, Why: peval.WhyPeerRouter, Clause: -1, Index: 2, Term: peerRtr.String()})},
		{"peval/zero term", peval.Policy{Undecided: []peval.Undecided{{Index: 1, Why: peval.WhyProtocol + " OSPF"}}},
			route("203.0.113.0/24", peer, 64501),
			undecided(Reason{Kind: ReasonPeval, Why: "protocol OSPF", Clause: -1, Index: 1})},
		// An undecided term at or before the accepting clause may take the
		// route instead: Accepted names it in Reasons.
		{"peval/a term before an accept is named", peval.Policy{Clauses: []peval.Clause{pclause(1, cust)},
			Undecided: []peval.Undecided{{Index: 0, Term: peerRtr, Why: peval.WhyPeerRouter}}},
			route("192.0.2.0/24", peer, 64501),
			Verdict{Outcome: Accepted, Clause: 0, Reasons: []Reason{{Kind: ReasonPeval, Why: peval.WhyPeerRouter, Clause: -1, Index: 0, Term: peerRtr.String()}}}},
		{"peval/a term at the accept's Index is named", peval.Policy{Clauses: []peval.Clause{pclause(0, normal(t, v4, "<AS64666>")), pclause(1, cust)},
			Undecided: []peval.Undecided{{Index: 1, Term: peerRtr, Why: peval.WhyLocalRouter}, {Index: 1, Term: peerRtr, Why: peval.WhyLocalRouter}}},
			route("192.0.2.0/24", peer, 64501),
			Verdict{Outcome: Accepted, Clause: 1, Reasons: []Reason{{Kind: ReasonPeval, Why: peval.WhyLocalRouter, Clause: -1, Index: 1, Term: peerRtr.String()}}}},
		{"peval/a term after an accept is not named", peval.Policy{Clauses: []peval.Clause{pclause(1, cust)},
			Undecided: []peval.Undecided{{Index: 2, Term: peerRtr, Why: peval.WhyPeerRouter}}},
			route("192.0.2.0/24", peer, 64501), accepted(0)},
		{"peval/only the terms up to the accept are named", peval.Policy{Clauses: []peval.Clause{pclause(0, pathX), pclause(2, cust)},
			Undecided: []peval.Undecided{{Index: 3, Why: peval.WhyProtocol + " OSPF"}, {Index: 1, Term: peerRtr, Why: peval.WhyPeerRouter}}},
			route("192.0.2.0/24", peer, 64501).pathUnknown(),
			Verdict{Outcome: Accepted, Clause: 1, EarlierUndecided: []int{0},
				Reasons: []Reason{{Kind: ReasonPeval, Why: peval.WhyPeerRouter, Clause: -1, Index: 1, Term: peerRtr.String()}}}},
		{"peval/after filter reasons", peval.Policy{Clauses: []peval.Clause{pclause(0, pathX)},
			Undecided: []peval.Undecided{{Index: 1, Term: peerRtr, Why: peval.WhyLocalRouter}}},
			route("203.0.113.0/24", peer, 64501).pathUnknown(),
			undecided(Reason{Kind: ReasonPathNotSequence, Term: "<AS64501>"},
				Reason{Kind: ReasonPeval, Why: peval.WhyLocalRouter, Clause: -1, Index: 1, Term: peerRtr.String()})},

		// Pos is the position in Policy.Clauses; Index is peval's (a REFINE
		// flattens to several clauses of one Index).
		{"pos/accepted names Pos", pol(pclause(3, cust), pclause(3, anyV4)), route("203.0.113.0/24", peer), accepted(1)},
		{"pos/fails name Pos", pol(pclause(3, cust), pclause(3, normal(t, v4, "<AS64666>"))), route("203.0.113.0/24", peer, 64501),
			rejected(Fail{Clause: 0, Test: FailPrefixNotIn}, Fail{Clause: 1, Test: "<AS64666>"})},
		{"pos/reasons name Pos and Index", pol(pclause(3, cust), pclause(3, pathX)), route("203.0.113.0/24", peer, 64501).pathUnknown(),
			undecided(Reason{Kind: ReasonPathNotSequence, Clause: 1, Index: 3, Term: "<AS64501>"})},

		// One reason per (Kind, Why, Clause, Index, Term).
		{"dedup/one test in two conjuncts", pol(pclause(0, normal(t, v4, "(<AS64501> AND community(1:1)) OR (<AS64501> AND community(1:2))"))),
			route("192.0.2.0/24", peer, 64501).pathUnknown().comms(comm(1, 1), comm(1, 2)),
			undecided(Reason{Kind: ReasonPathNotSequence, Term: "<AS64501>"})},
		{"dedup/one test in two clauses", pol(pclause(0, pathX), pclause(1, pathX)),
			route("192.0.2.0/24", peer, 64501).pathUnknown(),
			undecided(Reason{Kind: ReasonPathNotSequence, Clause: 0, Term: "<AS64501>"},
				Reason{Kind: ReasonPathNotSequence, Clause: 1, Index: 1, Term: "<AS64501>"})},

		// No clause and no undecided term: the caller's NoPolicy case;
		// never Rejected.
		{"nopolicy/undecided without a reason", peval.Policy{}, route("192.0.2.0/24", peer), undecided()},
	}
}

func TestDecide(t *testing.T) {
	for _, c := range decideCases(t) {
		t.Run(c.name, func(t *testing.T) {
			if got := Decide(c.p, c.r); !sameVerdict(got, c.want) {
				t.Errorf("Decide =\n  %+v\nwant\n  %+v", got, c.want)
			}
		})
	}
}

// TestDecideMatchesCompiled holds the two entry points equal, and a
// compiled policy's answer the same when its path memo is warm.
func TestDecideMatchesCompiled(t *testing.T) {
	for _, c := range decideCases(t) {
		cp := Compile(c.p)
		if !reflect.DeepEqual(cp.Policy(), c.p) {
			t.Errorf("%s: Policy() is not the policy compiled", c.name)
		}
		want := Decide(c.p, c.r)
		for i := range 2 {
			if got := cp.Decide(c.r); !reflect.DeepEqual(got, want) {
				t.Errorf("%s: Compiled.Decide (call %d) =\n  %+v\nDecide =\n  %+v", c.name, i+1, got, want)
			}
		}
	}
}

// TestDecideConcurrent decides the table from several goroutines over one
// Compiled per case, for the race detector.
func TestDecideConcurrent(t *testing.T) {
	cases := decideCases(t)
	compiled := make([]*Compiled, len(cases))
	for i, c := range cases {
		compiled[i] = Compile(c.p)
	}
	var wg sync.WaitGroup
	errs := make(chan string, 8*len(cases))
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := range cases {
				i := (k + g) % len(cases)
				if got := compiled[i].Decide(cases[i].r); !sameVerdict(got, cases[i].want) {
					errs <- fmt.Sprintf("%s: %+v", cases[i].name, got)
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// TestDecideAnySetsPerConjunct: an Accepted verdict names the sets reaching
// AS-ANY that the AS-path tests of the conjunct that accepted the route
// name, either polarity, sorted and deduplicated; a set of another conjunct
// of the clause is not named, and Rejected and Undecided name none.
func TestDecideAnySetsPerConjunct(t *testing.T) {
	v4 := types.AFIv4
	all, a, zzz := setName(t, "AS-ALL"), setName(t, "AS-A"), setName(t, "AS-ZZZ")
	sets := map[types.SetName]resolve.ASNSet{
		all: resolve.NewAnyASNSet(),
		a:   resolve.NewASNSet(64501),
		zzz: resolve.NewAnyASNSet(),
	}
	path := func(negated bool, body string) resolve.PathMatch {
		return resolve.PathMatch{Negated: negated, RE: parseRE(t, body), Sets: sets}
	}
	conj := func(prefixes string, paths ...resolve.PathMatch) resolve.Conjunct {
		return resolve.Conjunct{Prefixes: normal(t, v4, prefixes).Conjuncts[0].Prefixes, Paths: paths}
	}
	filter := func(cs ...resolve.Conjunct) peval.Policy {
		return pol(pclause(0, resolve.NormalFilter{Conjuncts: cs}))
	}
	twoConj := filter(conj("{10.0.0.0/8}", path(false, "AS-ALL$")), conj("{192.0.2.0/24}", path(false, "^AS64501")))
	negated := filter(conj("ANY", path(true, "AS-ALL")))
	withA := filter(conj("ANY", path(false, "AS-ALL"), path(false, "AS-A")))
	several := filter(conj("ANY", path(false, "AS-ZZZ"), path(true, "AS-ALL AS-A AS-ALL"), path(false, "AS-ALL")))
	lower := filter(conj("ANY", path(false, "as-all")))
	withAnySets := func(v Verdict, names ...string) Verdict { v.AnySets = names; return v }
	for _, c := range []struct {
		name string
		p    peval.Policy
		r    Route
		want Verdict
	}{
		{"conjunct naming the set", twoConj, route("10.0.0.0/8", 64501), withAnySets(accepted(0), "AS-ALL")},
		{"other conjunct of the clause", twoConj, route("192.0.2.0/24", 64501), accepted(0)},
		{"negated, empty path", negated, route("192.0.2.0/24"), withAnySets(accepted(0), "AS-ALL")},
		{"beside a set not reaching AS-ANY", withA, route("192.0.2.0/24", 64501), withAnySets(accepted(0), "AS-ALL")},
		{"canonical name, written in lower case", lower, route("192.0.2.0/24", 64501), withAnySets(accepted(0), "AS-ALL")},
		{"sorted and deduplicated", several, route("192.0.2.0/24", 64501), withAnySets(accepted(0), "AS-ALL", "AS-ZZZ")},
		{"rejected", withA, route("192.0.2.0/24", 64502),
			rejected(Fail{Clause: 0, Test: "<AS-A>"})},
		{"rejected by both conjuncts", twoConj, route("198.51.100.0/24", 64501),
			rejected(Fail{Clause: 0, Test: FailPrefixNotIn})},
		{"undecided", withA, route("192.0.2.0/24", 64501).pathUnknown(),
			undecided(Reason{Kind: ReasonPathNotSequence, Clause: 0, Term: "<AS-ALL>"},
				Reason{Kind: ReasonPathNotSequence, Clause: 0, Term: "<AS-A>"})},
	} {
		t.Run(c.name, func(t *testing.T) {
			cp := Compile(c.p)
			got := cp.Decide(c.r)
			if !sameVerdict(got, c.want) {
				t.Fatalf("Decide =\n  %+v\nwant\n  %+v", got, c.want)
			}
			if got.AnySets != nil && len(got.AnySets) == 0 {
				t.Errorf("AnySets is an empty slice, want nil")
			}
			// Each verdict's AnySets is its own: changing it changes no
			// later verdict.
			for i := range got.AnySets {
				got.AnySets[i] = "AS-CHANGED"
			}
			if again := cp.Decide(c.r); !sameVerdict(again, c.want) {
				t.Errorf("after changing the first verdict's AnySets, Decide =\n  %+v", again)
			}
		})
	}
}

func setName(t testing.TB, s string) types.SetName {
	t.Helper()
	n, err := types.ParseSetName(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestCompileBuildsIndexOnce is review focus 4: one clause of 100,000
// ranges decided for 100,000 routes builds its prefix index once.
func TestCompileBuildsIndexOnce(t *testing.T) {
	const n = 100_000
	var b strings.Builder
	b.WriteString("{")
	prefixes := make([]netip.Prefix, n)
	for i := range n {
		prefixes[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{10 + byte(i>>16), byte(i >> 8), byte(i), 0}), 24)
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(prefixes[i].String())
	}
	b.WriteString("}")
	f := normal(t, types.AFIv4, b.String())
	if got := f.Conjuncts[0].Prefixes.Len(); got != n {
		t.Fatalf("filter has %d ranges, want %d", got, n)
	}
	before := indexBuilds.Load()
	c := Compile(pol(pclause(0, f)))
	for i, p := range prefixes {
		r := route(p.String(), peer)
		if v := c.Decide(r); v.Outcome != Accepted {
			t.Fatalf("route %d %s: %+v", i, p, v)
		}
	}
	if v := c.Decide(route("10.0.0.0/25", peer)); v.Outcome != Rejected {
		t.Errorf("10.0.0.0/25: %+v, want Rejected", v)
	}
	if v := c.Decide(route("12.0.0.0/24", peer)); v.Outcome != Rejected {
		t.Errorf("12.0.0.0/24: %+v, want Rejected", v)
	}
	// One conjunct: one index of its Prefixes and one of its NotPrefixes,
	// counted by newPrefixIndex itself, so a build inside Decide counts too.
	if built := indexBuilds.Load() - before; built != 2 {
		t.Errorf("%d prefix indexes built, want 2 (one conjunct's Prefixes and NotPrefixes)", built)
	}
}

// TestPrefixIndexMatchesContains holds the index to PrefixRange.Contains
// over random ranges and prefixes of both families.
func TestPrefixIndexMatchesContains(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	// Each round draws three addresses per family with every bit random (all
	// 32 or 128); an address is one of them, or one with a random bit
	// flipped, so ranges nest and prefixes hit them at any depth.
	var bases4 [3][4]byte
	var bases6 [3][16]byte
	addr := func(v6 bool) netip.Addr {
		if v6 {
			a := bases6[rng.IntN(len(bases6))]
			if rng.IntN(2) == 0 {
				i := rng.IntN(128)
				a[i/8] ^= 0x80 >> (i % 8)
			}
			return netip.AddrFrom16(a)
		}
		a := bases4[rng.IntN(len(bases4))]
		if rng.IntN(2) == 0 {
			i := rng.IntN(32)
			a[i/8] ^= 0x80 >> (i % 8)
		}
		return netip.AddrFrom4(a)
	}
	for round := range 1000 {
		for i := range bases4 {
			binary.BigEndian.PutUint32(bases4[i][:], rng.Uint32())
			binary.BigEndian.PutUint64(bases6[i][:8], rng.Uint64())
			binary.BigEndian.PutUint64(bases6[i][8:], rng.Uint64())
		}
		var ranges []types.PrefixRange
		for range rng.IntN(12) {
			v6 := rng.IntN(2) == 0
			maxBits := 32
			if v6 {
				maxBits = 128
			}
			bits := rng.IntN(maxBits + 1)
			lo := bits + rng.IntN(maxBits-bits+1)
			hi := lo + rng.IntN(maxBits-lo+1)
			r, ok := types.NewPrefixRange(netip.PrefixFrom(addr(v6), bits), lo, hi)
			if ok {
				ranges = append(ranges, r)
			}
		}
		x := newPrefixIndex(ranges)
		for range 200 {
			v6 := rng.IntN(2) == 0
			maxBits := 32
			if v6 {
				maxBits = 128
			}
			p := netip.PrefixFrom(addr(v6), rng.IntN(maxBits+1))
			want := false
			for _, r := range ranges {
				want = want || r.Contains(p)
			}
			if got := x.contains(p); got != want {
				t.Fatalf("round %d: ranges %v: contains(%s) = %v, want %v", round, ranges, p, got, want)
			}
		}
		if x.contains(netip.Prefix{}) {
			t.Fatalf("round %d: the zero prefix is contained", round)
		}
	}
}

func TestParseCommunity(t *testing.T) {
	for _, c := range []struct {
		in   string
		want uint32
		kind string
	}{
		{"65000:100", comm(65000, 100), ""},
		{"0:0", 0, ""},
		{"65535:65535", 0xFFFFFFFF, ""},
		{" 65000 : 100 ", comm(65000, 100), ""},
		{"4294967295", 0xFFFFFFFF, ""},
		{"100", 100, ""},
		{"no_export", 0xFFFFFF01, ""},
		{"No_Export", 0xFFFFFF01, ""},
		{"no_advertise", 0xFFFFFF02, ""},
		{"local_as", 0xFFFFFF03, ""},
		{"LOCAL_AS", 0xFFFFFF03, ""},
		{"internet", 0, ReasonCommInternet},
		{"Internet", 0, ReasonCommInternet},
		{"65536:1", 0, ReasonCommValue},
		{"1:65536", 0, ReasonCommValue},
		{"4294967296", 0, ReasonCommValue},
		{"-1", 0, ReasonCommValue},
		{"+1", 0, ReasonCommValue},
		{"1:2:3", 0, ReasonCommValue},
		{":1", 0, ReasonCommValue},
		{"1:", 0, ReasonCommValue},
		{"6 5000:1", 0, ReasonCommValue},
		{"{3561,70}", 0, ReasonCommValue},
		{"PeerAS:100", 0, ReasonCommValue},
		{"no_export_subconfed", 0xFFFFFF03, ""},
		{"NO_EXPORT_SUBCONFED", 0xFFFFFF03, ""},
		{"no_peer", 0, ReasonCommValue},
		{"", 0, ReasonCommValue},
		{"0x10", 0, ReasonCommValue},
		{"١٢", 0, ReasonCommValue},
	} {
		got, kind := parseCommunity(c.in)
		if kind != c.kind || kind == "" && got != c.want {
			t.Errorf("parseCommunity(%q) = %#x, %q; want %#x, %q", c.in, got, kind, c.want, c.kind)
		}
	}
}

// TestPathMemoBounded checks the memo's key bytes stay within its bound,
// counted right, and its answers stay right after it is cleared, from one
// goroutine and then from several.
func TestPathMemoBounded(t *testing.T) {
	old := memoKeyBytes
	memoKeyBytes = 40 // three keys of 12 or 16 bytes at most
	defer func() { memoKeyBytes = old }()
	f := normal(t, types.AFIv4, "<^PeerAS AS-CUST$>")
	c := Compile(pol(pclause(0, f)))
	for round := range 3 {
		for i := range 20 {
			// AS-CUST is AS64501 and AS64502: [peer, last] is accepted
			// unless last is AS64503; [peer, 65000+i, last] never is.
			last := types.ASN(64501 + i%3)
			r := route("192.0.2.0/24", peer, last)
			want := Accepted
			if last == 64503 {
				want = Rejected
			}
			if i%2 == 0 {
				r = route("192.0.2.0/24", peer, types.ASN(65000+i), last)
				want = Rejected
			}
			if v := c.Decide(r); v.Outcome != want {
				t.Fatalf("round %d, path %v: %+v, want %v", round, r.Path, v, want)
			}
			if counted, held := c.memoBytes(); counted != held || held > memoKeyBytes {
				t.Fatalf("memo counts %d key bytes, holds %d, bound %d", counted, held, memoKeyBytes)
			}
		}
	}

	c = Compile(pol(pclause(0, f)))
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 200 {
				last := types.ASN(64501 + (i+g)%3)
				want := Accepted
				if last == 64503 {
					want = Rejected
				}
				if v := c.Decide(route("192.0.2.0/24", peer, last)); v.Outcome != want {
					t.Errorf("goroutine %d, last AS%d: %+v, want %v", g, last, v, want)
					return
				}
			}
		}()
	}
	wg.Wait()
	if counted, held := c.memoBytes(); counted != held || held > memoKeyBytes {
		t.Fatalf("memo counts %d key bytes, holds %d, bound %d", counted, held, memoKeyBytes)
	}
}

// TestMemoKeyOverBound checks a key longer than the whole bound is answered
// and not kept.
func TestMemoKeyOverBound(t *testing.T) {
	old := memoKeyBytes
	memoKeyBytes = 8
	defer func() { memoKeyBytes = old }()
	c := Compile(pol(pclause(0, normal(t, types.AFIv4, "<^PeerAS AS-CUST$>"))))
	if v := c.Decide(route("192.0.2.0/24", peer, 64501)); v.Outcome != Accepted {
		t.Fatalf("%+v, want Accepted", v)
	}
	if counted, held := c.memoBytes(); counted != 0 || held != 0 {
		t.Errorf("memo holds %d (counted %d) key bytes, want none", held, counted)
	}
}

// TestDecideAllocs pins "no allocation per clause beyond the verdict": a
// route that passes undecided-free through several clauses of prefix, path
// and community tests allocates only its path's memo key.
func TestDecideAllocs(t *testing.T) {
	v4 := types.AFIv4
	c := Compile(pol(
		pclause(0, normal(t, v4, "AS-CUST AND <^PeerAS AS-CUST$>")),
		pclause(1, normal(t, v4, "<AS64666> OR community(1:1)")),
		pclause(2, normal(t, v4, "NOT <AS64666> AND community(65000:100)")),
	))
	r := route("203.0.113.0/24", peer, 64501).comms(comm(65000, 100))
	if v := c.Decide(r); !sameVerdict(v, accepted(2)) {
		t.Fatalf("Decide = %+v, want accepted by clause 2", v)
	}
	if n := testing.AllocsPerRun(100, func() { c.Decide(r) }); n > 1 {
		t.Errorf("Decide allocates %v times, want at most 1 (the memo key)", n)
	}
}

// TestOutcomeText: an Outcome writes as its name, in text and in JSON.
func TestOutcomeText(t *testing.T) {
	for o, want := range map[Outcome]string{Accepted: "accepted", Rejected: "rejected", Undecided: "undecided", 0: "Outcome(0)", 9: "Outcome(9)"} {
		if got := o.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", uint8(o), got, want)
		}
		b, err := o.MarshalText()
		if err != nil || string(b) != want {
			t.Errorf("%d.MarshalText() = %q, %v; want %q", uint8(o), b, err, want)
		}
	}
}
