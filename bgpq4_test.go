package routecheck_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/routecheck/verdict"
	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/irrdq"
	"github.com/rkolesnichenko/rpsl/resolve/irrdserver"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

// The bgpq4 differential (spec §10): for a prefix-only policy, "from AS64500
// accept S", verdict accepts a route exactly when its prefix is in bgpq4's
// expansion of S. The registry is rpsl v0.30.0's bgpq4 snapshot
// (testdata/irr/snapshot, synthetic), served to bgpq4 by rpsl's IRRd-compatible
// server (resolve/irrdq, resolve/irrdserver) on a localhost port; the
// policy, testdata/irr/policies.txt, is evaluated by peval over the same
// objects. The test skips when bgpq4 is not on PATH, and fails instead with
// ROUTECHECK_ORACLES_REQUIRED=1 (CI sets it).

// bgpq4Flags are rpsl's differential's: JSON, documentation and private ASNs
// kept (-p), list name x, as-set recursion depth 64. No -A, -R, -r or -m, so
// bgpq4 neither aggregates nor widens the ranges it prints.
var bgpq4Flags = []string{"-j", "-p", "-l", "x", "-L", "64"}

// bgpq4Sources is the source precedence, the server's and the policy side's.
var bgpq4Sources = []string{"TEST", "RADB"}

const (
	diffLocal = types.ASN(64496)
	diffPeer  = types.ASN(64500)
)

func TestPrefixPolicyMatchesBgpq4(t *testing.T) {
	if _, err := exec.LookPath("bgpq4"); err != nil {
		if os.Getenv("ROUTECHECK_ORACLES_REQUIRED") == "1" {
			t.Fatal("bgpq4 is not on PATH, and ROUTECHECK_ORACLES_REQUIRED=1")
		}
		t.Skip("bgpq4 is not on PATH")
	}
	objs, sets := readDiffRegistry(t)
	addr := serveDiffRegistry(t, objs)

	all := &resolve.Corpus{KeepPolicy: true}
	for _, o := range objs {
		all.Put(o.obj)
	}
	ev := peval.Evaluator{Src: all.Source(bgpq4Sources...)}
	ctx := context.Background()

	// Prefixes the registry names in each family: probes for every set,
	// so that each is checked against prefixes it must reject too.
	probes := map[bool][]netip.Prefix{}
	for _, o := range objs {
		for _, attr := range []string{"route", "route6", "members", "mp-members"} {
			for _, v := range o.values[attr] {
				for _, item := range strings.Split(v, ",") {
					item = strings.TrimSpace(item)
					if i := strings.IndexByte(item, '^'); i >= 0 {
						item = item[:i]
					}
					if p, err := netip.ParsePrefix(item); err == nil {
						probes[p.Addr().Is6()] = append(probes[p.Addr().Is6()], p)
					}
				}
			}
		}
	}

	type family struct {
		name, flag string
		v6         bool
	}
	var bad []string
	for _, fam := range []family{{"ipv4.unicast", "-4", false}, {"ipv6.unicast", "-6", true}} {
		af, err := types.ParseAddrFamily(fam.name)
		if err != nil {
			t.Fatal(err)
		}
		p, err := ev.Import(ctx, peval.Session{Local: diffLocal, Peer: diffPeer, AF: af})
		if err != nil {
			t.Fatalf("%s: Import: %v", fam.name, err)
		}
		if len(p.Undecided) > 0 {
			t.Fatalf("%s: undecided terms %v", fam.name, p.Undecided)
		}
		clauses := map[string]peval.Clause{}
		for _, c := range p.Clauses {
			clauses[fmt.Sprint(c.Term.Filter)] = c
		}
		for _, set := range sets {
			c, ok := clauses[set]
			if !ok {
				t.Fatalf("%s: policies.txt has no term accepting %s", fam.name, set)
			}
			// One clause alone: the aut-num's other terms would accept a
			// route first whenever two sets share a prefix.
			compiled := verdict.Compile(peval.Policy{Clauses: []peval.Clause{c}})
			ranges := runBgpq4(t, addr, fam.flag, set)
			cands := candidates(ranges, probes[fam.v6], fam.v6)
			accepted := 0
			for _, q := range cands {
				want := slices.ContainsFunc(ranges, func(r types.PrefixRange) bool { return r.Contains(q) })
				got := compiled.Decide(verdict.Route{Prefix: q, Path: []types.ASN{diffPeer}, PathKnown: true, CommsKnown: true})
				if got.Outcome == verdict.Accepted {
					accepted++
				}
				if (got.Outcome == verdict.Accepted) != want || got.Outcome == verdict.Undecided {
					bad = append(bad, fmt.Sprintf("%s %s %s: bgpq4 lists it %v, verdict %+v (clause filter %s)", set, fam.flag, q, want, got, c.Filter))
				}
			}
			t.Logf("%-16s %s: %3d routes compared, %2d bgpq4 entries, %3d accepted", set, fam.flag, len(cands), len(ranges), accepted)
			if len(cands) == 0 {
				t.Errorf("%s %s: no route compared", set, fam.flag)
			}
		}
	}
	if len(bad) > 0 {
		t.Errorf("%d disagreements with bgpq4; the first %d:\n%s", len(bad), min(len(bad), 10), strings.Join(bad[:min(len(bad), 10)], "\n"))
	}
}

// diffObject is one object of the registry, decoded, with its source and
// its attribute values by name.
type diffObject struct {
	obj    rpsl.Object
	source string
	values map[string][]string
}

// readDiffRegistry reads the snapshot and the policies, and returns the
// objects and the names of the snapshot's as-sets and route-sets, each once,
// in file order.
func readDiffRegistry(t *testing.T) ([]diffObject, []string) {
	t.Helper()
	files := []string{
		"testdata/irr/snapshot/as-sets.txt", "testdata/irr/snapshot/route-sets.txt",
		"testdata/irr/snapshot/routes.txt", "testdata/irr/snapshot/claims.txt",
		"testdata/irr/policies.txt",
	}
	var objs []diffObject
	var sets []string
	for _, name := range files {
		data, err := os.ReadFile(filepath.FromSlash(name))
		if err != nil {
			t.Fatal(err)
		}
		for o, diags := range rpsl.Parse(bytes.NewReader(data)) {
			if o == nil {
				t.Fatalf("%s: %v", name, diags)
			}
			obj, _ := rpsl.Decode(o)
			if obj == nil {
				t.Fatalf("%s: %s %s does not decode", name, o.Class(), o.Key())
			}
			d := diffObject{obj: obj, values: map[string][]string{}}
			for _, a := range o.Attributes() {
				n := a.Name
				d.values[n] = append(d.values[n], a.Value)
			}
			if v := d.values["source"]; len(v) > 0 {
				d.source = strings.ToUpper(strings.TrimSpace(v[0]))
			}
			objs = append(objs, d)
			if c := strings.ToLower(o.Class()); (c == "as-set" || c == "route-set") && !slices.Contains(sets, strings.ToUpper(o.Key())) {
				sets = append(sets, strings.ToUpper(o.Key()))
			}
		}
	}
	return objs, sets
}

// serveDiffRegistry serves the objects as rpsld would, one registry per
// source (TEST, then RADB), on a localhost port until the test ends; it
// returns the address.
func serveDiffRegistry(t *testing.T, objs []diffObject) string {
	t.Helper()
	var regs []*irrdq.Registry
	for _, src := range bgpq4Sources {
		c := &resolve.Corpus{KeepPolicy: true, KeepRouteText: true}
		for _, o := range objs {
			if o.source == src {
				c.Put(o.obj)
			}
		}
		r, err := irrdq.NewRegistry(src, 0, c)
		if err != nil {
			t.Fatal(err)
		}
		regs = append(regs, r)
	}
	snap, err := irrdq.NewSnapshot(regs, irrdq.SnapshotOptions{Default: bgpq4Sources})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &irrdserver.Server{Snapshot: func() *irrdq.Snapshot { return snap }}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
		if err := <-done; err != nil && !errors.Is(err, irrdserver.ErrServerClosed) {
			t.Errorf("Serve: %v", err)
		}
	})
	return ln.Addr().String()
}

// runBgpq4 runs bgpq4 for set in one family (-4 or -6) and returns its list
// as ranges: an entry that is not exact covers the lengths from its
// greater-equal (its own length when absent) to its less-equal (the
// family's longest when absent).
func runBgpq4(t *testing.T, addr, famFlag, set string) []types.PrefixRange {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	args := append(append([]string{"-h", addr}, bgpq4Flags...), "-S", strings.Join(bgpq4Sources, ","), famFlag, set)
	cmd := exec.CommandContext(ctx, "bgpq4", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("bgpq4 %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	var doc map[string][]struct {
		Prefix string `json:"prefix"`
		Exact  bool   `json:"exact"`
		GE     *int   `json:"greater-equal"`
		LE     *int   `json:"less-equal"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("bgpq4 %s: bad JSON %q: %v", strings.Join(args, " "), out, err)
	}
	entries, ok := doc["x"]
	if !ok {
		t.Fatalf("bgpq4 %s: no list x in %q", strings.Join(args, " "), out)
	}
	var ranges []types.PrefixRange
	for _, e := range entries {
		p, err := netip.ParsePrefix(e.Prefix)
		if err != nil {
			t.Fatalf("bgpq4 %s: entry %q: %v", strings.Join(args, " "), e.Prefix, err)
		}
		lo, hi := p.Bits(), p.Bits()
		if !e.Exact {
			if e.GE != nil {
				lo = *e.GE
			}
			hi = p.Addr().BitLen()
			if e.LE != nil {
				hi = *e.LE
			}
		}
		r, ok := types.NewPrefixRange(p, lo, hi)
		if !ok {
			t.Fatalf("bgpq4 %s: entry %+v is no range", strings.Join(args, " "), e)
		}
		ranges = append(ranges, r)
	}
	return ranges
}

// candidates returns the routes to decide for a set in one family: every
// prefix bgpq4 listed and every probe, each with its two halves and its
// covering prefix, and for a listed range its first prefix of each length
// from one under the range to one over it; deduplicated and sorted.
func candidates(ranges []types.PrefixRange, probes []netip.Prefix, v6 bool) []netip.Prefix {
	seen := map[netip.Prefix]bool{}
	add := func(p netip.Prefix) {
		if p.Addr().Is6() != v6 {
			return
		}
		seen[p.Masked()] = true
	}
	around := func(p netip.Prefix) {
		add(p)
		if p.Bits() > 0 {
			add(netip.PrefixFrom(p.Addr(), p.Bits()-1))
		}
		if p.Bits() < p.Addr().BitLen() {
			add(netip.PrefixFrom(p.Addr(), p.Bits()+1))
			add(netip.PrefixFrom(setBit(p.Addr(), p.Bits()), p.Bits()+1))
		}
	}
	for _, r := range ranges {
		around(r.Prefix())
		for l := max(r.Lo()-1, 0); l <= min(r.Hi()+1, r.Prefix().Addr().BitLen()); l++ {
			add(netip.PrefixFrom(r.Prefix().Addr(), l))
		}
	}
	for _, p := range probes {
		around(p)
	}
	out := make([]netip.Prefix, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return out
}

// setBit returns a with bit i (from the left) set.
func setBit(a netip.Addr, i int) netip.Addr {
	raw := a.AsSlice()
	raw[i/8] |= 0x80 >> (i % 8)
	out, _ := netip.AddrFromSlice(raw)
	return out
}
