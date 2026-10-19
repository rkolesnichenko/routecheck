package routecheck_test

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/rkolesnichenko/routecheck"
	"github.com/rkolesnichenko/routecheck/verdict"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/resolve/rpki"
	"github.com/rkolesnichenko/rpsl/types"
)

func TestDumpRegistry(t *testing.T) {
	for _, c := range []struct {
		name string
		reg  string
		ok   bool
	}{
		{"ripe.db.aut-num.gz", "ripe", true},
		{"apnic.db.route6.gz", "apnic", true},
		{"radb.db.gz", "radb", true},
		{"nttcom.db.gz", "nttcom", true},
		{"level3.db.gz", "", false},
		{"rv2-rib.20261018.1200.bz2", "", false},
		{"ripe.gz", "", false},
	} {
		reg, ok := dumpRegistry(c.name)
		if reg != c.reg || ok != c.ok {
			t.Errorf("dumpRegistry(%q) = %q, %v; want %q, %v", c.name, reg, ok, c.reg, c.ok)
		}
	}
}

func TestOrderDumps(t *testing.T) {
	in := []string{"altdb.db.gz", "radb.db.gz", "apnic.db.route.gz", "ripe.db.aut-num.gz", "arin.db.gz", "ripe.db.as-set.gz"}
	want := []string{"ripe.db.aut-num.gz", "ripe.db.as-set.gz", "apnic.db.route.gz", "arin.db.gz", "radb.db.gz", "altdb.db.gz"}
	orig := slices.Clone(in)
	if got := orderDumps(in); !slices.Equal(got, want) {
		t.Errorf("orderDumps(%v) = %v, want %v", in, got, want)
	}
	if !slices.Equal(in, orig) {
		t.Errorf("orderDumps changed its argument: %v, was %v", in, orig)
	}
}

func TestChooseDumps(t *testing.T) {
	dumps := []string{"ripe.db.aut-num.gz", "ripe.db.as-set.gz", "radb.db.gz"}
	for _, c := range []struct {
		want string
		out  []string
		err  string // "" for success
	}{
		{"", dumps, ""},
		{"RIPE", dumps[:2], ""},
		{"ripe,radb", dumps, ""},
		{"ripe,arin", nil, "arin"},
		{"foo", nil, "foo"},
	} {
		got, err := chooseDumps(dumps, c.want)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("chooseDumps(%q): error %v, want one containing %q", c.want, err, c.err)
			}
			continue
		}
		if err != nil || !slices.Equal(got, c.out) {
			t.Errorf("chooseDumps(%q) = %v, %v; want %v", c.want, got, err, c.out)
		}
	}
}

// writeGzip writes the objects (separated by a blank line) to dir/name,
// gzipped.
func writeGzip(t *testing.T, dir, name string, objects ...string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	if _, err := zw.Write([]byte(strings.Join(objects, "\n\n") + "\n")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadRegistryPrecedenceAndSelection(t *testing.T) {
	dir := t.TempDir()
	dumps := []string{
		writeGzip(t, dir, "ripe.db.aut-num.gz",
			"aut-num: AS64496\nimport: from AS64500 accept AS-X\nsource: RIPE"),
		writeGzip(t, dir, "ripe.db.as-set.gz",
			"as-set: AS-X\nmembers: AS64501\nsource: RIPE"),
		writeGzip(t, dir, "radb.db.gz",
			"aut-num: AS64497\nimport: from AS64500 accept ANY\nsource: RADB",
			"as-set: AS-X\nmembers: AS64502\nsource: RADB",
			"as-set: AS-Y\nmembers: AS64503\nsource: RADB"),
	}
	reg := loadRegistry(t, dumps, "", nil)

	if want := map[types.ASN]bool{64496: true}; !reflect.DeepEqual(reg.autnums, want) {
		t.Errorf("autnums = %v, want %v", reg.autnums, want)
	}
	if len(reg.imports) != 1 || len(reg.imports[64496]) != 1 {
		t.Errorf("imports = %v, want only AS64496", reg.imports)
	}
	if want := []string{"RIPE", "RADB"}; !slices.Equal(reg.sources, want) {
		t.Errorf("sources = %v, want %v", reg.sources, want)
	}
	if want := map[string]int{"RIPE": 2, "RADB": 3}; !reflect.DeepEqual(reg.perSource, want) {
		t.Errorf("perSource = %v, want %v", reg.perSource, want)
	}
	if want := []string{"ripe", "radb"}; !slices.Equal(reg.registries, want) {
		t.Errorf("registries = %v, want %v", reg.registries, want)
	}

	ex := &resolve.Expander{Src: reg.src}
	for _, c := range []struct {
		set  string
		want []types.ASN
	}{
		{"AS-X", []types.ASN{64501}}, // RIPE's wins over RADB's
		{"AS-Y", []types.ASN{64503}}, // only RADB has it
	} {
		ref, err := types.ParseSetRef(c.set)
		if err != nil {
			t.Fatal(err)
		}
		res, err := ex.ExpandAS(context.Background(), ref)
		if err != nil {
			t.Fatalf("ExpandAS(%s): %v", c.set, err)
		}
		if got := res.List(); !slices.Equal(got, c.want) {
			t.Errorf("ExpandAS(%s) = %v, want %v", c.set, got, c.want)
		}
	}
}

func TestReportTalliesMissingSetsAndRouteObjects(t *testing.T) {
	ref := func(s string) types.SetRef {
		r, err := types.ParseSetRef(s)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	yes, no := true, false
	rep := routecheck.Report{Policy: peval.Policy{Clauses: make([]peval.Clause, 1)}, Routes: []routecheck.RouteVerdict{
		{
			Verdict: verdict.Verdict{Outcome: verdict.Rejected, Fails: []verdict.Fail{
				{Missing: []types.SetRef{ref("AS-A")}},
				{Missing: []types.SetRef{ref("AS-A"), ref("AS-B")}},
			}},
			RouteObj: &yes,
		},
		{
			Verdict:  verdict.Verdict{Outcome: verdict.Rejected, Fails: []verdict.Fail{{Missing: []types.SetRef{ref("AS-B")}}}},
			RouteObj: &no,
		},
		{Verdict: verdict.Verdict{Outcome: verdict.Accepted}},
	}}
	r := pairResult{
		reasons: [2]tally{{}, {}}, tooExp: tally{}, unevaluable: tally{}, anySets: tally{},
		missingSets: [2]tally{{}, {}}, routeObj: [2]tally{{}, {}},
	}
	r.report(&rep, 1, "x", reportCtx{pair: "AS1-AS2", family: "ipv4.unicast", neighbour: "AS1"})
	if r.rejMissing[1] != 2 {
		t.Errorf("rejMissing[1] = %d, want 2", r.rejMissing[1])
	}
	if want := (tally{"AS-A": 1, "AS-B": 2}); !reflect.DeepEqual(r.missingSets[1], want) {
		t.Errorf("missingSets[1] = %v, want %v", r.missingSets[1], want)
	}
	if want := (tally{"yes": 1, "no": 1, "unknown": 1}); !reflect.DeepEqual(r.routeObj[1], want) {
		t.Errorf("routeObj[1] = %v, want %v", r.routeObj[1], want)
	}
	if len(r.missingSets[0]) != 0 || len(r.routeObj[0]) != 0 {
		t.Errorf("direction 0 was touched: %v %v", r.missingSets[0], r.routeObj[0])
	}
	if got := topN(tally{"AS-B": 2, "AS-A": 1, "AS-C": 2}, 2); got != "AS-B 2, AS-C 2" {
		t.Errorf("topN = %q", got)
	}
	if got := topN(tally{}, 5); got != "" {
		t.Errorf("topN of empty = %q", got)
	}
}

func exportRoute(known bool) verdict.Route {
	return verdict.Route{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Path: []types.ASN{6762, 3356}, PathKnown: known}
}

func TestRouteKey(t *testing.T) {
	af := types.AddrFamily{AFI: types.AFIv4, SAFI: types.SAFIUnicast}
	got := routeKey("AS9086-AS6762", "export", af.String(), "AS174", exportRoute(true))
	if want := "AS9086-AS6762|export|ipv4.unicast|AS174|192.0.2.0/24|AS6762 AS3356"; got != want {
		t.Errorf("routeKey = %q, want %q", got, want)
	}
	got = routeKey("AS9086-AS6762", "export", af.String(), "AS174", exportRoute(false))
	if want := "AS9086-AS6762|export|ipv4.unicast|AS174|192.0.2.0/24|AS6762 AS3356 ?"; got != want {
		t.Errorf("routeKey, path unknown = %q, want %q", got, want)
	}
}

func TestRouteKeyUnique(t *testing.T) {
	rv := routecheck.RouteVerdict{Route: exportRoute(true), Verdict: verdict.Verdict{Outcome: verdict.Accepted}}
	rep := routecheck.Report{Policy: peval.Policy{Clauses: make([]peval.Clause, 1)}, Routes: []routecheck.RouteVerdict{rv, rv}}
	r := newTestPair()
	r.report(&rep, 1, "x", reportCtx{pair: "AS1-AS2", family: "ipv4.unicast", neighbour: "AS3"})
	if r.dupKeys != 1 {
		t.Errorf("dupKeys = %d, want 1", r.dupKeys)
	}
}

func newTestPair() pairResult {
	return pairResult{
		reasons: [2]tally{{}, {}}, tooExp: tally{}, unevaluable: tally{}, anySets: tally{},
		missingSets: [2]tally{{}, {}}, routeObj: [2]tally{{}, {}},
	}
}

func TestTrackedLines(t *testing.T) {
	ref := func(s string) types.SetRef {
		r, err := types.ParseSetRef(s)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	route := func(pfx string) verdict.Route {
		return verdict.Route{Prefix: netip.MustParsePrefix(pfx), Path: []types.ASN{2}, PathKnown: true}
	}
	rep := routecheck.Report{Policy: peval.Policy{Clauses: make([]peval.Clause, 1)}, Routes: []routecheck.RouteVerdict{
		{Route: route("192.0.2.0/24"), Verdict: verdict.Verdict{Outcome: verdict.Rejected, Fails: []verdict.Fail{
			{Missing: []types.SetRef{ref("AS-B")}},
			{Missing: []types.SetRef{ref("AS-A")}},
			{Missing: []types.SetRef{ref("AS-A")}},
		}}},
		{Route: route("198.51.100.0/24"), Verdict: verdict.Verdict{Outcome: verdict.Undecided, Reasons: []verdict.Reason{
			{Kind: verdict.ReasonUnevaluable}, {Kind: verdict.ReasonPeval, Why: "x"},
		}}},
		{Route: route("203.0.113.0/24"), Verdict: verdict.Verdict{Outcome: verdict.Accepted}},
		{Route: route("100.64.0.0/10"), Verdict: verdict.Verdict{Outcome: verdict.Accepted, Reasons: []verdict.Reason{{Kind: verdict.ReasonPeval, Why: "x"}}}},
	}}
	r := newTestPair()
	ctx := reportCtx{pair: "AS1-AS2", family: "ipv4.unicast", neighbour: "AS2"}
	r.track = map[string]bool{}
	for _, p := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "100.64.0.0/10"} {
		r.track[routeKey(ctx.pair, "import", ctx.family, ctx.neighbour, route(p))] = true
	}
	o, err := openRealOut(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer o.abort()
	if r.spool, err = o.spool(1); err != nil {
		t.Fatal(err)
	}
	r.report(&rep, 0, "x", ctx)
	pre := "AS1-AS2|import|ipv4.unicast|AS2|"
	want := map[string]string{
		pre + "192.0.2.0/24|AS2":    pre + "192.0.2.0/24|AS2\trejected\t\tAS-A,AS-B",
		pre + "198.51.100.0/24|AS2": pre + "198.51.100.0/24|AS2\tundecided\tpeval,unevaluable\t",
		pre + "203.0.113.0/24|AS2":  pre + "203.0.113.0/24|AS2\taccepted\t\t",
		pre + "100.64.0.0/10|AS2":   pre + "100.64.0.0/10|AS2\taccepted\t\t",
	}
	if !reflect.DeepEqual(r.lines, want) {
		t.Errorf("lines = %q, want %q", r.lines, want)
	}
	if err := r.spool.close(); err != nil {
		t.Fatal(err)
	}
	rej, err := os.ReadFile(r.spool.paths[1])
	if err != nil {
		t.Fatal(err)
	}
	if string(rej) != want[pre+"192.0.2.0/24|AS2"]+"\n" {
		t.Errorf("spooled rejected lines = %q", rej)
	}
}

func TestReadTrackKeys(t *testing.T) {
	f := filepath.Join(t.TempDir(), "track.tsv")
	if err := os.WriteFile(f, []byte("a|b\trejected\t\tAS-A\n\nc|d\taccepted\t\t\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	keys, err := readTrackKeys(f)
	if err != nil || !slices.Equal(keys, []string{"a|b", "c|d"}) {
		t.Errorf("readTrackKeys = %q, %v", keys, err)
	}
}

func TestRealOutTracked(t *testing.T) {
	dir := t.TempDir()
	track := filepath.Join(dir, "track.tsv")
	// A1-A2's key is checked and found; A3-A4's pair is not checked; A1-A2's
	// second key is missing from a completed pair.
	if err := os.WriteFile(track, []byte("AS1-AS2|k1\trejected\t\tAS-A\nAS3-AS4|k2\trejected\t\tAS-A\nAS1-AS2|k3\trejected\t\tAS-A\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	o, err := openRealOut(filepath.Join(dir, "out"), track)
	if err != nil {
		t.Fatal(err)
	}
	defer o.abort()
	r := newTestPair()
	r.p = pair{L: 1, X: 2}
	r.lines = map[string]string{"AS1-AS2|k1": "AS1-AS2|k1\taccepted\t\t"}
	if r.spool, err = o.spool(1); err != nil {
		t.Fatal(err)
	}
	r.spool.writeRejected("AS1-AS2|r\trejected\t\tAS-A")
	if err := o.addPair(&r); err != nil {
		t.Fatal(err)
	}
	if r.lines != nil || r.spool != nil {
		t.Error("addPair did not free the pair's lines")
	}
	tot := totals{missingSets: [2]tally{{"AS-B": 2, "AS-A": 1}, {"AS-C": 3}}}
	var errs []string
	if err := o.finish(&tot, func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }); err != nil {
		t.Fatal(err)
	}
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(dir, "out", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if got, want := read("tracked.tsv"), "AS1-AS2|k1\taccepted\t\t\nAS3-AS4|k2\tnone\t\t\nAS1-AS2|k3\tnone\t\t\n"; got != want {
		t.Errorf("tracked.tsv = %q, want %q", got, want)
	}
	if got, want := read("missing-sets.tsv"), "import\tAS-A\t1\nimport\tAS-B\t2\nexport\tAS-C\t3\n"; got != want {
		t.Errorf("missing-sets.tsv = %q, want %q", got, want)
	}
	if got, want := read("rejected-missing.tsv"), "AS1-AS2|r\trejected\t\tAS-A\n"; got != want {
		t.Errorf("rejected-missing.tsv = %q, want %q", got, want)
	}
	if len(errs) != 1 || !strings.Contains(errs[0], "AS1-AS2|k3") {
		t.Errorf("errors = %q, want one naming AS1-AS2|k3", errs)
	}
}

func TestParsePairSelection(t *testing.T) {
	for _, c := range []struct {
		sel  string
		n    int
		want []int
	}{
		{"", 3, []int{1, 2, 3}},
		{"1-2,3", 3, []int{1, 2, 3}},
		{"2", 3, []int{2}},
		{" 1 - 2 , 3 ", 3, []int{1, 2, 3}},
	} {
		got, err := parsePairSelection(c.sel, c.n)
		if err != nil {
			t.Errorf("parsePairSelection(%q, %d): %v", c.sel, c.n, err)
			continue
		}
		want := map[int]bool{}
		for _, i := range c.want {
			want[i] = true
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("parsePairSelection(%q, %d) = %v, want %v", c.sel, c.n, got, want)
		}
	}
	for _, c := range []struct{ sel, item string }{
		{"0", "0"}, {"4", "4"}, {"3-1", "3-1"}, {"1,,2", ""}, {"x", "x"},
	} {
		_, err := parsePairSelection(c.sel, 3)
		if err == nil {
			t.Errorf("parsePairSelection(%q, 3): no error", c.sel)
		} else if !strings.Contains(err.Error(), fmt.Sprintf("%q", c.item)) {
			t.Errorf("parsePairSelection(%q, 3): error %q does not name the item %q", c.sel, err, c.item)
		}
	}
}

func TestLoadRegistryExtraDumpRanksLast(t *testing.T) {
	dir := t.TempDir()
	dumps := []string{
		writeGzip(t, dir, "ripe.db.gz",
			"aut-num: AS64496\nimport: from AS64500 accept AS-X\nsource: RIPE",
			"as-set: AS-X\nmembers: AS64501\nsource: RIPE"),
		writeGzip(t, dir, "radb.db.gz",
			"as-set: AS-Y\nmembers: AS64503\nsource: RADB"),
	}
	extra := writeGzip(t, dir, "extra.db.gz",
		"as-set: AS-NEW\nmembers: AS64504\nsource: LEVEL3",
		"aut-num: AS64499\nimport: from AS64500 accept ANY\nsource: RIPE")
	reg := loadRegistry(t, dumps, extra, nil)

	if want := []string{"RIPE", "RADB", "LEVEL3"}; !slices.Equal(reg.sources, want) {
		t.Errorf("sources = %v, want %v", reg.sources, want)
	}
	if want := []string{"ripe", "radb", "extra"}; !slices.Equal(reg.registries, want) {
		t.Errorf("registries = %v, want %v", reg.registries, want)
	}
	if want := map[types.ASN]bool{64496: true}; !reflect.DeepEqual(reg.autnums, want) {
		t.Errorf("autnums = %v, want %v (the extra dump must not feed the selection)", reg.autnums, want)
	}
	if _, ok := reg.imports[64499]; ok {
		t.Errorf("imports holds the extra dump's aut-num: %v", reg.imports)
	}
	ref, err := types.ParseSetRef("AS-NEW")
	if err != nil {
		t.Fatal(err)
	}
	ex := &resolve.Expander{Src: reg.src}
	res, err := ex.ExpandAS(context.Background(), ref)
	if err != nil {
		t.Fatalf("ExpandAS(AS-NEW): %v", err)
	}
	if got, want := res.List(), []types.ASN{64504}; !slices.Equal(got, want) {
		t.Errorf("AS-NEW = %v, want %v", got, want)
	}
}

func TestParseRoutesFrom(t *testing.T) {
	got, err := parseRoutesFrom("")
	if err != nil || got != nil {
		t.Errorf(`parseRoutesFrom("") = %v, %v, want nil, nil`, got, err)
	}
	got, err = parseRoutesFrom("RIPE, apnic")
	if want := map[string]bool{"ripe": true, "apnic": true}; err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf(`parseRoutesFrom("RIPE, apnic") = %v, %v, want %v`, got, err, want)
	}
	if _, err := parseRoutesFrom("ripe,nope"); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Errorf(`parseRoutesFrom("ripe,nope") error = %v, want one naming nope`, err)
	}
	if _, err := parseRoutesFrom("ripe,,apnic"); err == nil {
		t.Errorf(`parseRoutesFrom("ripe,,apnic"): no error`)
	}
}

func TestLoadRegistryRoutesFrom(t *testing.T) {
	dir := t.TempDir()
	dumps := []string{
		writeGzip(t, dir, "ripe.db.route.gz",
			"route: 192.0.2.0/24\norigin: AS64496\nsource: RIPE"),
		writeGzip(t, dir, "radb.db.gz",
			"route: 198.51.100.0/24\norigin: AS64496\nsource: RADB",
			"route: 203.0.113.0/24\norigin: AS64497\nmember-of: RS-X\nsource: RADB",
			"route-set: RS-X\nmbrs-by-ref: ANY\nsource: RADB",
			"as-set: AS-Y\nmembers: AS64503\nsource: RADB"),
	}
	prefixes := func(reg *irrRegistry, as types.ASN) []string {
		ps, err := reg.src.OriginatedRoutes(context.Background(), as, types.AFIv4)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, p := range ps {
			out = append(out, p.String())
		}
		slices.Sort(out)
		return out
	}
	expandRS := func(reg *irrRegistry) []netip.Prefix {
		ref, err := types.ParseSetRef("RS-X")
		if err != nil {
			t.Fatal(err)
		}
		res, err := (&resolve.Expander{Src: reg.src}).ExpandPrefixes(context.Background(), ref)
		if err != nil {
			t.Fatalf("ExpandPrefixes(RS-X): %v", err)
		}
		return res.List()
	}

	reg := loadRegistry(t, dumps, "", map[string]bool{"ripe": true})
	if got, want := prefixes(reg, 64496), []string{"192.0.2.0/24"}; !slices.Equal(got, want) {
		t.Errorf("AS64496 routes = %v, want %v", got, want)
	}
	if got := prefixes(reg, 64497); len(got) != 0 {
		t.Errorf("AS64497 routes = %v, want none", got)
	}
	ref, err := types.ParseSetRef("AS-Y")
	if err != nil {
		t.Fatal(err)
	}
	if res, err := (&resolve.Expander{Src: reg.src}).ExpandAS(context.Background(), ref); err != nil || !slices.Equal(res.List(), []types.ASN{64503}) {
		t.Errorf("ExpandAS(AS-Y) = %v, %v, want [64503]", res.List(), err)
	}
	if got := expandRS(reg); len(got) != 0 {
		t.Errorf("ExpandPrefixes(RS-X) = %v, want empty", got)
	}
	if want := map[string]int{"radb": 2}; !reflect.DeepEqual(reg.droppedRoutes, want) {
		t.Errorf("droppedRoutes = %v, want %v", reg.droppedRoutes, want)
	}
	if reg.droppedClaims != 1 {
		t.Errorf("droppedClaims = %d, want 1", reg.droppedClaims)
	}

	all := loadRegistry(t, dumps, "", nil)
	if got, want := prefixes(all, 64496), []string{"192.0.2.0/24", "198.51.100.0/24"}; !slices.Equal(got, want) {
		t.Errorf("nil: AS64496 routes = %v, want %v", got, want)
	}
	if got := expandRS(all); len(got) != 1 || got[0].String() != "203.0.113.0/24" {
		t.Errorf("nil: ExpandPrefixes(RS-X) = %v, want [203.0.113.0/24]", got)
	}
	if len(all.droppedRoutes) != 0 || all.droppedClaims != 0 {
		t.Errorf("nil: dropped %v, %d", all.droppedRoutes, all.droppedClaims)
	}
}

func TestRouteLineV2(t *testing.T) {
	yes := true
	valid := rpki.Valid
	acc := &routecheck.RouteVerdict{Route: exportRoute(true), RouteObj: &yes, RPKI: &valid,
		Verdict: verdict.Verdict{Outcome: verdict.Accepted, Reasons: []verdict.Reason{{Kind: verdict.ReasonPeval}}}}
	if got, want := routeLineV2("k", acc), "k\taccepted\tyes\tvalid\t"; got != want {
		t.Errorf("accepted: %q, want %q", got, want)
	}
	und := &routecheck.RouteVerdict{Route: exportRoute(true),
		Verdict: verdict.Verdict{Outcome: verdict.Undecided, Reasons: []verdict.Reason{{Kind: verdict.ReasonUnevaluable}, {Kind: verdict.ReasonPeval}, {Kind: verdict.ReasonPeval}}}}
	if got, want := routeLineV2("k", und), "k\tundecided\tunknown\tnone\tpeval,unevaluable"; got != want {
		t.Errorf("undecided: %q, want %q", got, want)
	}
	no := false
	inv := rpki.Invalid
	rej := &routecheck.RouteVerdict{Route: exportRoute(true), RouteObj: &no, RPKI: &inv, Verdict: verdict.Verdict{Outcome: verdict.Rejected}}
	if got, want := routeLineV2("k", rej), "k\trejected\tno\tinvalid\t"; got != want {
		t.Errorf("rejected: %q, want %q", got, want)
	}
}

func TestRealOutRoutesStream(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	o, err := openRealOut(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer o.abort()
	yes := true
	valid := rpki.Valid
	route := func(pfx string) verdict.Route {
		return verdict.Route{Prefix: netip.MustParsePrefix(pfx), Path: []types.ASN{2}, PathKnown: true}
	}
	rep := routecheck.Report{Policy: peval.Policy{Clauses: make([]peval.Clause, 1)}, Routes: []routecheck.RouteVerdict{
		{Route: route("192.0.2.0/24"), RouteObj: &yes, RPKI: &valid, Verdict: verdict.Verdict{Outcome: verdict.Accepted}},
		{Route: route("198.51.100.0/24"), Verdict: verdict.Verdict{Outcome: verdict.Undecided, Reasons: []verdict.Reason{{Kind: verdict.ReasonUnevaluable}}}},
	}}
	ctx := reportCtx{pair: "AS1-AS2", family: "ipv4.unicast", neighbour: "AS2"}
	r := newTestPair()
	r.p = pair{L: 1, X: 2}
	if r.spool, err = o.spool(1); err != nil {
		t.Fatal(err)
	}
	r.report(&rep, 0, "x", ctx)
	r.report(&routecheck.Report{NoPolicy: true, Routes: rep.Routes}, 1, "x", ctx)
	if err := o.addPair(&r); err != nil {
		t.Fatal(err)
	}
	o.setStatus(pair{L: 5, X: 6}, "not selected")
	to := newTestPair()
	to.p = pair{L: 3, X: 4}
	to.err, to.timeout = context.DeadlineExceeded, true
	if to.spool, err = o.spool(3); err != nil {
		t.Fatal(err)
	}
	to.spool.writeRoute("AS3-AS4|timed out")
	if err := o.addPair(&to); err != nil {
		t.Fatal(err)
	}
	if len(o.got) != 0 {
		t.Errorf("realOut holds %d route lines without TRACK", len(o.got))
	}
	if err := o.finish(&totals{}, t.Errorf); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(dir, "routes.tsv.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	pre := "AS1-AS2|import|ipv4.unicast|AS2|"
	want := pre + "192.0.2.0/24|AS2\taccepted\tyes\tvalid\t\n" + pre + "198.51.100.0/24|AS2\tundecided\tunknown\tnone\tunevaluable\n"
	if string(b) != want {
		t.Errorf("routes.tsv.gz = %q, want %q", b, want)
	}
	ps, err := os.ReadFile(filepath.Join(dir, "pairs.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "AS1-AS2\tchecked\nAS5-AS6\tnot selected\nAS3-AS4\ttimeout\n"; string(ps) != want {
		t.Errorf("pairs.tsv = %q, want %q", ps, want)
	}
}
