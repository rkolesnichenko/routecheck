package routecheck_test

import (
	"compress/gzip"
	"context"
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
	reg := loadRegistry(t, dumps)

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
	r.report(&rep, 1, "x")
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
