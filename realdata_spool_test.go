package routecheck_test

import (
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

// TestPairSpool writes three pairs' lines through their spools: the lines of
// the checked pairs reach routes.tsv.gz and rejected-missing.tsv in pair
// order, the failed pair's none, and no spool file remains.
func TestPairSpool(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	o, err := openRealOut(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer o.abort()
	for i, pr := range []struct {
		lines []string
		err   error
	}{
		{lines: []string{"a1", "a2"}},
		{lines: []string{"b1"}, err: errors.New("failed")},
		{lines: []string{"c1"}},
	} {
		sp, err := o.spool(i + 1)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range pr.lines {
			sp.writeRoute("route " + l)
			sp.writeRejected("rejected " + l)
		}
		r := newTestPair()
		r.p = pair{L: types.ASN(i + 1), X: 100}
		r.err, r.spool = pr.err, sp
		if err := o.addPair(&r); err != nil {
			t.Fatal(err)
		}
		if r.spool != nil {
			t.Error("addPair did not free the pair's spool")
		}
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
	if want := "route a1\nroute a2\nroute c1\n"; string(b) != want {
		t.Errorf("routes.tsv.gz = %q, want %q", b, want)
	}
	b, err = os.ReadFile(filepath.Join(dir, "rejected-missing.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "rejected a1\nrejected a2\nrejected c1\n"; string(b) != want {
		t.Errorf("rejected-missing.tsv = %q, want %q", b, want)
	}
	left, err := filepath.Glob(filepath.Join(dir, ".pair-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Errorf("spool files left: %q", left)
	}
}

// TestPairSpoolWithoutOut: without ROUTECHECK_REALDATA_OUT (a nil *realOut)
// there is no spool, writing to it does nothing and addPair writes nothing:
// no spool file appears in the working directory, where a relative path would
// land.
func TestPairSpoolWithoutOut(t *testing.T) {
	var o *realOut
	sp, err := o.spool(1)
	if err != nil || sp != nil {
		t.Fatalf("spool = %v, %v; want nil, nil", sp, err)
	}
	sp.writeRoute("route a1")
	sp.writeRejected("rejected a1")
	r := newTestPair()
	r.p = pair{L: 1, X: 2}
	r.spool = sp
	if err := o.addPair(&r); err != nil {
		t.Fatal(err)
	}
	left, err := filepath.Glob(".pair-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Errorf("spool files written without OUT: %q", left)
	}
}

// TestCheckPairStreams runs checkPair over collector RIBs (check_test.go's
// collectorRecs): each family's summary is what Check's Result says
// (TestCheckCollectorExportPerNeighbour), and the routes and rejected lines
// reach the outputs, import report first, then each export report by
// neighbour.
func TestCheckPairStreams(t *testing.T) {
	file := filepath.Join(t.TempDir(), "rib.mrt")
	if err := os.WriteFile(file, slices.Concat(collectorRecs()...), 0o644); err != nil {
		t.Fatal(err)
	}
	reg := &irrRegistry{src: registry(t, autL, autX)}
	dir := filepath.Join(t.TempDir(), "out")
	o, err := openRealOut(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer o.abort()
	sp, err := o.spool(1)
	if err != nil {
		t.Fatal(err)
	}
	p := pair{L: types.ASN(asL), X: types.ASN(asX)}
	r := checkPair(t, reg, nil, p, file, time.Minute, resolve.Expander{}, nil, sp, nil, 1)
	if r.err != nil {
		t.Fatal(r.err)
	}
	if r.through != 5 || r.info.Direct != 2 {
		t.Errorf("through %d, direct %d; want 5, 2", r.through, r.info.Direct)
	}
	if len(r.fams) != 2 {
		t.Fatalf("fams: %+v", r.fams)
	}
	v4 := r.fams[0]
	if v4.af.String() != "ipv4.unicast" || v4.obs != 3 || v4.impNoPolicy || v4.imp != (outcomes{2, 1, 0}) ||
		v4.neighbours != 2 || v4.expNoPolicy != 1 || v4.exp != (outcomes{1, 1, 0}) || v4.directNotCheck != 2 {
		t.Errorf("ipv4: %+v", v4)
	}
	if v6 := r.fams[1]; v6.af.String() != "ipv6.unicast" || v6.obs != 0 || v6.neighbours != 0 || v6.directNotCheck != 0 {
		t.Errorf("ipv6: %+v", v6)
	}
	if err := o.addPair(&r); err != nil {
		t.Fatal(err)
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
	var keys []string
	for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		k, rest, _ := strings.Cut(l, "\t")
		out, _, _ := strings.Cut(rest, "\t")
		keys = append(keys, k+" "+out)
	}
	imp, exp := "AS64496-AS64500|import|ipv4.unicast|AS64500|", "AS64496-AS64500|export|ipv4.unicast|AS64510|"
	want := []string{
		imp + "192.0.2.0/24|AS64500 accepted",
		imp + "198.51.100.0/24|AS64500 AS64501 accepted",
		imp + "203.0.113.0/24|AS64500 AS64502 rejected",
		exp + "192.0.2.0/24|AS64500 accepted",
		exp + "198.51.100.0/24|AS64500 AS64501 rejected",
	}
	if !slices.Equal(keys, want) {
		t.Errorf("routes.tsv.gz:\n got %q\nwant %q", keys, want)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".pair-*")); len(left) != 0 {
		t.Errorf("spool files left: %q", left)
	}
}
