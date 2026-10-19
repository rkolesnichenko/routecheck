package routecheck_test

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/rkolesnichenko/routecheck/internal/memprof"
	"github.com/rkolesnichenko/rpsl"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/types"
)

const memprofCorpus = `aut-num:    AS65001
as-name:    LOCAL
import:     from AS65002 accept ANY
export:     to AS65002 announce AS65001
source:     TEST

aut-num:    AS65002
as-name:    PEER
source:     TEST

aut-num:    AS65003
as-name:    OTHER
source:     TEST

as-set:     AS-ONE
members:    AS65001, AS65002
source:     TEST
`

func memprofRegistry(t *testing.T) *irrRegistry {
	t.Helper()
	c := &resolve.Corpus{KeepPolicy: true}
	for o := range rpsl.Parse(bytes.NewReader([]byte(memprofCorpus))) {
		if o == nil {
			t.Fatal("bad RPSL")
		}
		obj, _ := rpsl.Decode(o)
		if obj == nil {
			t.Fatalf("%s %s does not decode", o.Class(), o.Key())
		}
		c.Put(obj)
	}
	return &irrRegistry{src: resolve.NewCache(c.Source("TEST"), 0)}
}

func markFiles(t *testing.T, dir string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, "mark-*.pb.gz"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMarkingSourceDelegates(t *testing.T) {
	reg := memprofRegistry(t)
	dir := t.TempDir()
	s, err := memprof.Start(dir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	var logged []string
	logf := func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }
	p := pair{L: 65001, X: 65002}
	src := policySourceFor(reg, s, 7, p, logf)
	ctx := context.Background()

	for _, as := range []types.ASN{65001, 65003, 65002, 65001} {
		got, gotErr := src.AutNum(ctx, as, "")
		want, wantErr := reg.src.AutNum(ctx, as, "")
		if got != want || (gotErr == nil) != (wantErr == nil) {
			t.Errorf("AutNum(%v): got %v, %v; inner %v, %v", as, got, gotErr, want, wantErr)
		}
	}
	// L, X and L again are marked; the unrelated AS65003 is not.
	if n := len(markFiles(t, dir)); n != 3 {
		t.Errorf("%d mark files, want 3", n)
	}
	if len(logged) != 3 || logged[0][:len("MEMPROF: pair-7-autnum-1-AS65001 live ")] != "MEMPROF: pair-7-autnum-1-AS65001 live " {
		t.Errorf("log lines %q", logged)
	}
	for i, w := range []string{"pair-7-autnum-1-AS65001", "pair-7-autnum-2-AS65002", "pair-7-autnum-3-AS65001"} {
		if len(logged) > i && !bytes.Contains([]byte(logged[i]), []byte(w+" live ")) {
			t.Errorf("log line %d = %q, want label %s", i, logged[i], w)
		}
	}

	// The sets' answers are the inner source's.
	ref, err := types.ParseSetRef("AS-ONE")
	if err != nil {
		t.Fatal(err)
	}
	gs, gerr := src.GetSet(ctx, ref)
	ws, werr := reg.src.GetSet(ctx, ref)
	if gs == nil || gerr != nil {
		t.Errorf("GetSet: %v, %v", gs, gerr)
	}
	if gs != ws || (gerr == nil) != (werr == nil) {
		t.Errorf("GetSet: got %v, %v; inner %v, %v", gs, gerr, ws, werr)
	}
	if n := len(markFiles(t, dir)); n != 3 {
		t.Errorf("GetSet marked: %d mark files, want 3", n)
	}
}

func TestMarksAreNoOpsWhenOff(t *testing.T) {
	reg := memprofRegistry(t)
	if got := policySourceFor(reg, nil, 1, pair{L: 65001, X: 65002}, t.Logf); got != reg.src {
		t.Errorf("nil sampler: got %T, want reg.src itself", got)
	}
	// A nil sampler's Mark is a no-op, so even a wrapper would be harmless.
	var s *memprof.Sampler
	markHeap(s, func(f string, a ...any) { t.Errorf("nil sampler logged "+f, a...) }, "x")
	if live := s.Mark("x"); live != 0 {
		t.Errorf("nil Mark = %d", live)
	}
}
