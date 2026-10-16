package hygiene

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/rkolesnichenko/routecheck/verdict"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/rpki"
	"github.com/rkolesnichenko/rpsl/types"
)

func vrps(t *testing.T, vs ...rpki.VRP) *rpki.VRPs {
	t.Helper()
	v, err := rpki.NewVRPs(vs)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func route(prefix string, path ...types.ASN) verdict.Route {
	return verdict.Route{Prefix: netip.MustParsePrefix(prefix), Path: path, PathKnown: true}
}

func TestRPKI(t *testing.T) {
	c := &Checker{VRPs: vrps(t,
		rpki.VRP{Prefix: netip.MustParsePrefix("192.0.2.0/24"), MaxLength: 24, ASN: 64500},
		rpki.VRP{Prefix: netip.MustParsePrefix("198.51.100.0/24"), MaxLength: 24, ASN: 64500},
	)}
	set := route("198.51.100.0/24", 64496, 64500)
	set.OriginSet = true
	setNF := route("203.0.113.0/24", 64496, 64500)
	setNF.OriginSet = true
	cases := []struct {
		name string
		r    verdict.Route
		want rpki.State
	}{
		{"valid", route("192.0.2.0/24", 64496, 64500), rpki.Valid},
		{"wrong origin", route("192.0.2.0/24", 64496, 64501), rpki.Invalid},
		{"too long", route("192.0.2.0/25", 64496, 64500), rpki.Invalid},
		{"not found", route("203.0.113.0/24", 64496, 64500), rpki.NotFound},
		{"as_set origin, covered", set, rpki.Invalid},
		{"as_set origin, uncovered", setNF, rpki.NotFound},
		{"empty path, covered", route("192.0.2.0/24"), rpki.Invalid},
		{"empty path, uncovered", route("203.0.113.0/24"), rpki.NotFound},
	}
	for _, tc := range cases {
		got := c.RPKI(tc.r)
		if got == nil || *got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
	if got := (&Checker{}).RPKI(route("192.0.2.0/24", 1)); got != nil {
		t.Errorf("nil VRPs: got %v, want nil", *got)
	}
}

const dump = `route: 192.0.2.0/24
origin: AS64500
source: TEST

route6: 2001:db8::/32
origin: AS64500
source: TEST

route: 198.51.100.0/22
origin: AS64501
source: TEST
`

func memSource(t *testing.T) *resolve.MemSource {
	t.Helper()
	s, err := resolve.LoadDump(strings.NewReader(dump))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type counting struct {
	resolve.Source
	calls atomic.Int64
	err   error
}

func (c *counting) OriginatedRoutes(ctx context.Context, as types.ASN, afi types.AFI) ([]netip.Prefix, error) {
	c.calls.Add(1)
	if c.err != nil {
		return nil, c.err
	}
	return c.Source.OriginatedRoutes(ctx, as, afi)
}

func TestRouteObject(t *testing.T) {
	ctx := context.Background()
	src := &counting{Source: memSource(t)}
	c := &Checker{Src: src}
	check := func(name string, r verdict.Route, afi types.AFI, want *bool) {
		t.Helper()
		got, err := c.RouteObject(ctx, r, afi)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if (got == nil) != (want == nil) || (got != nil && *got != *want) {
			t.Errorf("%s: got %v, want %v", name, got, want)
		}
	}
	yes, no := true, false
	check("exact", route("192.0.2.0/24", 1, 64500), types.AFIv4, &yes)
	check("exact v6", route("2001:db8::/32", 1, 64500), types.AFIv6, &yes)
	check("covering object only", route("198.51.100.0/24", 1, 64501), types.AFIv4, &no)
	check("wrong origin", route("192.0.2.0/24", 1, 64501), types.AFIv4, &no)
	check("unknown origin", route("192.0.2.0/24", 1, 64999), types.AFIv4, &no)
	set := route("192.0.2.0/24", 1, 64500)
	set.OriginSet = true
	check("as_set origin", set, types.AFIv4, nil)
	check("empty path", route("192.0.2.0/24"), types.AFIv4, nil)
	if got, err := (&Checker{}).RouteObject(ctx, route("192.0.2.0/24", 64500), types.AFIv4); got != nil || err != nil {
		t.Errorf("nil Src: got %v, %v", got, err)
	}

	// Many routes of one origin and family: one read.
	src2 := &counting{Source: memSource(t)}
	c = &Checker{Src: src2}
	for i := 0; i < 50; i++ {
		check("many", route("192.0.2.0/24", 1, 64500), types.AFIv4, &yes)
	}
	if n := src2.calls.Load(); n != 1 {
		t.Errorf("OriginatedRoutes called %d times, want 1", n)
	}
	check("other family", route("2001:db8::/32", 1, 64500), types.AFIv6, &yes)
	if n := src2.calls.Load(); n != 2 {
		t.Errorf("calls = %d, want 2 (one per origin and family)", n)
	}
}

func TestRouteObjectConcurrent(t *testing.T) {
	src := &counting{Source: memSource(t)}
	c := &Checker{Src: src}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := c.RouteObject(context.Background(), route("192.0.2.0/24", 1, 64500), types.AFIv4)
			if err != nil || got == nil || !*got {
				t.Errorf("got %v, %v", got, err)
			}
		}()
	}
	wg.Wait()
	if n := src.calls.Load(); n != 1 {
		t.Errorf("calls = %d, want 1", n)
	}
}

func TestRouteObjectErrorNotCached(t *testing.T) {
	boom := errors.New("boom")
	src := &counting{Source: memSource(t), err: boom}
	c := &Checker{Src: src}
	r := route("192.0.2.0/24", 1, 64500)
	if got, err := c.RouteObject(context.Background(), r, types.AFIv4); !errors.Is(err, boom) || got != nil {
		t.Fatalf("got %v, %v", got, err)
	}
	src.err = nil
	got, err := c.RouteObject(context.Background(), r, types.AFIv4)
	if err != nil || got == nil || !*got {
		t.Fatalf("after recovery: got %v, %v", got, err)
	}
	if n := src.calls.Load(); n != 2 {
		t.Errorf("calls = %d, want 2", n)
	}
}
