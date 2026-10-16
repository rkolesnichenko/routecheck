package hygiene

import (
	"context"
	"net/netip"
	"sync"

	"github.com/rkolesnichenko/routecheck/verdict"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/rpki"
	"github.com/rkolesnichenko/rpsl/types"
)

// Checker answers the two per-route questions that do not depend on policy.
// Its zero value has neither data set and answers nil to both. It is safe
// for concurrent use; do not copy it after first use.
type Checker struct {
	VRPs *rpki.VRPs     // nil: RPKI answers nil
	Src  resolve.Source // nil: RouteObject answers nil

	mu    sync.Mutex
	cache map[originKey]*originRoutes
}

type originKey struct {
	as  types.ASN
	afi types.AFI
}

// originRoutes is one origin's route objects, or a read in flight.
type originRoutes struct {
	done     chan struct{}
	prefixes map[netip.Prefix]struct{}
	err      error
}

// origin is the route's origin AS. ok is false when there is none: the
// path's last segment was an AS_SET, or Path is empty (observe never
// produces that; it is treated like an AS_SET).
func origin(r verdict.Route) (as types.ASN, ok bool) {
	if r.OriginSet || len(r.Path) == 0 {
		return 0, false
	}
	return r.Path[len(r.Path)-1], true
}

// RPKI returns the route's RFC 6811 origin-validation state, or nil when
// VRPs is nil. A route without an origin (AS_SET or empty path) is
// validated as AS0: Invalid when a VRP covers the prefix, NotFound
// otherwise (AS0 never matches).
func (c *Checker) RPKI(r verdict.Route) *rpki.State {
	if c.VRPs == nil {
		return nil
	}
	as, _ := origin(r) // no origin: AS0
	s := c.VRPs.Validate(r.Prefix, as)
	return &s
}

// RouteObject reports whether a route or route6 object exists for exactly
// (r.Prefix, origin); a covering or more specific object does not count.
// It returns nil, nil when the route has no origin (AS_SET or empty path)
// or Src is nil. An origin's objects are read once per family and cached;
// concurrent calls for one key share the read. An error from Src is
// returned as is and not cached; a call that waited on a failed read gets
// that read's error.
func (c *Checker) RouteObject(ctx context.Context, r verdict.Route, afi types.AFI) (*bool, error) {
	as, ok := origin(r)
	if !ok || c.Src == nil {
		return nil, nil
	}
	e, err := c.routes(ctx, originKey{as, afi})
	if err != nil {
		return nil, err
	}
	_, found := e.prefixes[r.Prefix.Masked()]
	return &found, nil
}

func (c *Checker) routes(ctx context.Context, k originKey) (*originRoutes, error) {
	c.mu.Lock()
	if e, ok := c.cache[k]; ok {
		c.mu.Unlock()
		select {
		case <-e.done:
			return e, e.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	e := &originRoutes{done: make(chan struct{})}
	if c.cache == nil {
		c.cache = make(map[originKey]*originRoutes)
	}
	c.cache[k] = e
	c.mu.Unlock()

	defer func() {
		if e.err != nil {
			c.mu.Lock()
			delete(c.cache, k)
			c.mu.Unlock()
		}
		close(e.done)
	}()
	var ps []netip.Prefix
	ps, e.err = c.Src.OriginatedRoutes(ctx, k.as, k.afi)
	if e.err != nil {
		return nil, e.err
	}
	e.prefixes = make(map[netip.Prefix]struct{}, len(ps))
	for _, p := range ps {
		e.prefixes[p.Masked()] = struct{}{}
	}
	return e, nil
}
