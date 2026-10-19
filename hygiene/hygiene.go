package hygiene

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/rkolesnichenko/routecheck/verdict"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/rpki"
	"github.com/rkolesnichenko/rpsl/types"
)

// ErrAFIMismatch is returned by RouteObject and VerifiedRouteObject when afi
// is IPv4 or IPv6 and the route's prefix is of the other family (a caller bug,
// not a missing object).
var ErrAFIMismatch = errors.New("hygiene: address family does not match the prefix")

var errReadIncomplete = errors.New("hygiene: route-object read did not complete")

func afiFits(afi types.AFI, p netip.Prefix) bool {
	switch afi {
	case types.AFIv4:
		return p.Addr().Is4()
	case types.AFIv6:
		return p.Addr().Is6()
	}
	return true
}

// Checker answers the three per-route questions that do not depend on policy:
// RPKI, RouteObject and VerifiedRouteObject. Its zero value has no data set
// and answers nil to all three. It is safe for concurrent use; do not copy it
// after first use. It keeps two route-object caches, one for Src and one for
// Verified, and each grows for the Checker's lifetime: use a fresh Checker per
// run.
type Checker struct {
	VRPs *rpki.VRPs     // nil: RPKI answers nil
	Src  resolve.Source // nil: RouteObject answers nil
	// Verified is the source of the registries that count as verified
	// (usually a subset of Src); nil: VerifiedRouteObject answers nil.
	Verified resolve.Source

	// waiting counts calls that began waiting behind a read, in either cache;
	// tests synchronize on it.
	waiting atomic.Int64

	objects  routeCache // reads of Src
	verified routeCache // reads of Verified
}

// routeCache is the route objects read from one Source, by origin and
// family.
type routeCache struct {
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
// returned as is and not cached; a call that waited on a failed read reads
// again unless its own context is done. A prefix of the other family than
// a non-"any" afi is ErrAFIMismatch.
func (c *Checker) RouteObject(ctx context.Context, r verdict.Route, afi types.AFI) (*bool, error) {
	if !afiFits(afi, r.Prefix) {
		return nil, fmt.Errorf("%w: %s for %s", ErrAFIMismatch, afi, r.Prefix)
	}
	return c.lookup(ctx, &c.objects, c.Src, r, afi)
}

// VerifiedRouteObject is RouteObject for the verified registries: whether
// Verified holds a route or route6 object for exactly (r.Prefix, origin).
// It returns nil, nil when the route has no origin or Verified is nil, and
// reads, caches and fails as RouteObject does, from its own cache.
func (c *Checker) VerifiedRouteObject(ctx context.Context, r verdict.Route, afi types.AFI) (*bool, error) {
	if !afiFits(afi, r.Prefix) {
		return nil, fmt.Errorf("%w: %s for %s", ErrAFIMismatch, afi, r.Prefix)
	}
	return c.lookup(ctx, &c.verified, c.Verified, r, afi)
}

func (c *Checker) lookup(ctx context.Context, rc *routeCache, src resolve.Source, r verdict.Route, afi types.AFI) (*bool, error) {
	as, ok := origin(r)
	if !ok || src == nil {
		return nil, nil
	}
	e, err := c.routes(ctx, rc, src, originKey{as, afi})
	if err != nil {
		return nil, err
	}
	_, found := e.prefixes[r.Prefix.Masked()]
	return &found, nil
}

func (c *Checker) routes(ctx context.Context, rc *routeCache, src resolve.Source, k originKey) (*originRoutes, error) {
	for {
		rc.mu.Lock()
		if e, ok := rc.cache[k]; ok {
			rc.mu.Unlock()
			c.waiting.Add(1)
			select {
			case <-e.done:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			if e.err == nil {
				return e, nil
			}
			// The read failed and its entry is gone. If this caller is still
			// live the failure may have been the leader's own (its context),
			// so read again, as the new leader or behind one.
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			continue
		}
		e := &originRoutes{done: make(chan struct{})}
		if rc.cache == nil {
			rc.cache = make(map[originKey]*originRoutes)
		}
		rc.cache[k] = e
		rc.mu.Unlock()
		return fetch(ctx, rc, src, k, e)
	}
}

// fetch is the leader's read. However it ends, normally, with an error or by
// a panic in Src, an unsuccessful entry leaves the cache and its waiters are
// released.
func fetch(ctx context.Context, rc *routeCache, src resolve.Source, k originKey, e *originRoutes) (*originRoutes, error) {
	completed := false
	defer func() {
		if !completed {
			e.err = errReadIncomplete
		}
		if e.err != nil {
			rc.mu.Lock()
			delete(rc.cache, k)
			rc.mu.Unlock()
		}
		close(e.done)
	}()
	ps, err := src.OriginatedRoutes(ctx, k.as, k.afi)
	if err != nil {
		e.err = err
		completed = true
		return nil, err
	}
	e.prefixes = make(map[netip.Prefix]struct{}, len(ps))
	for _, p := range ps {
		e.prefixes[p.Masked()] = struct{}{}
	}
	completed = true
	return e, nil
}
