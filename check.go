package routecheck

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"github.com/rkolesnichenko/mrt"
	"github.com/rkolesnichenko/mrt/bgp"
	"github.com/rkolesnichenko/routecheck/hygiene"
	"github.com/rkolesnichenko/routecheck/observe"
	"github.com/rkolesnichenko/routecheck/verdict"
	"github.com/rkolesnichenko/rpsl/resolve"
	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/resolve/rpki"
	"github.com/rkolesnichenko/rpsl/types"
)

// Mode is where the routes come from.
type Mode uint8

// The modes. The zero Mode is none of them.
const (
	// ModeSession reads a capture of the L–X session itself: BGP4MP
	// messages X sent L (spec §6.2).
	ModeSession Mode = iota + 1
	// ModeCollector reads route-collector RIB dumps and takes the routes X
	// announced to anyone (spec §6.3).
	ModeCollector
)

// Direction selects the policies Check evaluates: L's import from X, X's
// export, or both.
type Direction uint8

// The directions. The zero Direction means DirBoth.
const (
	DirImport Direction = 1                     // L's import policy toward X
	DirExport Direction = 2                     // X's export policy toward L (session mode) or each neighbour (collector mode)
	DirBoth   Direction = DirImport | DirExport // both
)

// Options says which session to check and how.
type Options struct {
	// Local is L. In session mode a zero Local is the capture's local AS
	// (observe.SessionInfo.LocalAS). In collector mode it must be set when
	// the import direction is checked; export alone does not need it.
	Local types.ASN
	// Peer is X, the neighbour whose routes are checked. It must be set and
	// differ from Local.
	Peer types.ASN
	// AF lists the address families to check, one Result each, in this
	// order: each one of ipv4.unicast, ipv4.multicast, ipv6.unicast and
	// ipv6.multicast, at most once. Empty means ipv4.unicast and
	// ipv6.unicast.
	AF []types.AddrFamily
	// LocalRtr and PeerRtr are L's and X's router addresses on the session,
	// for peerings that name routers (peval.Session). Never taken from the
	// capture (spec §5); Coverage gives the capture's addresses as a hint.
	LocalRtr, PeerRtr netip.Addr
	// PeerAddr, session mode only: when valid, only the capture's records
	// with this peer address are read.
	PeerAddr netip.Addr
	// At, session mode only: the state at this time (records at At
	// included); zero is the end of the capture.
	At time.Time
	// PrePolicyRIB, session mode only: RIB dumps in the input are X's
	// Adj-RIB-In before import policy (spec D2).
	PrePolicyRIB bool
	// Directions selects the policies checked; zero is DirBoth.
	Directions Direction
	// VRPs, when set, gives each route its RPKI origin-validation state.
	VRPs *rpki.VRPs
}

// Checker checks one session's routes against the registered policies.
// Check holds no state between calls, so a Checker may serve concurrent
// calls when its sources may.
type Checker struct {
	// Eval evaluates the aut-nums' policies: its Src, Expander and Source
	// as rpsl's peval takes them.
	Eval peval.Evaluator
	// Routes answers whether a route object exists for each route
	// (Source.OriginatedRoutes); usually Eval.Src. Nil: not checked, and
	// RouteVerdict.RouteObj is nil.
	Routes resolve.Source
}

// Result is what Check found for one address family.
type Result struct {
	AF types.AddrFamily
	// Import is L's import policy toward X over every route; nil when the
	// import direction is not checked.
	Import *Report
	// Export is X's export policy: in session mode one Report, toward L,
	// over every route; in collector mode one per neighbour X was seen
	// announcing to, ordered by AS, each over the routes seen announced to
	// that neighbour, and an empty non-nil slice when no neighbour was seen.
	// Nil when the export direction is not checked.
	Export []Report
	// Coverage is what the input shows about its own completeness.
	Coverage Coverage
}

// Coverage is what the routes rest on and what was left out. The same
// observe info, OtherFamilies count and hints appear in every Result of
// one Check.
type Coverage struct {
	// Session is session mode's capture info (mid-session start, session
	// down at the end, routes not starting with X, malformed and skipped
	// records); nil in collector mode.
	Session *observe.SessionInfo
	// Collector is collector mode's dump info; nil in session mode.
	Collector *observe.CollectorInfo
	// OtherFamilies counts the routes of the whole input in an address
	// family not asked for (or none of the four Options.AF allows): dropped,
	// never decided under another family's policy.
	OtherFamilies int
	// DirectNotChecked, collector mode with the export direction checked:
	// this family's routes seen on X's own feed to a collector, whose AS a
	// RIB dump does not carry, so that sighting is checked toward no
	// neighbour. A route also seen announced to a neighbour is still
	// checked toward that neighbour.
	DirectNotChecked int
	// HintLocalAddr and HintPeerAddr, session mode: the capture's local and
	// peer addresses (observe.SessionInfo), a hint for LocalRtr and PeerRtr
	// when a peering names a router. Zero in collector mode.
	HintLocalAddr, HintPeerAddr netip.Addr
}

// Report is one policy decided for a set of routes.
type Report struct {
	// Toward is the session's peer in the policy's own view: X for L's
	// import, the neighbour (L in session mode) for X's export.
	Toward types.ASN
	Policy peval.Policy
	// NoPolicy: the policy has no clause and no undecided term (no term
	// for this peer in this family), so there are no per-route verdicts.
	NoPolicy bool
	// Routes are the verdicts, in prefix order (then path ID, then peer
	// address in session mode, then path in collector mode).
	Routes []RouteVerdict
	// The counts of Routes by outcome.
	Accepted, Rejected, Undecided int
}

// RouteVerdict is one route's verdict, with what it rests on.
type RouteVerdict struct {
	Route    verdict.Route
	Evidence observe.Evidence // the neighbours, direct feed, collector-peer count and time (shared with observe: do not modify)
	Verdict  verdict.Verdict
	// RPKI is the route's origin-validation state; nil without VRPs.
	RPKI *rpki.State
	// RouteObj reports whether a route object exists for exactly (prefix,
	// origin); nil when Checker.Routes is nil or the route has no single
	// origin (an AS_SET at the end of its path, spec §6.6). RPKI and
	// RouteObj are shared by every report that holds the route.
	RouteObj *bool
}

// ErrOptions is wrapped by every error Check returns for options it cannot
// use — a command-line mistake, not a failure of the run. That includes
// the two found only after the capture is read: Local not set and the
// capture naming no local AS, and the capture's local AS being Peer.
var ErrOptions = errors.New("routecheck: invalid options")

// compiles counts the policies Check compiles (Review Focus 4: once per
// family, direction and Toward); read by tests only.
var compiles atomic.Int64

// ctxEvery is how many records Check reads, and how many routes it
// decides, between two reads of its context; it also reads it before each
// policy is evaluated.
const ctxEvery = 4096

// Check reads the routes from records (mrt.Records over the inputs) and
// returns one Result per address family of o.AF, in its order. It never
// stops at a bad route: bad routes are counted in the Result's Coverage.
//
// Each Report evaluates its policy with peval once and compiles it once
// (verdict.Compile), then decides every route it covers. In session mode
// L's import is peval.Session{Local: L, Peer: X} with o's routers and X's
// export is {Local: X, Peer: L} with them swapped (X's router is its local
// one); in collector mode X's export toward each neighbour N is {Local: X,
// Peer: N} with no routers, since o's routers are those of the L–X session
// and a given but mismatched router would make a term not apply where an
// unset one leaves it Undecided.
//
// A policy peval cannot evaluate because it names AS-ANY or RS-ANY where
// rpsl cannot expand it (a *resolve.AnySetError, such as an as-set whose
// members are AS-ANY in an AS-path regexp) is not an error (ruling R19):
// that one Report has an empty Policy and every one of its routes is
// Undecided with the single reason verdict.ReasonUnevaluable, whose Why is
// the error's text.
//
// Check returns an error, and no Results, for options it cannot use, an
// input observe cannot read (a truncated stream, observe.ErrRIBNotPrePolicy),
// any other policy peval cannot evaluate (a missing aut-num, a limit), an
// error from Routes, and ctx's error once it is done (also while observe
// reads the input, which it reads whole before yielding a route). Errors for
// options wrap ErrOptions.
func (c *Checker) Check(ctx context.Context, mode Mode, records iter.Seq2[mrt.Record, error], o Options) ([]Result, error) {
	afs, dirs, err := o.check(mode)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r := &run{
		ctx: ctx,
		c:   c,
		hyg: &hygiene.Checker{VRPs: o.VRPs, Src: c.Routes},
	}

	// The observations, by family.
	byAF := make(map[types.AddrFamily][]observe.Observation, len(afs))
	for _, a := range afs {
		byAF[a] = nil
	}
	var (
		obs     iter.Seq2[observe.Observation, error]
		session func() observe.SessionInfo
		coll    func() observe.CollectorInfo
	)
	if mode == ModeSession {
		obs, session = observe.Session(withContext(ctx, records), observe.SessionSel{Peer: o.Peer, PeerAddr: o.PeerAddr, At: o.At, PrePolicyRIB: o.PrePolicyRIB})
	} else {
		obs, coll = observe.Collector(withContext(ctx, records), o.Peer)
	}
	other := 0
	for ob, err := range obs {
		if err != nil {
			return nil, err
		}
		if err := r.tick(); err != nil {
			return nil, err
		}
		a, ok := family(ob.Family)
		if _, asked := byAF[a]; !ok || !asked {
			other++
			continue
		}
		byAF[a] = append(byAF[a], ob)
	}

	local := o.Local
	base := Coverage{OtherFamilies: other}
	var sinfo observe.SessionInfo
	var cinfo observe.CollectorInfo
	if mode == ModeSession {
		sinfo = session()
		if local == 0 {
			local = sinfo.LocalAS
		}
		if local == 0 {
			return nil, fmt.Errorf("%w: Options.Local is not set and the capture names no local AS", ErrOptions)
		}
		if local == o.Peer {
			return nil, fmt.Errorf("%w: the capture's local AS is the peer, %s", ErrOptions, local)
		}
		base.HintLocalAddr, base.HintPeerAddr = sinfo.LocalAddr, sinfo.PeerAddr
	} else {
		cinfo = coll()
	}

	results := make([]Result, 0, len(afs))
	for _, a := range afs {
		res := Result{AF: a, Coverage: base}
		if mode == ModeSession {
			si := sinfo
			res.Coverage.Session = &si
		} else {
			ci := cinfo
			res.Coverage.Collector = &ci
		}
		fam := r.family(a, byAF[a])
		if dirs&DirImport != 0 {
			rep, err := fam.report(peval.Session{Local: local, Peer: o.Peer, LocalRtr: o.LocalRtr, PeerRtr: o.PeerRtr, AF: a}, false, nil)
			if err != nil {
				return nil, err
			}
			res.Import = &rep
		}
		if dirs&DirExport != 0 {
			if mode == ModeSession {
				rep, err := fam.report(peval.Session{Local: o.Peer, Peer: local, LocalRtr: o.PeerRtr, PeerRtr: o.LocalRtr, AF: a}, true, nil)
				if err != nil {
					return nil, err
				}
				res.Export = []Report{rep}
			} else {
				reps, direct, err := fam.perNeighbour(o.Peer)
				if err != nil {
					return nil, err
				}
				res.Export, res.Coverage.DirectNotChecked = reps, direct
			}
		}
		results = append(results, res)
		// Its reports are built: release the family's observations (R14).
		byAF[a], fam.obs, fam.memo = nil, nil, nil
	}
	return results, nil
}

// withContext passes records on, reading ctx every ctxEvery records; once
// ctx is done it yields ctx's error, which observe returns as is (it is not
// a *mrt.RecordError), and stops.
func withContext(ctx context.Context, records iter.Seq2[mrt.Record, error]) iter.Seq2[mrt.Record, error] {
	return func(yield func(mrt.Record, error) bool) {
		n := 0
		for rec, err := range records {
			n++
			if n%ctxEvery == 0 {
				if cerr := ctx.Err(); cerr != nil {
					yield(nil, cerr)
					return
				}
			}
			if !yield(rec, err) {
				return
			}
		}
	}
}

// check validates o for mode and returns its families and directions with
// the defaults applied.
func (o Options) check(mode Mode) ([]types.AddrFamily, Direction, error) {
	if mode != ModeSession && mode != ModeCollector {
		return nil, 0, fmt.Errorf("%w: unknown mode %d", ErrOptions, mode)
	}
	if o.Peer == 0 {
		return nil, 0, fmt.Errorf("%w: Options.Peer is not set", ErrOptions)
	}
	if o.Local == o.Peer {
		return nil, 0, fmt.Errorf("%w: Options.Local and Options.Peer are both %s", ErrOptions, o.Peer)
	}
	dirs := o.Directions
	if dirs == 0 {
		dirs = DirBoth
	}
	if dirs > DirBoth {
		return nil, 0, fmt.Errorf("%w: unknown direction %d", ErrOptions, o.Directions)
	}
	if mode == ModeCollector {
		switch {
		case o.Local == 0 && dirs&DirImport != 0:
			return nil, 0, fmt.Errorf("%w: collector mode needs Options.Local to check the import direction", ErrOptions)
		case !o.At.IsZero():
			return nil, 0, fmt.Errorf("%w: Options.At is for session mode", ErrOptions)
		case o.PeerAddr.IsValid():
			return nil, 0, fmt.Errorf("%w: Options.PeerAddr is for session mode", ErrOptions)
		case o.PrePolicyRIB:
			return nil, 0, fmt.Errorf("%w: Options.PrePolicyRIB is for session mode", ErrOptions)
		}
	}
	afs := o.AF
	if len(afs) == 0 {
		afs = []types.AddrFamily{
			{AFI: types.AFIv4, SAFI: types.SAFIUnicast},
			{AFI: types.AFIv6, SAFI: types.SAFIUnicast},
		}
	}
	for i, a := range afs {
		if (a.AFI != types.AFIv4 && a.AFI != types.AFIv6) || (a.SAFI != types.SAFIUnicast && a.SAFI != types.SAFIMulticast) {
			return nil, 0, fmt.Errorf("%w: address family %q is not ipv4 or ipv6, unicast or multicast", ErrOptions, a)
		}
		if slices.Contains(afs[:i], a) {
			return nil, 0, fmt.Errorf("%w: address family %s given twice", ErrOptions, a)
		}
	}
	return slices.Clone(afs), dirs, nil
}

// family maps an observation's BGP family to its RPSL address family: AFI
// 1 and 2 by SAFI 1 and 2. Any other family has none.
func family(f bgp.Family) (types.AddrFamily, bool) {
	var a types.AddrFamily
	switch f.AFI {
	case bgp.AFIIPv4:
		a.AFI = types.AFIv4
	case bgp.AFIIPv6:
		a.AFI = types.AFIv6
	default:
		return a, false
	}
	switch f.SAFI {
	case bgp.SAFIUnicast:
		a.SAFI = types.SAFIUnicast
	case bgp.SAFIMulticast:
		a.SAFI = types.SAFIMulticast
	default:
		return a, false
	}
	return a, true
}

// run is one Check call's state.
type run struct {
	ctx context.Context
	c   *Checker
	hyg *hygiene.Checker // one per Check (R13b): its route-object cache lives as long as the call
	n   int              // routes handled, for tick
}

// tick counts one route and reads the context every ctxEvery routes.
func (r *run) tick() error {
	r.n++
	if r.n%ctxEvery == 0 {
		return r.ctx.Err()
	}
	return nil
}

// famRun is one address family's routes and their hygiene, computed once
// per route for every report that holds it.
type famRun struct {
	*run
	af   types.AddrFamily
	afi  types.AFI
	obs  []observe.Observation
	memo []routeHygiene // by observation
}

type routeHygiene struct {
	done bool
	rpki *rpki.State
	obj  *bool
}

func (r *run) family(a types.AddrFamily, obs []observe.Observation) *famRun {
	return &famRun{run: r, af: a, afi: a.AFI, obs: obs, memo: make([]routeHygiene, len(obs))}
}

// report evaluates the policy of s (Import, or Export when export) and
// decides the observations at idx (every one when idx is nil).
func (f *famRun) report(s peval.Session, export bool, idx []int) (Report, error) {
	if err := f.ctx.Err(); err != nil {
		return Report{}, err
	}
	var (
		p   peval.Policy
		err error
	)
	if export {
		p, err = f.c.Eval.Export(f.ctx, s)
	} else {
		p, err = f.c.Eval.Import(f.ctx, s)
	}
	var anySet *resolve.AnySetError
	unevaluable := errors.As(err, &anySet)
	if err != nil && !unevaluable {
		return Report{}, err
	}
	rep := Report{Toward: s.Peer, Policy: p}
	if unevaluable {
		// Ruling R19: the policy names AS-ANY or RS-ANY where rpsl cannot
		// expand it; this report decides nothing, and says why, for each
		// of its routes.
		rep.Policy = peval.Policy{}
		return f.unevaluable(rep, err.Error(), idx)
	}
	if len(p.Clauses) == 0 && len(p.Undecided) == 0 {
		rep.NoPolicy = true
		return rep, nil
	}
	compiles.Add(1)
	cp := verdict.Compile(p)
	n := len(f.obs)
	if idx != nil {
		n = len(idx)
	}
	rep.Routes = make([]RouteVerdict, 0, n)
	for k := range n {
		i := k
		if idx != nil {
			i = idx[k]
		}
		if err := f.tick(); err != nil {
			return Report{}, err
		}
		h, err := f.hygiene(i)
		if err != nil {
			return Report{}, err
		}
		ob := &f.obs[i]
		v := cp.Decide(ob.Route)
		switch v.Outcome {
		case verdict.Accepted:
			rep.Accepted++
		case verdict.Rejected:
			rep.Rejected++
		default:
			rep.Undecided++
		}
		rep.Routes = append(rep.Routes, RouteVerdict{Route: ob.Route, Evidence: ob.Evidence, Verdict: v, RPKI: h.rpki, RouteObj: h.obj})
	}
	return rep, nil
}

// unevaluable fills rep, whose policy peval could not evaluate (why), with
// an Undecided verdict for each observation at idx (every one when idx is
// nil), each with the one reason verdict.ReasonUnevaluable.
func (f *famRun) unevaluable(rep Report, why string, idx []int) (Report, error) {
	n := len(f.obs)
	if idx != nil {
		n = len(idx)
	}
	rep.Routes = make([]RouteVerdict, 0, n)
	for k := range n {
		i := k
		if idx != nil {
			i = idx[k]
		}
		if err := f.tick(); err != nil {
			return Report{}, err
		}
		h, err := f.hygiene(i)
		if err != nil {
			return Report{}, err
		}
		ob := &f.obs[i]
		v := verdict.Verdict{Outcome: verdict.Undecided, Reasons: []verdict.Reason{{Kind: verdict.ReasonUnevaluable, Why: why, Clause: -1, Index: -1}}}
		rep.Undecided++
		rep.Routes = append(rep.Routes, RouteVerdict{Route: ob.Route, Evidence: ob.Evidence, Verdict: v, RPKI: h.rpki, RouteObj: h.obj})
	}
	return rep, nil
}

// hygiene returns observation i's RPKI state and route-object answer,
// computing them on first use.
func (f *famRun) hygiene(i int) (routeHygiene, error) {
	h := &f.memo[i]
	if !h.done {
		r := f.obs[i].Route
		obj, err := f.hyg.RouteObject(f.ctx, r, f.afi)
		if err != nil {
			return routeHygiene{}, err
		}
		h.rpki, h.obj, h.done = f.hyg.RPKI(r), obj, true
	}
	return *h, nil
}

// perNeighbour is collector mode's export: one Report per neighbour AS X
// was seen announcing to, by AS, over the observations naming it, and the
// count of observations seen on a direct feed.
func (f *famRun) perNeighbour(x types.ASN) ([]Report, int, error) {
	direct := 0
	byN := map[types.ASN][]int{}
	for i := range f.obs {
		e := &f.obs[i].Evidence
		if e.Direct {
			direct++
		}
		for _, n := range e.Neighbours {
			byN[n] = append(byN[n], i)
		}
	}
	ns := make([]types.ASN, 0, len(byN))
	for n := range byN {
		ns = append(ns, n)
	}
	slices.Sort(ns)
	reps := make([]Report, 0, len(ns))
	for _, n := range ns {
		rep, err := f.report(peval.Session{Local: x, Peer: n, AF: f.af}, true, byN[n])
		if err != nil {
			return nil, 0, err
		}
		reps = append(reps, rep)
	}
	return reps, direct, nil
}
