package observe

import (
	"net/netip"
	"time"

	"github.com/rkolesnichenko/mrt/bgp"
	"github.com/rkolesnichenko/routecheck/verdict"
	"github.com/rkolesnichenko/rpsl/types"
)

// Evidence is what an observation rests on. In session mode only Time is set:
// the route was on the session itself. In collector mode the other fields say
// through whom it was seen.
type Evidence struct {
	Neighbours     []types.ASN // collector mode: the ASes X announced it to, sorted
	Direct         bool        // collector mode: X is a collector's own peer
	CollectorPeers int         // collector mode: collector peers it was seen through
	Time           time.Time   // when it was announced (a RIB entry: when it was learned)
}

// Observation is one route as X announced it, with its address family and
// the evidence for it.
type Observation struct {
	Route    verdict.Route
	Evidence Evidence
	Family   bgp.Family
}

// Route converts a decoded path to a verdict.Route (spec §6.1). The
// AS_SEQUENCE segments of p.ASPath (AS_PATH merged with AS4_PATH) are
// concatenated, prepends kept; any other segment type, or an AS_TRANS (23456)
// left after the merge, makes PathKnown false, and Path then holds the
// sequence parts for display only. OriginSet is set when the last segment is
// an AS_SET. A nil p gives a route with an unknown, empty path. The result
// shares no memory with p.
func Route(prefix netip.Prefix, p *bgp.Path, commsKnown bool) verdict.Route {
	r := verdict.Route{Prefix: prefix, CommsKnown: commsKnown}
	if p == nil {
		return r
	}
	r.PathKnown = true
	segs := p.ASPath.Segments
	n := 0
	for _, s := range segs {
		if s.Type == bgp.ASSequence {
			n += len(s.ASNs)
		}
	}
	if n > 0 {
		r.Path = make([]types.ASN, 0, n)
	}
	for _, s := range segs {
		if s.Type != bgp.ASSequence {
			r.PathKnown = false
			continue
		}
		for _, a := range s.ASNs {
			if a == bgp.ASTrans {
				r.PathKnown = false
			}
			r.Path = append(r.Path, types.ASN(a))
		}
	}
	if len(segs) > 0 && segs[len(segs)-1].Type == bgp.ASSet {
		r.OriginSet = true
	}
	if len(p.Communities) > 0 {
		r.Communities = make([]uint32, len(p.Communities))
		for i, c := range p.Communities {
			r.Communities[i] = uint32(c)
		}
	}
	return r
}

// disposition is what RFC 7606 makes of an UPDATE (or a RIB entry) given the
// diagnostics mrt reported for it.
type disposition uint8

const (
	dispOK       disposition = iota // use it as it is
	dispWithdraw                    // treat-as-withdraw: its announcements are withdrawals
	dispReset                       // session reset: its NLRI cannot be trusted to be delimited
)

func (d disposition) String() string {
	switch d {
	case dispOK:
		return "ok"
	case dispWithdraw:
		return "treat-as-withdraw"
	case dispReset:
		return "reset"
	}
	return "?"
}

// discarded are the attributes RFC 7606 §7 (and RFC 6793 §6 for the AS4
// ones) handles by attribute discard on an external session: a malformed one
// is dropped and the route kept. None of them feeds verdict.Route, and a
// discarded AS4_PATH leaves AS_TRANS in the path, which makes PathKnown false.
var discarded = [256]bool{
	bgp.AttrLocalPref:       true, // §7.5, external neighbour
	bgp.AttrAtomicAggregate: true, // §7.6
	bgp.AttrAggregator:      true, // §7.7
	bgp.AttrOriginatorID:    true, // §7.9, external neighbour
	bgp.AttrClusterList:     true, // §7.10, external neighbour
	bgp.AttrAS4Path:         true, // RFC 6793 §6
	bgp.AttrAS4Aggregator:   true, // RFC 6793 §6
}

// classify decides an UPDATE's disposition from the diagnostics of
// bgp.ParseUpdate (upd) and of Attrs.Decode (attrs); a RIB entry has attrs only.
//
// mrt's severities do not draw RFC 7606's line: a known attribute of the
// wrong length is a Warning and goes to Path.Unknown, so a route whose
// COMMUNITIES did not decode would otherwise look like a route with none.
// The rule, strongest first (RFC 7606 §3.h):
//   - reset: any Error from ParseUpdate (the message's framing or its NLRI,
//     §3.j, §5.3); any Error from Decode (bgp/attr-truncated: attributes past
//     the break, an MP_REACH_NLRI among them, cannot be located, §3.j; and
//     bgp/nlri-length inside MP_REACH_NLRI or MP_UNREACH_NLRI); any Warning
//     about MP_REACH_NLRI or MP_UNREACH_NLRI (undecodable, a next hop of the
//     wrong length §7.11, or a duplicate §3.g).
//   - treat-as-withdraw: any other Warning from Decode, except a duplicate
//     attribute (§3.g: the first copy is used) and an attribute RFC 7606
//     discards (see discarded).
//   - otherwise the UPDATE is used as it is: Info diagnostics (a cleared
//     prefix bit, an ignored AS4_PATH) and ParseUpdate's Warning for bytes
//     after the message's own length.
func classify(upd, attrs []bgp.Diagnostic) disposition {
	d := dispOK
	for _, x := range upd {
		if x.Severity >= bgp.SeverityError {
			return dispReset
		}
	}
	for _, x := range attrs {
		switch {
		case x.Severity < bgp.SeverityWarning:
		case x.Severity >= bgp.SeverityError,
			x.Attr == bgp.AttrMPReach, x.Attr == bgp.AttrMPUnreach:
			return dispReset
		case x.Code == "bgp/attr-duplicate", discarded[x.Attr]:
		default:
			d = dispWithdraw
		}
	}
	return d
}
