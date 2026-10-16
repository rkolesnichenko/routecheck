package observe

import (
	"cmp"
	"encoding/binary"
	"errors"
	"iter"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/rkolesnichenko/mrt"
	"github.com/rkolesnichenko/mrt/bgp"
	"github.com/rkolesnichenko/routecheck/verdict"
	"github.com/rkolesnichenko/rpsl/types"
)

// CollectorInfo is what Collector found in the dumps besides the routes.
// Every count is of RIB entries (one per collector peer and prefix), not of
// observations.
type CollectorInfo struct {
	Entries int // RIB entries read (TABLE_DUMP_V2 and legacy TABLE_DUMP); BGP4MP records are not entries
	// Malformed: entries RFC 7606 keeps no route from (see classify),
	// skipped whether or not X is on their path, since a path that did not
	// decode cleanly cannot be trusted to show it.
	Malformed int
	Skipped   int // records and RIB entries mrt could not read or place (a *mrt.RecordError)
	Through   int // well-formed entries whose AS path holds X
	// Of Through: X's leftmost occurrence is in an AS_SET or a confederation
	// segment, so there is no suffix to cut; no observation.
	NotSequence int
	Direct      int // of Through: X is the path's first AS, the collector's own peer
	// Of Through: the element left of X is in an AS_SET or a confederation
	// segment, or is AS_TRANS; observed, with no neighbour and not direct.
	NoNeighbour int
}

// Collector reads route-collector RIB dumps (TABLE_DUMP_V2 and legacy
// TABLE_DUMP, any number of them concatenated, each with its own
// PEER_INDEX_TABLE) and yields the routes X announced, as X announced them
// (spec §6.3, controller ruling R11), in prefix order (then address family,
// then path). It reads the whole input before it yields anything, since
// observations are deduplicated across it. The info function is valid after
// the sequence is drained.
//
// The rules:
//   - Only RIB entries are read; BGP4MP records are not used.
//   - A RIB entry RFC 7606 keeps no route from (see classify) is skipped and
//     counted in Malformed.
//   - The observed route is the suffix of the entry's path from X's
//     leftmost (collector-nearest) occurrence on, prepends kept; a later X
//     (path poisoning) does not move the cut. When that occurrence is not in
//     an AS_SEQUENCE there is no route (NotSequence).
//   - The route is Route's conversion of the suffix alone: an AS_SET, a
//     confederation segment or AS_TRANS left of X does not make it unknown.
//     CommsKnown is false and Communities empty: an AS left of X may have
//     changed them (spec D3).
//   - The neighbour X announced it to is the AS immediately left of X when
//     that element is in an AS_SEQUENCE (the previous segment's last AS when
//     X starts a segment). With nothing left of X, X is a collector peer and
//     the sighting is direct. Otherwise (an AS_SET or a confederation
//     segment, or AS_TRANS, which names no AS) there is no neighbour and the
//     sighting is not direct (NoNeighbour).
//   - Observations are deduplicated by (address family, prefix, suffix); the
//     suffix compares by segments, so X {Y} and X Y differ while two
//     adjacent AS_SEQUENCEs equal one, and an AS_SET's order does not count.
//     Evidence.Neighbours is the sorted set of their neighbours; Direct is
//     set when any sighting was direct; CollectorPeers counts distinct
//     collector peers (BGP ID, address and AS); Time is the latest record
//     time among the sightings (a RIB's record time, not the entry's
//     originated time); PeerAddr is zero.
//
// A *mrt.RecordError is counted in Skipped; any other error (a truncated
// stream, a read error) is yielded and ends the sequence with no
// observations.
func Collector(records iter.Seq2[mrt.Record, error], x types.ASN) (iter.Seq2[Observation, error], func() CollectorInfo) {
	var info CollectorInfo
	seq := func(yield func(Observation, error) bool) {
		c := collection{x: bgp.ASN(x), byKey: map[suffixKey]int{}, peers: map[mrt.Peer]uint32{}}
		obs, err := c.run(records)
		info = c.info
		if err != nil {
			yield(Observation{}, err)
			return
		}
		for _, o := range obs {
			if !yield(o, nil) {
				return
			}
		}
	}
	return seq, func() CollectorInfo { return info }
}

// suffixKey is what observations are deduplicated by.
type suffixKey struct {
	fam    bgp.Family
	prefix netip.Prefix
	suffix string // encodeSuffix
}

// sighting is one observation being gathered.
type sighting struct {
	route      verdict.Route
	fam        bgp.Family
	suffix     string
	neighbours []types.ASN // sorted, unique
	peers      []uint32    // interned collector peers, sorted, unique
	direct     bool
	time       time.Time
}

// collection is one run of Collector.
type collection struct {
	x     bgp.ASN
	info  CollectorInfo
	obs   []sighting
	byKey map[suffixKey]int   // index into obs
	peers map[mrt.Peer]uint32 // interned collector peers
}

func (c *collection) run(records iter.Seq2[mrt.Record, error]) ([]Observation, error) {
	for r, err := range mrt.Routes(records) {
		if err != nil {
			var re *mrt.RecordError
			if !errors.As(err, &re) || errors.Is(err, mrt.ErrTruncated) {
				return nil, err
			}
			c.info.Skipped++
			continue
		}
		if r.Kind != mrt.KindRIB || r.Path == nil {
			continue
		}
		c.info.Entries++
		if ribMalformed(r.Diagnostics) {
			c.info.Malformed++
			continue
		}
		c.entry(r)
	}
	return c.finish(), nil
}

// neighbourKind is what is left of X's leftmost occurrence.
type neighbourKind uint8

const (
	leftAS     neighbourKind = iota // an AS in an AS_SEQUENCE: the neighbour
	leftNone                        // nothing: a direct feed
	leftOpaque                      // an AS_SET, a confederation segment or AS_TRANS: no neighbour
)

// entry adds one well-formed RIB entry.
func (c *collection) entry(r mrt.Route) {
	segs := r.Path.ASPath.Segments
	si, ai, found := leftmost(segs, c.x)
	if !found {
		return
	}
	c.info.Through++
	if segs[si].Type != bgp.ASSequence {
		c.info.NotSequence++
		return
	}
	suffix := make([]bgp.Segment, 0, len(segs)-si)
	suffix = append(suffix, bgp.Segment{Type: bgp.ASSequence, ASNs: segs[si].ASNs[ai:]})
	suffix = append(suffix, segs[si+1:]...)

	nb, kind := leftOf(segs, si, ai)
	switch kind {
	case leftNone:
		c.info.Direct++
	case leftOpaque:
		c.info.NoNeighbour++
	}

	k := suffixKey{r.Family, r.Prefix, encodeSuffix(suffix)}
	i, ok := c.byKey[k]
	if !ok {
		p := bgp.Path{ASPath: bgp.ASPath{Segments: suffix}}
		c.obs = append(c.obs, sighting{route: Route(r.Prefix, &p, false), fam: r.Family, suffix: k.suffix})
		i = len(c.obs) - 1
		c.byKey[k] = i
	}
	s := &c.obs[i]
	switch kind {
	case leftAS:
		s.neighbours = insertSorted(s.neighbours, types.ASN(nb))
	case leftNone:
		s.direct = true
	}
	id, ok := c.peers[r.Peer]
	if !ok {
		id = uint32(len(c.peers))
		c.peers[r.Peer] = id
	}
	s.peers = insertSorted(s.peers, id)
	if r.Time.After(s.time) {
		s.time = r.Time
	}
}

// leftmost finds x's leftmost occurrence in segs: segment si, element ai.
func leftmost(segs []bgp.Segment, x bgp.ASN) (si, ai int, found bool) {
	for si, s := range segs {
		if ai := slices.Index(s.ASNs, x); ai >= 0 {
			return si, ai, true
		}
	}
	return 0, 0, false
}

// leftOf says what is immediately left of element ai of segment si, which
// is an AS_SEQUENCE: an AS (the neighbour), nothing (a direct feed), or an
// element that names no neighbour.
func leftOf(segs []bgp.Segment, si, ai int) (bgp.ASN, neighbourKind) {
	var a bgp.ASN
	switch {
	case ai > 0:
		a = segs[si].ASNs[ai-1]
	default:
		k := si - 1
		for k >= 0 && len(segs[k].ASNs) == 0 {
			k--
		}
		if k < 0 {
			return 0, leftNone
		}
		if segs[k].Type != bgp.ASSequence {
			return 0, leftOpaque
		}
		a = segs[k].ASNs[len(segs[k].ASNs)-1]
	}
	if a == bgp.ASTrans {
		return 0, leftOpaque
	}
	return a, leftAS
}

// encodeSuffix is the canonical form segments compare by: an AS_SEQUENCE
// or AS_CONFED_SEQUENCE element is its type and AS (so adjacent sequences of
// one type join); any other segment is one unit of a zero byte, its type, its
// sorted unique ASes' count and the ASes (a set's order does not count).
func encodeSuffix(segs []bgp.Segment) string {
	var b []byte
	for _, s := range segs {
		switch s.Type {
		case bgp.ASSequence, bgp.ASConfedSequence:
			for _, a := range s.ASNs {
				b = append(b, byte(s.Type))
				b = binary.BigEndian.AppendUint32(b, uint32(a))
			}
		default:
			set := slices.Compact(slices.Sorted(slices.Values(s.ASNs)))
			b = append(b, 0, byte(s.Type))
			b = binary.BigEndian.AppendUint32(b, uint32(len(set)))
			for _, a := range set {
				b = binary.BigEndian.AppendUint32(b, uint32(a))
			}
		}
	}
	return string(b)
}

func insertSorted[T cmp.Ordered](s []T, v T) []T {
	i, found := slices.BinarySearch(s, v)
	if found {
		return s
	}
	return slices.Insert(s, i, v)
}

// finish sorts the observations: prefix, address family, path, then the
// suffix's encoding (a total order: the key is unique per prefix and family).
func (c *collection) finish() []Observation {
	slices.SortFunc(c.obs, func(a, b sighting) int {
		return cmp.Or(
			a.route.Prefix.Addr().Compare(b.route.Prefix.Addr()),
			cmp.Compare(a.route.Prefix.Bits(), b.route.Prefix.Bits()),
			cmp.Compare(a.fam.AFI, b.fam.AFI),
			cmp.Compare(a.fam.SAFI, b.fam.SAFI),
			slices.Compare(a.route.Path, b.route.Path),
			strings.Compare(a.suffix, b.suffix),
		)
	})
	out := make([]Observation, len(c.obs))
	for i, s := range c.obs {
		out[i] = Observation{
			Route:  s.route,
			Family: s.fam,
			Evidence: Evidence{
				Neighbours:     s.neighbours,
				Direct:         s.direct,
				CollectorPeers: len(s.peers),
				Time:           s.time,
			},
		}
	}
	return out
}
