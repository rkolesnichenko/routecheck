package observe

import (
	"bytes"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/rkolesnichenko/mrt"
	"github.com/rkolesnichenko/mrt/bgp"
	"github.com/rkolesnichenko/routecheck/internal/mrtgen"
	"github.com/rkolesnichenko/rpsl/types"
)

// Collector-mode ASes besides X (asX), Y and Z: the collector peers and the
// ASes between them and X.
const (
	asP1 bgp.ASN = 64510
	asP2 bgp.ASN = 64511
	asP3 bgp.ASN = 64512
)

var collectorID = netip.MustParseAddr("192.0.2.254")

// cpeer is collector peer n with AS as.
func cpeer(n byte, as bgp.ASN) mrt.Peer {
	a := netip.AddrFrom4([4]byte{198, 51, 100, n})
	return mrt.Peer{BGPID: a, Addr: a, AS: as}
}

func pitRec(ts time.Time, peers ...mrt.Peer) []byte {
	return mrtgen.Header(mrt.TypeTableDumpV2, mrt.SubPeerIndexTable, ts, mrtgen.PeerIndexTable(collectorID, "", peers))
}

// ribRec is an IPv4 unicast RIB record for p.
func ribRec(ts time.Time, p string, entries ...mrtgen.Entry) []byte {
	st := mrt.SubRIBIPv4Unicast
	return mrtgen.Header(mrt.TypeTableDumpV2, st, ts, mrtgen.RIB(st, 0, pfx(p), entries))
}

// pathAttrs is a well-formed IPv4 attribute block with the given AS_PATH.
func pathAttrs(segs ...bgp.Segment) []byte {
	return slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(true, segs...), mrtgen.NextHop(nh4))
}

func ent(peer uint16, segs ...bgp.Segment) mrtgen.Entry {
	return mrtgen.Entry{PeerIndex: peer, Originated: at(-100), Attrs: pathAttrs(segs...)}
}

func collect(t *testing.T, recs ...[]byte) ([]Observation, CollectorInfo, error) {
	t.Helper()
	seq, info := Collector(mrt.Records(bytes.NewReader(slices.Concat(recs...))), types.ASN(asX))
	var obs []Observation
	var first error
	for o, err := range seq {
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		obs = append(obs, o)
	}
	return obs, info(), first
}

func mustCollect(t *testing.T, recs ...[]byte) ([]Observation, CollectorInfo) {
	t.Helper()
	obs, info, err := collect(t, recs...)
	if err != nil {
		t.Fatalf("Collector: %v", err)
	}
	return obs, info
}

// byPrefix returns the single observation for p.
func byPrefix(t *testing.T, obs []Observation, p string) Observation {
	t.Helper()
	var found []Observation
	for _, o := range obs {
		if o.Route.Prefix == pfx(p) {
			found = append(found, o)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s: %d observations, want 1 (all: %v)", p, len(found), prefixes(obs))
	}
	return found[0]
}

func TestCollectorSuffix(t *testing.T) {
	obs, info := mustCollect(t,
		pitRec(at(0), cpeer(1, asP1), cpeer(2, asX)),
		ribRec(at(0), "10.0.0.0/24", ent(0, mrtgen.Seq(asP1, asP2, asX, asY, asZ))),
		ribRec(at(0), "10.0.1.0/24", ent(1, mrtgen.Seq(asX, asX, asX, asY))),
		// X at the start of a second AS_SEQUENCE: the neighbour is the first one's last AS.
		ribRec(at(0), "10.0.2.0/24", ent(0, mrtgen.Seq(asP1, asP2), mrtgen.Seq(asX, asY))),
		// no X at all
		ribRec(at(0), "10.0.3.0/24", ent(0, mrtgen.Seq(asP1, asY))),
	)
	if got, want := prefixes(obs), []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"}; !slices.Equal(got, want) {
		t.Fatalf("prefixes = %v, want %v", got, want)
	}
	o := obs[0]
	if !slices.Equal(o.Route.Path, asns(asX, asY, asZ)) || !o.Route.PathKnown || o.Route.OriginSet ||
		!slices.Equal(o.Evidence.Neighbours, asns(asP2)) || o.Evidence.Direct || o.Evidence.CollectorPeers != 1 {
		t.Errorf("P1 P2 X Y Z: %+v", o)
	}
	o = obs[1]
	if !slices.Equal(o.Route.Path, asns(asX, asX, asX, asY)) || !o.Route.PathKnown ||
		len(o.Evidence.Neighbours) != 0 || !o.Evidence.Direct || o.Evidence.CollectorPeers != 1 {
		t.Errorf("X X X Y from a direct feed: %+v", o)
	}
	o = obs[2]
	if !slices.Equal(o.Route.Path, asns(asX, asY)) || !o.Route.PathKnown ||
		!slices.Equal(o.Evidence.Neighbours, asns(asP2)) || o.Evidence.Direct {
		t.Errorf("(P1 P2)(X Y): %+v", o)
	}
	for _, o := range obs {
		if o.Family != v4u || o.Evidence.PeerAddr.IsValid() || !o.Evidence.Time.Equal(at(0)) {
			t.Errorf("%v: family %v, PeerAddr %v, Time %v", o.Route.Prefix, o.Family, o.Evidence.PeerAddr, o.Evidence.Time)
		}
	}
	want := CollectorInfo{Entries: 4, Through: 3, Direct: 1}
	if info != want {
		t.Errorf("info = %+v, want %+v", info, want)
	}
}

func TestCollectorPoisoning(t *testing.T) {
	obs, _ := mustCollect(t,
		pitRec(at(0), cpeer(1, asP1)),
		ribRec(at(0), "10.0.0.0/24", ent(0, mrtgen.Seq(asP1, asX, asY, asX, asZ))),
	)
	o := byPrefix(t, obs, "10.0.0.0/24")
	if !slices.Equal(o.Route.Path, asns(asX, asY, asX, asZ)) || !slices.Equal(o.Evidence.Neighbours, asns(asP1)) {
		t.Errorf("P X Y X Z: %+v", o)
	}
}

// Review Focus 1: X as the origin, seen through a neighbour.
func TestCollectorOriginIsX(t *testing.T) {
	obs, _ := mustCollect(t,
		pitRec(at(0), cpeer(1, asP1)),
		ribRec(at(0), "10.0.0.0/24", ent(0, mrtgen.Seq(asP1, asX))),
	)
	o := byPrefix(t, obs, "10.0.0.0/24")
	if !slices.Equal(o.Route.Path, asns(asX)) || !o.Route.PathKnown || !slices.Equal(o.Evidence.Neighbours, asns(asP1)) || o.Evidence.Direct {
		t.Errorf("P X: %+v", o)
	}
}

func TestCollectorDedup(t *testing.T) {
	// Two RIB files, each with its own PEER_INDEX_TABLE, concatenated.
	a1, a2, b1 := cpeer(1, asP2), cpeer(2, asP3), cpeer(3, asP1)
	fileA := [][]byte{
		pitRec(at(0), a1, a2),
		ribRec(at(0), "10.0.0.0/24",
			ent(0, mrtgen.Seq(asP2, asX, asY)),
			ent(1, mrtgen.Seq(asP3, asZ, asX, asY)), // neighbour Z, through a second peer
		),
	}
	fileB := [][]byte{
		// The same peer as a1 (same BGP ID, address and AS) at index 1 here.
		pitRec(at(10), b1, a1),
		ribRec(at(10), "10.0.0.0/24",
			ent(0, mrtgen.Seq(asP1, asX, asY)),
			ent(1, mrtgen.Seq(asP2, asX, asY)),
			ent(0, mrtgen.Seq(asP1, asX, asZ)), // another suffix: another observation
			// The same flattened Path, other segments: X {Y} is not X Y.
			ent(0, mrtgen.Seq(asP1, asX), mrtgen.Set(asY)),
			// The same path split into two AS_SEQUENCEs is the same suffix.
			ent(1, mrtgen.Seq(asP2, asX), mrtgen.Seq(asY)),
		),
	}
	obs, info := mustCollect(t, slices.Concat(fileA, fileB)...)
	if len(obs) != 3 {
		t.Fatalf("%d observations, want 3: %+v", len(obs), obs)
	}
	// Path order: X; X Y; X Z (X {Y} has Path X).
	if o := obs[0]; !slices.Equal(o.Route.Path, asns(asX)) || o.Route.PathKnown || !o.Route.OriginSet ||
		!slices.Equal(o.Evidence.Neighbours, asns(asP1)) || o.Evidence.CollectorPeers != 1 {
		t.Errorf("X {Y}: %+v", o)
	}
	o := obs[1]
	if !slices.Equal(o.Route.Path, asns(asX, asY)) || !o.Route.PathKnown {
		t.Fatalf("X Y: %+v", o)
	}
	if !slices.Equal(o.Evidence.Neighbours, asns(asZ, asP1, asP2)) {
		t.Errorf("neighbours = %v, want sorted %v", o.Evidence.Neighbours, asns(asZ, asP1, asP2))
	}
	if o.Evidence.CollectorPeers != 3 || o.Evidence.Direct || !o.Evidence.Time.Equal(at(10)) {
		t.Errorf("X Y evidence = %+v, want 3 collector peers (a1 once), time at(10)", o.Evidence)
	}
	if o := obs[2]; !slices.Equal(o.Route.Path, asns(asX, asZ)) || !slices.Equal(o.Evidence.Neighbours, asns(asP1)) {
		t.Errorf("X Z: %+v", o)
	}
	if info.Entries != 7 || info.Through != 7 {
		t.Errorf("info = %+v", info)
	}

	// The brief's case alone: two collector peers, two neighbours, one observation.
	obs, _ = mustCollect(t,
		pitRec(at(0), a1), ribRec(at(0), "10.0.0.0/24", ent(0, mrtgen.Seq(asP2, asX, asY))),
		pitRec(at(5), b1), ribRec(at(5), "10.0.0.0/24", ent(0, mrtgen.Seq(asP1, asX, asY))),
	)
	if len(obs) != 1 || !slices.Equal(obs[0].Evidence.Neighbours, asns(asP1, asP2)) || obs[0].Evidence.CollectorPeers != 2 ||
		!obs[0].Evidence.Time.Equal(at(5)) {
		t.Errorf("two collectors: %+v", obs)
	}

	// A direct sighting and one through a neighbour of the same suffix.
	obs, info = mustCollect(t,
		pitRec(at(0), cpeer(1, asX), b1),
		ribRec(at(0), "10.0.0.0/24", ent(0, mrtgen.Seq(asX, asY)), ent(1, mrtgen.Seq(asP1, asX, asY))),
	)
	if len(obs) != 1 || !obs[0].Evidence.Direct || !slices.Equal(obs[0].Evidence.Neighbours, asns(asP1)) ||
		obs[0].Evidence.CollectorPeers != 2 || info.Direct != 1 {
		t.Errorf("direct and through P1: %+v, %+v", obs, info)
	}
}

func TestCollectorNotSequence(t *testing.T) {
	obs, info := mustCollect(t,
		pitRec(at(0), cpeer(1, asP1)),
		// X inside an AS_SET only: not an observation.
		ribRec(at(0), "10.0.0.0/24", ent(0, mrtgen.Seq(asP1, asY), mrtgen.Set(asX, asZ))),
		// X in the sequence part, an AS_SET after it: PathKnown false.
		ribRec(at(0), "10.0.1.0/24", ent(0, mrtgen.Seq(asP1, asX, asY), mrtgen.Set(asZ, asP3))),
		// X leftmost in an AS_SET and again in a later AS_SEQUENCE: the
		// leftmost occurrence decides, so no observation.
		ribRec(at(0), "10.0.2.0/24", ent(0, mrtgen.Seq(asP1), mrtgen.Set(asX), mrtgen.Seq(asX, asZ))),
		// X in a confederation segment.
		ribRec(at(0), "10.0.3.0/24", ent(0, mrtgen.Seq(asP1), mrtgen.ConfedSeq(asX), mrtgen.Seq(asY))),
		// AS_TRANS after X: PathKnown false.
		ribRec(at(0), "10.0.4.0/24", ent(0, mrtgen.Seq(asP1, asX, bgp.ASTrans, asZ))),
	)
	if got, want := prefixes(obs), []string{"10.0.1.0/24", "10.0.4.0/24"}; !slices.Equal(got, want) {
		t.Fatalf("prefixes = %v, want %v", got, want)
	}
	if o := obs[0]; !slices.Equal(o.Route.Path, asns(asX, asY)) || o.Route.PathKnown || !o.Route.OriginSet ||
		!slices.Equal(o.Evidence.Neighbours, asns(asP1)) {
		t.Errorf("P X Y {Z P3}: %+v", o)
	}
	if o := obs[1]; !slices.Equal(o.Route.Path, asns(asX, bgp.ASTrans, asZ)) || o.Route.PathKnown {
		t.Errorf("P X 23456 Z: %+v", o)
	}
	if info.Through != 5 || info.NotSequence != 3 || info.NoNeighbour != 0 {
		t.Errorf("info = %+v", info)
	}
}

// Ruling R11 (a, b): the neighbour is the AS_SEQUENCE element immediately
// left of X; anything else there gives no neighbour and no direct feed, and
// segments left of X do not make the suffix unknown.
func TestCollectorNoNeighbour(t *testing.T) {
	obs, info := mustCollect(t,
		pitRec(at(0), cpeer(1, asP1)),
		ribRec(at(0), "10.0.0.0/24", ent(0, mrtgen.Set(asP1, asP2), mrtgen.Seq(asX, asY))),
		ribRec(at(0), "10.0.1.0/24", ent(0, mrtgen.ConfedSeq(asP1), mrtgen.Seq(asX, asY))),
		// AS_TRANS left of X names no AS: recording it would invent a neighbour.
		ribRec(at(0), "10.0.2.0/24", ent(0, mrtgen.Seq(asP1, bgp.ASTrans, asX, asY))),
	)
	if got, want := prefixes(obs), []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"}; !slices.Equal(got, want) {
		t.Fatalf("prefixes = %v, want %v", got, want)
	}
	for _, o := range obs {
		if !slices.Equal(o.Route.Path, asns(asX, asY)) || !o.Route.PathKnown || len(o.Evidence.Neighbours) != 0 || o.Evidence.Direct {
			t.Errorf("%v: %+v", o.Route.Prefix, o)
		}
	}
	if info.NoNeighbour != 3 || info.Direct != 0 || info.Through != 3 {
		t.Errorf("info = %+v", info)
	}
}

func TestCollectorComms(t *testing.T) {
	obs, _ := mustCollect(t,
		pitRec(at(0), cpeer(1, asP1), cpeer(2, asX)),
		ribRec(at(0), "10.0.0.0/24",
			mrtgen.Entry{PeerIndex: 0, Attrs: slices.Concat(pathAttrs(mrtgen.Seq(asP1, asX)), mrtgen.Communities(bgp.Community(64500<<16|1)))},
			mrtgen.Entry{PeerIndex: 1, Attrs: slices.Concat(pathAttrs(mrtgen.Seq(asX, asY)), mrtgen.Communities(bgp.Community(64500<<16|2)))},
		),
		ribRec(at(0), "10.0.1.0/24", ent(1, mrtgen.Seq(asX))),
	)
	if len(obs) != 3 {
		t.Fatalf("%d observations", len(obs))
	}
	for _, o := range obs {
		if o.Route.CommsKnown || len(o.Route.Communities) != 0 {
			t.Errorf("%v %v: CommsKnown %v, communities %v", o.Route.Prefix, o.Route.Path, o.Route.CommsKnown, o.Route.Communities)
		}
	}
}

func TestCollectorIgnoresUpdates(t *testing.T) {
	obs, info := mustCollect(t,
		established(at(0)),
		upd(at(1), nil, nlri("10.9.0.0/24"), attrs4(asX, asY)),
		pitRec(at(2), cpeer(1, asP1)),
		ribRec(at(2), "10.0.0.0/24", ent(0, mrtgen.Seq(asP1, asX))),
		upd(at(3), nlri("10.0.0.0/24"), nlri("10.9.1.0/24"), attrs4(asX)),
	)
	if got, want := prefixes(obs), []string{"10.0.0.0/24"}; !slices.Equal(got, want) {
		t.Errorf("prefixes = %v, want %v", got, want)
	}
	if info != (CollectorInfo{Entries: 1, Through: 1, Ignored: 3}) {
		t.Errorf("info = %+v", info)
	}

	// Ruling R12 (1): broken BGP4MP records are ignored too, never Skipped. A
	// record with AFI 3 is a *mrt.RecordError from the reader; a message
	// whose BGP header is broken is one from mrt.Routes when it gets there;
	// a BGP4MP_ET record is a BGP4MP record.
	badAFI := msg(at(1), mrt.SubMessageAS4, asX, peerAddr, localAddr, nil)
	badAFI[12+8+2+1] = 3
	badHeader := msg(at(1), mrt.SubMessageAS4, asX, peerAddr, localAddr, []byte{1, 2, 3})
	st := mrt.SubMessageAS4
	et := mrtgen.Header(mrt.TypeBGP4MPET, st, at(1), mrtgen.BGP4MP(st, asX, asL, peerAddr, localAddr,
		mrtgen.Update(nil, nlri("10.9.2.0/24"), attrs4(asX), false)))
	obs, info = mustCollect(t,
		pitRec(at(2), cpeer(1, asP1)),
		badAFI, badHeader, et,
		ribRec(at(2), "10.0.0.0/24", ent(0, mrtgen.Seq(asP1, asX))),
	)
	if got, want := prefixes(obs), []string{"10.0.0.0/24"}; !slices.Equal(got, want) {
		t.Errorf("broken BGP4MP: prefixes = %v, want %v", got, want)
	}
	if info != (CollectorInfo{Entries: 1, Through: 1, Ignored: 3}) {
		t.Errorf("broken BGP4MP: info = %+v, want Skipped 0, Ignored 3", info)
	}
}

// Ruling R12 (1): a broken PEER_INDEX_TABLE still reaches mrt.Routes, so the
// previous table is not used for the entries after it.
func TestCollectorBrokenPeerIndexTable(t *testing.T) {
	good := pitRec(at(0), cpeer(1, asP1))
	body := mrtgen.PeerIndexTable(collectorID, "", []mrt.Peer{cpeer(1, asP1)})
	broken := mrtgen.Header(mrt.TypeTableDumpV2, mrt.SubPeerIndexTable, at(1), body[:len(body)-2])
	obs, info := mustCollect(t, good, broken, ribRec(at(1), "10.0.0.0/24", ent(0, mrtgen.Seq(asP1, asX))))
	if len(obs) != 0 || info.Skipped != 2 || info.Ignored != 0 {
		t.Errorf("after a broken PIT: %v, %+v; want no observation, Skipped 2", prefixes(obs), info)
	}
}

// Ruling R12 (2): with X first, the collector peer's AS decides: X is a
// direct feed, another AS is the neighbour (a transparent route server),
// AS_TRANS names no AS.
func TestCollectorDirectNeedsPeerAS(t *testing.T) {
	obs, info := mustCollect(t,
		pitRec(at(0), cpeer(1, asX), cpeer(2, asP1)),
		ribRec(at(0), "10.0.0.0/24", ent(0, mrtgen.Seq(asX, asY))),
		ribRec(at(0), "10.0.1.0/24", ent(1, mrtgen.Seq(asX, asY))),
		// A legacy TABLE_DUMP from a 4-byte peer: its AS is AS_TRANS.
		tableDump(at(0), pfx("10.0.2.0/24"), netip.MustParseAddr("198.51.100.9"), bgp.ASTrans,
			slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(false, mrtgen.Seq(asX, asY)))),
	)
	if got, want := prefixes(obs), []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"}; !slices.Equal(got, want) {
		t.Fatalf("prefixes = %v, want %v", got, want)
	}
	if ev := obs[0].Evidence; !ev.Direct || len(ev.Neighbours) != 0 {
		t.Errorf("peer AS X: %+v, want direct", ev)
	}
	if ev := obs[1].Evidence; ev.Direct || !slices.Equal(ev.Neighbours, asns(asP1)) {
		t.Errorf("peer AS P1: %+v, want neighbour P1, not direct", ev)
	}
	if ev := obs[2].Evidence; ev.Direct || len(ev.Neighbours) != 0 {
		t.Errorf("peer AS AS_TRANS: %+v, want no neighbour, not direct", ev)
	}
	for _, o := range obs {
		if !slices.Equal(o.Route.Path, asns(asX, asY)) || !o.Route.PathKnown {
			t.Errorf("%v: path %v", o.Route.Prefix, o.Route.Path)
		}
	}
	if info.Direct != 1 || info.NoNeighbour != 1 || info.Through != 3 {
		t.Errorf("info = %+v, want Direct 1, NoNeighbour 1", info)
	}
}

// Ruling R11 (c): a RIB entry RFC 7606 would not keep is skipped and counted
// Malformed, whether or not X is on its path; an attribute discarded under
// RFC 7606 does not make it malformed.
func TestCollectorMalformed(t *testing.T) {
	badComm := mrtgen.Raw(mrtgen.FlagOptional|mrtgen.FlagTransitive, 8, []byte{1, 2, 3})
	badMPReach := mrtgen.Raw(mrtgen.FlagOptional, 14, []byte{40})
	badAggregator := mrtgen.Raw(mrtgen.FlagOptional|mrtgen.FlagTransitive, 7, []byte{1})
	obs, info := mustCollect(t,
		pitRec(at(0), cpeer(1, asP1)),
		ribRec(at(0), "10.0.0.0/24", mrtgen.Entry{PeerIndex: 0, Attrs: slices.Concat(pathAttrs(mrtgen.Seq(asP1, asX)), badComm)}),
		ribRec(at(0), "10.0.1.0/24", mrtgen.Entry{PeerIndex: 0, Attrs: slices.Concat(pathAttrs(mrtgen.Seq(asP1, asX)), badMPReach)}),
		ribRec(at(0), "10.0.2.0/24", mrtgen.Entry{PeerIndex: 0, Attrs: slices.Concat(pathAttrs(mrtgen.Seq(asP1, asY)), badComm)}),
		ribRec(at(0), "10.0.3.0/24", mrtgen.Entry{PeerIndex: 0, Attrs: slices.Concat(pathAttrs(mrtgen.Seq(asP1, asX)), badAggregator)}),
	)
	if got, want := prefixes(obs), []string{"10.0.3.0/24"}; !slices.Equal(got, want) {
		t.Errorf("prefixes = %v, want %v", got, want)
	}
	if info != (CollectorInfo{Entries: 4, Malformed: 3, Through: 1}) {
		t.Errorf("info = %+v", info)
	}
}

// Ruling R11 (c): a record or entry mrt cannot read is counted Skipped; a
// truncated stream ends the sequence with the error and nothing else.
func TestCollectorRecordErrors(t *testing.T) {
	obs, info := mustCollect(t,
		pitRec(at(0), cpeer(1, asP1)),
		ribRec(at(0), "10.0.0.0/24", ent(0, mrtgen.Seq(asP1, asX)), ent(7, mrtgen.Seq(asP1, asX, asY))),
		ribRec(at(0), "10.0.1.0/24", ent(0, mrtgen.Seq(asP1, asX))),
	)
	if got, want := prefixes(obs), []string{"10.0.0.0/24", "10.0.1.0/24"}; !slices.Equal(got, want) || info.Skipped != 1 || info.Entries != 2 {
		t.Errorf("a peer index not in the table: %v, %+v", got, info)
	}

	rec := ribRec(at(0), "10.0.1.0/24", ent(0, mrtgen.Seq(asP1, asX)))
	obs, _, err := collect(t, pitRec(at(0), cpeer(1, asP1)), ribRec(at(0), "10.0.0.0/24", ent(0, mrtgen.Seq(asP1, asX))), rec[:len(rec)-3])
	if !errors.Is(err, mrt.ErrTruncated) || len(obs) != 0 {
		t.Errorf("a truncated stream: %v, %v", prefixes(obs), err)
	}
}

func TestCollectorFamiliesAndOrder(t *testing.T) {
	v6 := mrt.SubRIBIPv6Unicast
	rib6 := mrtgen.Header(mrt.TypeTableDumpV2, v6, at(0), mrtgen.RIB(v6, 0, pfx("2001:db8:1::/48"), []mrtgen.Entry{
		{PeerIndex: 0, Attrs: slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(true, mrtgen.Seq(asP1, asX)), mrtgen.MPReachAbbrev(nh6))},
	}))
	obs, info := mustCollect(t,
		pitRec(at(0), cpeer(1, asP1)),
		rib6,
		ribRec(at(0), "10.0.1.0/24", ent(0, mrtgen.Seq(asP1, asX, asZ)), ent(0, mrtgen.Seq(asP1, asX, asY))),
		ribRec(at(0), "10.0.0.0/25", ent(0, mrtgen.Seq(asP1, asX))),
		ribRec(at(0), "10.0.0.0/24", ent(0, mrtgen.Seq(asP1, asX))),
		// A legacy TABLE_DUMP entry (2-byte ASNs), its peer's AS is P2.
		tableDump(at(3), pfx("10.0.2.0/24"), netip.MustParseAddr("198.51.100.9"), asP2,
			slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(false, mrtgen.Seq(asP2, asX, asY)))),
	)
	if got, want := prefixes(obs), []string{"10.0.0.0/24", "10.0.0.0/25", "10.0.1.0/24", "10.0.1.0/24", "10.0.2.0/24", "2001:db8:1::/48"}; !slices.Equal(got, want) {
		t.Fatalf("prefixes = %v, want %v", got, want)
	}
	if !slices.Equal(obs[2].Route.Path, asns(asX, asY)) || !slices.Equal(obs[3].Route.Path, asns(asX, asZ)) {
		t.Errorf("same prefix, path order: %v then %v", obs[2].Route.Path, obs[3].Route.Path)
	}
	if o := obs[4]; !slices.Equal(o.Route.Path, asns(asX, asY)) || !slices.Equal(o.Evidence.Neighbours, asns(asP2)) || !o.Evidence.Time.Equal(at(3)) {
		t.Errorf("TABLE_DUMP: %+v", o)
	}
	if o := obs[5]; o.Family != v6u || !slices.Equal(o.Route.Path, asns(asX)) {
		t.Errorf("IPv6: %+v", o)
	}
	if info.Entries != 6 || info.Through != 6 {
		t.Errorf("info = %+v", info)
	}
}

// The sequence stops when the consumer stops.
func TestCollectorStopsEarly(t *testing.T) {
	seq, _ := Collector(mrt.Records(bytes.NewReader(slices.Concat(pitRec(at(0), cpeer(1, asP1)),
		ribRec(at(0), "10.0.0.0/24", ent(0, mrtgen.Seq(asP1, asX))),
		ribRec(at(0), "10.0.1.0/24", ent(0, mrtgen.Seq(asP1, asX)))))), types.ASN(asX))
	n := 0
	for range seq {
		n++
		break
	}
	if n != 1 {
		t.Errorf("n = %d", n)
	}
}

// leftOf skips empty segments, which mrt v0.4.0 reports as a malformed
// AS_PATH and so never reach it from Collector.
func TestCollectorLeftOfEmptySegments(t *testing.T) {
	empty := bgp.Segment{Type: bgp.ASSet}
	tests := []struct {
		segs []bgp.Segment
		as   bgp.ASN
		kind neighbourKind
	}{
		{[]bgp.Segment{mrtgen.Seq(asP1), empty, mrtgen.Seq(asX)}, asP1, leftAS},
		{[]bgp.Segment{empty, mrtgen.Seq(asX)}, 0, leftNone},
		{[]bgp.Segment{mrtgen.Set(asP1), empty, mrtgen.Seq(asX)}, 0, leftOpaque},
	}
	for i, tt := range tests {
		if as, kind := leftOf(tt.segs, len(tt.segs)-1, 0); as != tt.as || kind != tt.kind {
			t.Errorf("%d: leftOf = %d, %d; want %d, %d", i, as, kind, tt.as, tt.kind)
		}
	}
}

// Another sighting of a known (family, prefix, suffix) allocates nothing: the
// suffix and its key are built only for a new key.
func TestCollectorRepeatSightingDoesNotAllocate(t *testing.T) {
	c := collection{x: asX, byKey: map[string]int{}, peers: map[mrt.Peer]uint32{}}
	r := mrt.Route{Time: at(0), Kind: mrt.KindRIB, Peer: cpeer(1, asP1), Family: v4u, Prefix: pfx("10.0.0.0/24"),
		Path: &bgp.Path{ASPath: bgp.ASPath{Segments: []bgp.Segment{mrtgen.Seq(asP1, asX, asY), mrtgen.Set(asP3, asZ)}}}}
	c.entry(r)
	if n := testing.AllocsPerRun(100, func() { c.entry(r) }); n != 0 {
		t.Errorf("a repeated sighting: %v allocations, want 0", n)
	}
	if len(c.obs) != 1 || c.info.Through != 102 || len(c.obs[0].peers) != 1 { // AllocsPerRun runs f once more to warm up
		t.Errorf("%d observations, Through %d", len(c.obs), c.info.Through)
	}
}
