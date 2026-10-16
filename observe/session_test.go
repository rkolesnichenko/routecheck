package observe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/rkolesnichenko/mrt"
	"github.com/rkolesnichenko/mrt/bgp"
	"github.com/rkolesnichenko/routecheck/internal/mrtgen"
	"github.com/rkolesnichenko/routecheck/verdict"
	"github.com/rkolesnichenko/rpsl/types"
)

// The session under test: L (AS64496) at localAddr, X (AS64500) at peerAddr.
const (
	asL bgp.ASN = 64496
	asX bgp.ASN = 64500
	asY bgp.ASN = 64501
	asZ bgp.ASN = 64502
)

var (
	peerAddr  = netip.MustParseAddr("192.0.2.1")
	localAddr = netip.MustParseAddr("192.0.2.2")
	peer6     = netip.MustParseAddr("2001:db8::1")
	local6    = netip.MustParseAddr("2001:db8::2")
	nh4       = netip.MustParseAddr("192.0.2.1")
	nh6       = netip.MustParseAddr("2001:db8::1")
	t0        = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	v4u       = bgp.Family{AFI: bgp.AFIIPv4, SAFI: bgp.SAFIUnicast}
	v6u       = bgp.Family{AFI: bgp.AFIIPv6, SAFI: bgp.SAFIUnicast}
	selX      = SessionSel{Peer: types.ASN(asX)}
)

func at(sec int) time.Time { return t0.Add(time.Duration(sec) * time.Second) }

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func nlri(ps ...string) []bgp.NLRI {
	var out []bgp.NLRI
	for _, p := range ps {
		out = append(out, bgp.NLRI{Prefix: pfx(p)})
	}
	return out
}

// attrs4 is a well-formed attribute block for IPv4 NLRI with AS path path.
func attrs4(path ...bgp.ASN) []byte {
	return slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(true, mrtgen.Seq(path...)), mrtgen.NextHop(nh4))
}

// msg is a whole BGP4MP record of a message X sent L on the v4 session.
func msg(ts time.Time, st mrt.Subtype, peerAS bgp.ASN, peer, local netip.Addr, m []byte) []byte {
	return mrtgen.Header(mrt.TypeBGP4MP, st, ts, mrtgen.BGP4MP(st, peerAS, asL, peer, local, m))
}

// upd is an UPDATE from X on the v4 session (4-byte ASNs, no add-path).
func upd(ts time.Time, withdrawn, announced []bgp.NLRI, attrs []byte) []byte {
	return msg(ts, mrt.SubMessageAS4, asX, peerAddr, localAddr, mrtgen.Update(withdrawn, announced, attrs, false))
}

// state is a state change of the v4 session with X.
func state(ts time.Time, old, new mrt.State) []byte {
	st := mrt.SubStateChangeAS4
	return mrtgen.Header(mrt.TypeBGP4MP, st, ts, mrtgen.StateChange(st, asX, asL, peerAddr, localAddr, old, new))
}

func established(ts time.Time) []byte {
	return state(ts, mrt.StateOpenConfirm, mrt.StateEstablished)
}

// run replays the concatenated records and returns the observations, the
// info and the first error (the sequence is drained either way).
func run(t *testing.T, sel SessionSel, recs ...[]byte) ([]Observation, SessionInfo, error) {
	t.Helper()
	seq, info := Session(mrt.Records(bytes.NewReader(slices.Concat(recs...))), sel)
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

func mustRun(t *testing.T, sel SessionSel, recs ...[]byte) ([]Observation, SessionInfo) {
	t.Helper()
	obs, info, err := run(t, sel, recs...)
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	return obs, info
}

// prefixes lists the observations' prefixes in order.
func prefixes(obs []Observation) []string {
	var out []string
	for _, o := range obs {
		out = append(out, o.Route.Prefix.String())
	}
	return out
}

func asns(a ...bgp.ASN) []types.ASN {
	out := make([]types.ASN, len(a))
	for i, x := range a {
		out[i] = types.ASN(x)
	}
	return out
}

func TestRouteConversion(t *testing.T) {
	seq := func(a ...bgp.ASN) bgp.Segment { return bgp.Segment{Type: bgp.ASSequence, ASNs: a} }
	seg := func(st bgp.SegmentType, a ...bgp.ASN) bgp.Segment { return bgp.Segment{Type: st, ASNs: a} }
	p := pfx("10.0.0.0/24")
	tests := []struct {
		name      string
		segs      []bgp.Segment
		path      []types.ASN
		known     bool
		originSet bool
	}{
		{"sequences concatenated, prepends kept", []bgp.Segment{seq(asX, asX, asX), seq(asY)}, asns(asX, asX, asX, asY), true, false},
		{"one AS", []bgp.Segment{seq(asX)}, asns(asX), true, false},
		{"empty path", nil, nil, true, false},
		{"last segment AS_SET", []bgp.Segment{seq(asX, asY), seg(bgp.ASSet, 1, 2)}, asns(asX, asY), false, true},
		{"AS_SET inside", []bgp.Segment{seq(asX), seg(bgp.ASSet, 1, 2), seq(asY)}, asns(asX, asY), false, false},
		{"AS_CONFED_SEQUENCE", []bgp.Segment{seg(bgp.ASConfedSequence, 65001), seq(asX, asY)}, asns(asX, asY), false, false},
		{"AS_CONFED_SET", []bgp.Segment{seq(asX), seg(bgp.ASConfedSet, 65001, 65002), seq(asY)}, asns(asX, asY), false, false},
		{"AS_TRANS left in the path", []bgp.Segment{seq(asX, bgp.ASTrans, asY)}, asns(asX, bgp.ASTrans, asY), false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bp := &bgp.Path{ASPath: bgp.ASPath{Segments: tc.segs}, Communities: []bgp.Community{0xFDE80001, 0xFFFFFF01}}
			r := Route(p, bp, true)
			want := verdict.Route{Prefix: p, Path: tc.path, PathKnown: tc.known, OriginSet: tc.originSet,
				Communities: []uint32{0xFDE80001, 0xFFFFFF01}, CommsKnown: true}
			if !routeEqual(r, want) {
				t.Errorf("Route = %+v, want %+v", r, want)
			}
		})
	}
	t.Run("commsKnown passed through, no communities", func(t *testing.T) {
		r := Route(p, &bgp.Path{ASPath: bgp.ASPath{Segments: []bgp.Segment{seq(asX)}}}, false)
		if r.CommsKnown || len(r.Communities) != 0 || !r.PathKnown {
			t.Errorf("Route = %+v", r)
		}
	})
	t.Run("nil path", func(t *testing.T) {
		r := Route(p, nil, true)
		if r.PathKnown || len(r.Path) != 0 || r.Prefix != p {
			t.Errorf("Route(nil) = %+v, want an unknown empty path", r)
		}
	})
	t.Run("result shares nothing with the bgp.Path", func(t *testing.T) {
		bp := &bgp.Path{ASPath: bgp.ASPath{Segments: []bgp.Segment{seq(asX, asY)}}, Communities: []bgp.Community{1}}
		r := Route(p, bp, true)
		bp.ASPath.Segments[0].ASNs[0] = 1
		bp.Communities[0] = 2
		if r.Path[0] != types.ASN(asX) || r.Communities[0] != 1 {
			t.Errorf("Route aliases its input: %+v", r)
		}
	})
	// After mrt's AS4 merge (a 2-byte session): AS4_PATH replaces the
	// AS_TRANS, and without AS4_PATH the AS_TRANS stays and the path is unknown.
	t.Run("AS4 merge", func(t *testing.T) {
		big := bgp.ASN(4200000001)
		merged := slices.Concat(mrtgen.ASPath(false, mrtgen.Seq(asX, bgp.ASTrans)), mrtgen.AS4PathAttr(mrtgen.Seq(asX, big)))
		bp, _ := bgp.NewAttrs(merged, bgp.Context{}).Decode()
		if r := Route(p, &bp, true); !r.PathKnown || !slices.Equal(r.Path, asns(asX, big)) {
			t.Errorf("merged: %+v", r)
		}
		bp, _ = bgp.NewAttrs(mrtgen.ASPath(false, mrtgen.Seq(asX, bgp.ASTrans)), bgp.Context{}).Decode()
		if r := Route(p, &bp, true); r.PathKnown || !slices.Equal(r.Path, asns(asX, bgp.ASTrans)) {
			t.Errorf("unmerged AS_TRANS: %+v", r)
		}
	})
}

func routeEqual(a, b verdict.Route) bool {
	return a.Prefix == b.Prefix && slices.Equal(a.Path, b.Path) && a.PathKnown == b.PathKnown &&
		a.OriginSet == b.OriginSet && slices.Equal(a.Communities, b.Communities) && a.CommsKnown == b.CommsKnown
}

func TestSessionReplay(t *testing.T) {
	v6attrs := func(ps ...string) []byte {
		return slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(true, mrtgen.Seq(asX, asZ)),
			mrtgen.MPReach(v6u, []netip.Addr{nh6}, nlri(ps...), false))
	}
	withComm := slices.Concat(attrs4(asX, asZ), mrtgen.Communities(0xFBF00001))
	obs, info := mustRun(t, selX,
		established(at(0)),
		upd(at(1), nil, nlri("10.0.1.0/24", "10.0.0.0/24", "10.0.2.0/24"), attrs4(asX, asY)),
		upd(at(2), nil, nlri("10.0.0.0/24"), withComm), // replaces
		upd(at(3), nlri("10.0.1.0/24"), nil, nil),      // deletes
		upd(at(4), nil, nil, v6attrs("2001:db8:2::/48", "2001:db8:1::/48")),
		upd(at(5), nil, nil, mrtgen.MPUnreach(v6u, nlri("2001:db8:2::/48"), false)),
		// In both fields of one UPDATE: withdrawn first, then announced.
		upd(at(6), nlri("10.0.3.0/24"), nlri("10.0.3.0/24"), attrs4(asX)),
		// A withdrawal of a key never announced is nothing.
		upd(at(7), nlri("10.9.0.0/16"), nil, nil),
	)
	if got, want := prefixes(obs), []string{"10.0.0.0/24", "10.0.2.0/24", "10.0.3.0/24", "2001:db8:1::/48"}; !slices.Equal(got, want) {
		t.Fatalf("prefixes = %v, want %v", got, want)
	}
	if info.MidSession || info.DownAtEnd || info.NotFirstAS+info.Malformed+info.MalformedResets+info.Skipped != 0 {
		t.Errorf("info = %+v", info)
	}
	r := obs[0]
	want := verdict.Route{Prefix: pfx("10.0.0.0/24"), Path: asns(asX, asZ), PathKnown: true, Communities: []uint32{0xFBF00001}, CommsKnown: true}
	if !routeEqual(r.Route, want) || r.Family != v4u || !r.Evidence.Time.Equal(at(2)) {
		t.Errorf("re-announced route = %+v", r)
	}
	if !obs[1].Evidence.Time.Equal(at(1)) || !slices.Equal(obs[1].Route.Path, asns(asX, asY)) {
		t.Errorf("first announcement = %+v", obs[1])
	}
	if o := obs[3]; o.Family != v6u || !slices.Equal(o.Route.Path, asns(asX, asZ)) || !o.Route.CommsKnown {
		t.Errorf("v6 route = %+v", o)
	}
	for _, o := range obs {
		if len(o.Evidence.Neighbours) != 0 || o.Evidence.Direct || o.Evidence.CollectorPeers != 0 {
			t.Errorf("session evidence carries collector fields: %+v", o.Evidence)
		}
		if o.Evidence.PeerAddr != peerAddr {
			t.Errorf("Evidence.PeerAddr = %v, want %v", o.Evidence.PeerAddr, peerAddr)
		}
	}
}

func TestSessionStateChanges(t *testing.T) {
	a := nlri("10.0.0.0/24")
	b := nlri("10.0.1.0/24")
	tests := []struct {
		name      string
		recs      [][]byte
		want      []string
		mid, down bool
	}{
		{"Established to Idle clears, down at end",
			[][]byte{established(at(0)), upd(at(1), nil, a, attrs4(asX)), state(at(2), mrt.StateEstablished, mrt.StateIdle)},
			nil, false, true},
		{"into Established clears",
			[][]byte{established(at(0)), upd(at(1), nil, a, attrs4(asX)),
				state(at(2), mrt.StateEstablished, mrt.StateIdle), established(at(3)), upd(at(4), nil, b, attrs4(asX))},
			[]string{"10.0.1.0/24"}, false, false},
		{"Established again without a recorded drop still clears",
			[][]byte{established(at(0)), upd(at(1), nil, a, attrs4(asX)), established(at(2)), upd(at(3), nil, b, attrs4(asX))},
			[]string{"10.0.1.0/24"}, false, false},
		{"session never up: down at end",
			[][]byte{state(at(0), mrt.StateIdle, mrt.StateConnect), state(at(1), mrt.StateConnect, mrt.StateActive)},
			nil, false, true},
		{"first UPDATE before any Established: mid-session",
			[][]byte{upd(at(1), nil, a, attrs4(asX)), upd(at(2), nil, b, attrs4(asX))},
			[]string{"10.0.0.0/24", "10.0.1.0/24"}, true, false},
		{"mid-session start, then a re-establishment: complete again",
			[][]byte{upd(at(1), nil, a, attrs4(asX)), state(at(2), mrt.StateEstablished, mrt.StateIdle),
				established(at(3)), upd(at(4), nil, b, attrs4(asX))},
			[]string{"10.0.1.0/24"}, false, false},
		{"UPDATE after a drop with no Established recorded: mid-session",
			[][]byte{established(at(0)), state(at(1), mrt.StateEstablished, mrt.StateIdle), upd(at(2), nil, b, attrs4(asX))},
			[]string{"10.0.1.0/24"}, true, false},
		{"no state changes at all: not down",
			[][]byte{established(at(0)), upd(at(1), nil, a, attrs4(asX))},
			[]string{"10.0.0.0/24"}, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			obs, info := mustRun(t, selX, tc.recs...)
			if got := prefixes(obs); !slices.Equal(got, tc.want) {
				t.Errorf("prefixes = %v, want %v", got, tc.want)
			}
			if info.MidSession != tc.mid || info.DownAtEnd != tc.down {
				t.Errorf("MidSession, DownAtEnd = %v, %v, want %v, %v", info.MidSession, info.DownAtEnd, tc.mid, tc.down)
			}
		})
	}
}

// Two sessions with X (one per family, PeerAddr not given) are two states:
// the v6 session going down leaves the v4 session's routes.
func TestSessionTwoSessions(t *testing.T) {
	st := mrt.SubStateChangeAS4
	state6 := func(ts time.Time, old, new mrt.State) []byte {
		return mrtgen.Header(mrt.TypeBGP4MP, st, ts, mrtgen.StateChange(st, asX, asL, peer6, local6, old, new))
	}
	upd6 := func(ts time.Time, ps ...string) []byte {
		a := slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(true, mrtgen.Seq(asX)),
			mrtgen.MPReach(v6u, []netip.Addr{nh6}, nlri(ps...), false))
		return msg(ts, mrt.SubMessageAS4, asX, peer6, local6, mrtgen.Update(nil, nil, a, false))
	}
	recs := [][]byte{
		established(at(0)), state6(at(0), mrt.StateOpenConfirm, mrt.StateEstablished),
		upd(at(1), nil, nlri("10.0.0.0/24"), attrs4(asX)),
		upd6(at(2), "2001:db8:1::/48"),
	}
	obs, info := mustRun(t, selX, append(recs, state6(at(3), mrt.StateEstablished, mrt.StateIdle))...)
	if got := prefixes(obs); !slices.Equal(got, []string{"10.0.0.0/24"}) || info.DownAtEnd {
		t.Errorf("v6 down: prefixes = %v, DownAtEnd %v", got, info.DownAtEnd)
	}
	obs, info = mustRun(t, selX, append(recs, state6(at(3), mrt.StateEstablished, mrt.StateIdle),
		state(at(4), mrt.StateEstablished, mrt.StateIdle))...)
	if len(obs) != 0 || !info.DownAtEnd {
		t.Errorf("both down: %v, DownAtEnd %v", prefixes(obs), info.DownAtEnd)
	}
	// One session given by address: only its routes.
	obs, _ = mustRun(t, SessionSel{Peer: types.ASN(asX), PeerAddr: peer6}, recs...)
	if got := prefixes(obs); !slices.Equal(got, []string{"2001:db8:1::/48"}) {
		t.Errorf("PeerAddr %v: prefixes = %v", peer6, got)
	}
}

// Review Focus 3: add-path keys.
func TestSessionAddPath(t *testing.T) {
	p := pfx("10.0.0.0/24")
	ap := func(ts time.Time, withdrawn, announced []bgp.NLRI, attrs []byte) []byte {
		return msg(ts, mrt.SubMessageAS4AddPath, asX, peerAddr, localAddr, mrtgen.Update(withdrawn, announced, attrs, true))
	}
	id := func(n uint32) []bgp.NLRI { return []bgp.NLRI{{Prefix: p, PathID: n, HasPathID: true}} }
	v6 := []bgp.NLRI{{Prefix: pfx("2001:db8:1::/48"), PathID: 7, HasPathID: true}, {Prefix: pfx("2001:db8:1::/48"), PathID: 8, HasPathID: true}}
	obs, _ := mustRun(t, selX,
		established(at(0)),
		ap(at(1), nil, id(1), attrs4(asX, asY)),
		ap(at(2), nil, id(2), attrs4(asX, asZ)),
		ap(at(3), id(1), nil, nil),                        // leaves ID 2
		upd(at(4), nil, nlri("10.0.0.0/24"), attrs4(asX)), // a plain message: path ID 0
		ap(at(5), nil, id(3), attrs4(asX, asY, asZ)),
		upd(at(6), nlri("10.0.0.0/24"), nil, nil), // a plain withdrawal deletes ID 0 only
		ap(at(7), nil, nil, slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(true, mrtgen.Seq(asX)),
			mrtgen.MPReach(v6u, []netip.Addr{nh6}, v6, true))),
		ap(at(8), nil, nil, mrtgen.MPUnreach(v6u, v6[:1], true)),
	)
	type key struct {
		p    string
		path int
	}
	var got []key
	for _, o := range obs {
		got = append(got, key{o.Route.Prefix.String(), len(o.Route.Path)})
	}
	// ID 2 (X Z), ID 3 (X Y Z), and v6 ID 8 (X); in prefix then path ID order.
	want := []key{{"10.0.0.0/24", 2}, {"10.0.0.0/24", 3}, {"2001:db8:1::/48", 1}}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if !slices.Equal(obs[0].Route.Path, asns(asX, asZ)) {
		t.Errorf("path ID 2: %v", obs[0].Route.Path)
	}

	// The plain announcement and an add-path ID 0 are one key.
	obs, _ = mustRun(t, selX, established(at(0)),
		upd(at(1), nil, nlri("10.0.0.0/24"), attrs4(asX)),
		ap(at(2), id(0), nil, nil))
	if len(obs) != 0 {
		t.Errorf("add-path ID 0 withdrawal left %v", prefixes(obs))
	}
}

// Within one UPDATE the same prefix of two SAFIs is two routes.
func TestSessionFamilies(t *testing.T) {
	v4m := bgp.Family{AFI: bgp.AFIIPv4, SAFI: bgp.SAFIMulticast}
	mc := slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(true, mrtgen.Seq(asX)),
		mrtgen.MPReach(v4m, []netip.Addr{nh4}, nlri("10.0.0.0/24"), false))
	// Repeated: the state is a map, so an order that did not compare the
	// family would come out either way.
	for range 20 {
		obs, _ := mustRun(t, selX, established(at(0)),
			upd(at(1), nil, nlri("10.0.0.0/24"), attrs4(asX)),
			upd(at(2), nil, nil, mc))
		if len(obs) != 2 || obs[0].Family != v4u || obs[1].Family != v4m {
			t.Fatalf("got %+v", obs)
		}
	}
	// A withdrawal of the multicast route leaves the unicast one.
	obs, _ := mustRun(t, selX, established(at(0)),
		upd(at(1), nil, nlri("10.0.0.0/24"), attrs4(asX)),
		upd(at(2), nil, nil, mc),
		upd(at(3), nil, nil, mrtgen.MPUnreach(v4m, nlri("10.0.0.0/24"), false)))
	if len(obs) != 1 || obs[0].Family != v4u {
		t.Fatalf("after the multicast withdrawal: %+v", obs)
	}
}

// setLen rewrites a BGP message's length field to its byte length.
func setLen(m []byte) []byte {
	binary.BigEndian.PutUint16(m[16:18], uint16(len(m)))
	return m
}

func TestSessionMalformed(t *testing.T) {
	a, b := nlri("10.0.0.0/24"), nlri("10.0.1.0/24")
	good := attrs4(asX, asY)
	v6route := slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(true, mrtgen.Seq(asX)),
		mrtgen.MPReach(v6u, []netip.Addr{nh6}, nlri("2001:db8:1::/48"), false))
	before := [][]byte{established(at(0)), upd(at(1), nil, slices.Concat(a, b), good), upd(at(1), nil, nil, v6route)}
	badComm := mrtgen.Raw(mrtgen.FlagOptional|mrtgen.FlagTransitive, 8, []byte{1, 2, 3, 4, 5})
	// truncated: a COMMUNITIES header claiming 16 bytes, with none after it.
	truncated := slices.Concat(attrs4(asX), []byte{mrtgen.FlagOptional | mrtgen.FlagTransitive, 8, 16})
	// prefix length 33 in the NLRI field.
	badNLRI := setLen(append(mrtgen.Update(nil, a, attrs4(asX), false), 33, 10, 0, 0, 0, 0))
	// An UPDATE between X and X: an internal session.
	ibgp := func(attrs []byte) []byte {
		st := mrt.SubMessageAS4
		return mrtgen.Header(mrt.TypeBGP4MP, st, at(2), mrtgen.BGP4MP(st, asX, asX, peerAddr, localAddr, mrtgen.Update(nil, a, attrs, false)))
	}
	all := []string{"10.0.0.0/24", "10.0.1.0/24", "2001:db8:1::/48"}
	tests := []struct {
		name              string
		last              []byte
		want              []string
		malformed, resets int
		down              bool
		comms             []uint32 // of 10.0.0.0/24 when present
	}{
		{"COMMUNITIES not a multiple of 4: treat-as-withdraw",
			upd(at(2), nil, a, slices.Concat(attrs4(asX), badComm)),
			[]string{"10.0.1.0/24", "2001:db8:1::/48"}, 1, 0, false, nil},
		{"NEXT_HOP of 3 bytes: treat-as-withdraw",
			upd(at(2), nil, a, slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(true, mrtgen.Seq(asX)), mrtgen.Raw(mrtgen.FlagTransitive, 3, []byte{1, 2, 3}))),
			[]string{"10.0.1.0/24", "2001:db8:1::/48"}, 1, 0, false, nil},
		{"malformed AS_PATH: treat-as-withdraw",
			upd(at(2), nil, a, slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.Raw(mrtgen.FlagTransitive, 2, []byte{2, 1, 0}), mrtgen.NextHop(nh4))),
			[]string{"10.0.1.0/24", "2001:db8:1::/48"}, 1, 0, false, nil},
		{"treat-as-withdraw still applies the withdrawals",
			upd(at(2), b, a, slices.Concat(attrs4(asX), mrtgen.Raw(mrtgen.FlagOptional|mrtgen.FlagTransitive, 8, []byte{1}))),
			[]string{"2001:db8:1::/48"}, 1, 0, false, nil},
		{"treat-as-withdraw over MP_REACH_NLRI (IPv6)",
			upd(at(2), nil, nil, slices.Concat(v6route, badComm)),
			[]string{"10.0.0.0/24", "10.0.1.0/24"}, 1, 0, false, nil},
		{"missing ORIGIN: treat-as-withdraw (RFC 7606 §3.d)",
			upd(at(2), nil, a, slices.Concat(mrtgen.ASPath(true, mrtgen.Seq(asX)), mrtgen.NextHop(nh4))),
			[]string{"10.0.1.0/24", "2001:db8:1::/48"}, 1, 0, false, nil},
		{"missing ORIGIN over MP_REACH_NLRI",
			upd(at(2), nil, nil, slices.Concat(mrtgen.ASPath(true, mrtgen.Seq(asX)), mrtgen.MPReach(v6u, []netip.Addr{nh6}, nlri("2001:db8:1::/48"), false))),
			[]string{"10.0.0.0/24", "10.0.1.0/24"}, 1, 0, false, nil},
		{"missing NEXT_HOP with IPv4 NLRI: treat-as-withdraw",
			upd(at(2), nil, a, slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(true, mrtgen.Seq(asX)))),
			[]string{"10.0.1.0/24", "2001:db8:1::/48"}, 1, 0, false, nil},
		{"NEXT_HOP 0.0.0.0: treat-as-withdraw",
			upd(at(2), nil, a, slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(true, mrtgen.Seq(asX)), mrtgen.NextHop(netip.IPv4Unspecified()))),
			[]string{"10.0.1.0/24", "2001:db8:1::/48"}, 1, 0, false, nil},
		{"NEXT_HOP multicast: treat-as-withdraw",
			upd(at(2), nil, a, slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(true, mrtgen.Seq(asX)), mrtgen.NextHop(netip.MustParseAddr("224.0.0.1")))),
			[]string{"10.0.1.0/24", "2001:db8:1::/48"}, 1, 0, false, nil},
		{"duplicate COMMUNITIES: the first wins, not malformed",
			upd(at(2), nil, a, slices.Concat(attrs4(asX), mrtgen.Communities(7), mrtgen.Communities(8))),
			all, 0, 0, false, []uint32{7}},
		{"malformed AGGREGATOR: attribute discard, not malformed",
			upd(at(2), nil, a, slices.Concat(attrs4(asX), mrtgen.Raw(mrtgen.FlagOptional|mrtgen.FlagTransitive, 7, []byte{1, 2, 3}))),
			all, 0, 0, false, nil},
		{"malformed LOCAL_PREF from an external peer: attribute discard",
			upd(at(2), nil, a, slices.Concat(attrs4(asX), mrtgen.Raw(mrtgen.FlagTransitive, 5, []byte{1}))),
			all, 0, 0, false, nil},
		{"malformed LOCAL_PREF on an internal session: treat-as-withdraw",
			ibgp(slices.Concat(attrs4(asX), mrtgen.Raw(mrtgen.FlagTransitive, 5, []byte{1}))),
			[]string{"10.0.1.0/24", "2001:db8:1::/48"}, 1, 0, false, nil},
		{"malformed AGGREGATOR on an internal session: still attribute discard",
			ibgp(slices.Concat(attrs4(asX), mrtgen.Raw(mrtgen.FlagOptional|mrtgen.FlagTransitive, 7, []byte{1, 2, 3}))),
			all, 0, 0, false, nil},
		{"attribute framing past the block: treat-as-withdraw (RFC 7606 §4)",
			upd(at(2), nil, a, truncated), []string{"10.0.1.0/24", "2001:db8:1::/48"}, 1, 0, false, nil},
		{"withdrawals only, with a malformed attribute: reset (RFC 7606 §5.2)",
			upd(at(2), b, nil, slices.Concat(mrtgen.Origin(bgp.OriginIGP), badComm)), nil, 0, 1, true, nil},
		{"withdrawals only, with a discarded malformed attribute: used",
			upd(at(2), b, nil, mrtgen.Raw(mrtgen.FlagOptional|mrtgen.FlagTransitive, 7, []byte{1, 2, 3})),
			[]string{"10.0.0.0/24", "2001:db8:1::/48"}, 0, 0, false, nil},
		{"NLRI that do not parse: reset",
			msg(at(2), mrt.SubMessageAS4, asX, peerAddr, localAddr, badNLRI), nil, 0, 1, true, nil},
		{"MP_REACH_NLRI next hop of 5 bytes: reset",
			upd(at(2), nil, nil, slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(true, mrtgen.Seq(asX)),
				mrtgen.Raw(mrtgen.FlagOptional, 14, slices.Concat([]byte{0, 2, 1, 5, 1, 2, 3, 4, 5, 0}, mrtgen.NLRIBytes(nlri("2001:db8::/32"), false))))),
			nil, 0, 1, true, nil},
		{"MP_UNREACH_NLRI too short: reset",
			upd(at(2), nil, nil, mrtgen.Raw(mrtgen.FlagOptional, 15, []byte{0, 2})), nil, 0, 1, true, nil},
		{"MP_REACH_NLRI framing past the block: reset",
			upd(at(2), nil, nil, slices.Concat(mrtgen.Origin(bgp.OriginIGP), []byte{mrtgen.FlagOptional, 14, 40, 0, 2})), nil, 0, 1, true, nil},
		{"a broken BGP header: reset",
			msg(at(2), mrt.SubMessageAS4, asX, peerAddr, localAddr, []byte{1, 2, 3}), nil, 0, 1, true, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			obs, info := mustRun(t, selX, append(slices.Clone(before), tc.last)...)
			if got := prefixes(obs); !slices.Equal(got, tc.want) {
				t.Errorf("prefixes = %v, want %v", got, tc.want)
			}
			if info.Malformed != tc.malformed || info.MalformedResets != tc.resets {
				t.Errorf("Malformed, MalformedResets = %d, %d, want %d, %d", info.Malformed, info.MalformedResets, tc.malformed, tc.resets)
			}
			if info.DownAtEnd != tc.down {
				t.Errorf("DownAtEnd = %v, want %v", info.DownAtEnd, tc.down)
			}
			if len(obs) > 0 && obs[0].Route.Prefix == a[0].Prefix && !slices.Equal(obs[0].Route.Communities, tc.comms) {
				t.Errorf("communities = %v, want %v", obs[0].Route.Communities, tc.comms)
			}
		})
	}
	// After a reset, X's next announcements form the state again, and the
	// session is no longer down.
	obs, info := mustRun(t, selX, append(slices.Clone(before),
		msg(at(2), mrt.SubMessageAS4, asX, peerAddr, localAddr, badNLRI), upd(at(3), nil, b, good))...)
	if got := prefixes(obs); !slices.Equal(got, []string{"10.0.1.0/24"}) || info.MidSession || info.DownAtEnd {
		t.Errorf("after a reset: %v, MidSession %v, DownAtEnd %v", got, info.MidSession, info.DownAtEnd)
	}
}

func TestClassify(t *testing.T) {
	d := func(sev bgp.Severity, code string, attr bgp.AttrCode) []bgp.Diagnostic {
		return []bgp.Diagnostic{{Severity: sev, Code: code, Attr: attr}}
	}
	both := func(x, y []bgp.Diagnostic) []bgp.Diagnostic { return slices.Concat(x, y) }
	ann := facts{reachable: true, otherAttrs: true} // an UPDATE announcing NLRI with attributes
	ibgp := facts{reachable: true, otherAttrs: true, ibgp: true}
	wdOnly := facts{otherAttrs: true} // withdrawals only, with attributes
	mpUnreachOnly := facts{}          // withdrawals only, MP_UNREACH_NLRI its only attribute
	W, E, I := bgp.SeverityWarning, bgp.SeverityError, bgp.SeverityInfo
	tests := []struct {
		name  string
		upd   []bgp.Diagnostic
		attrs []bgp.Diagnostic
		f     facts
		want  disposition
	}{
		{"none", nil, nil, ann, dispOK},
		{"trailing bytes after the message", d(W, "bgp/message-header", 0), nil, ann, dispOK},
		{"prefix bits cleared", d(I, "bgp/prefix-bits", 0), nil, ann, dispOK},
		{"MP prefix bits cleared", nil, d(I, "bgp/prefix-bits", bgp.AttrMPReach), ann, dispOK},
		{"AS4_PATH ignored", nil, d(I, "bgp/as4path-ignored", bgp.AttrAS4Path), ann, dispOK},
		{"duplicate", nil, d(W, "bgp/attr-duplicate", bgp.AttrCommunities), ann, dispOK},
		{"AS4_PATH malformed", nil, d(W, "bgp/attr-value", bgp.AttrAS4Path), ann, dispOK},
		{"AS4_AGGREGATOR", nil, d(W, "bgp/attr-length", bgp.AttrAS4Aggregator), ann, dispOK},
		{"AGGREGATOR", nil, d(W, "bgp/attr-length", bgp.AttrAggregator), ann, dispOK},
		{"ATOMIC_AGGREGATE", nil, d(W, "bgp/attr-length", bgp.AttrAtomicAggregate), ann, dispOK},
		{"LOCAL_PREF", nil, d(W, "bgp/attr-length", bgp.AttrLocalPref), ann, dispOK},
		{"ORIGINATOR_ID", nil, d(W, "bgp/attr-length", bgp.AttrOriginatorID), ann, dispOK},
		{"CLUSTER_LIST", nil, d(W, "bgp/attr-length", bgp.AttrClusterList), ann, dispOK},
		{"iBGP LOCAL_PREF", nil, d(W, "bgp/attr-length", bgp.AttrLocalPref), ibgp, dispWithdraw},
		{"iBGP ORIGINATOR_ID", nil, d(W, "bgp/attr-length", bgp.AttrOriginatorID), ibgp, dispWithdraw},
		{"iBGP CLUSTER_LIST", nil, d(W, "bgp/attr-length", bgp.AttrClusterList), ibgp, dispWithdraw},
		{"iBGP AGGREGATOR", nil, d(W, "bgp/attr-length", bgp.AttrAggregator), ibgp, dispOK},
		{"iBGP AS4_PATH", nil, d(W, "bgp/attr-value", bgp.AttrAS4Path), ibgp, dispOK},
		{"ORIGIN", nil, d(W, "bgp/attr-value", bgp.AttrOrigin), ann, dispWithdraw},
		{"AS_PATH", nil, d(W, "bgp/aspath-width", bgp.AttrASPath), ann, dispWithdraw},
		{"NEXT_HOP", nil, d(W, "bgp/attr-length", bgp.AttrNextHop), ann, dispWithdraw},
		{"MED", nil, d(W, "bgp/attr-length", bgp.AttrMED), ann, dispWithdraw},
		{"COMMUNITIES", nil, d(W, "bgp/attr-length", bgp.AttrCommunities), ann, dispWithdraw},
		{"EXTENDED COMMUNITIES", nil, d(W, "bgp/attr-length", bgp.AttrExtCommunities), ann, dispWithdraw},
		{"LARGE_COMMUNITY", nil, d(W, "bgp/attr-length", bgp.AttrLargeCommunity), ann, dispWithdraw},
		{"OTC", nil, d(W, "bgp/attr-length", bgp.AttrOnlyToCustomer), ann, dispWithdraw},
		{"missing ORIGIN", nil, nil, facts{reachable: true, otherAttrs: true, missingOrigin: true}, dispWithdraw},
		{"missing or invalid NEXT_HOP", nil, nil, facts{reachable: true, otherAttrs: true, badNextHop: true}, dispWithdraw},
		{"withdraw and discard: withdraw", nil, both(d(W, "bgp/attr-length", bgp.AttrAggregator), d(W, "bgp/attr-length", bgp.AttrMED)), ann, dispWithdraw},
		{"attribute framing: treat-as-withdraw (§4)", nil, d(E, "bgp/attr-truncated", bgp.AttrCommunities), ann, dispWithdraw},
		{"attribute framing, no code", nil, d(E, "bgp/attr-truncated", 0), ann, dispWithdraw},
		{"MP_REACH framing: reset", nil, d(E, "bgp/attr-truncated", bgp.AttrMPReach), ann, dispReset},
		{"MP_UNREACH framing: reset", nil, d(E, "bgp/attr-truncated", bgp.AttrMPUnreach), ann, dispReset},
		{"MP_REACH next hop", nil, d(W, "bgp/attr-value", bgp.AttrMPReach), ann, dispReset},
		{"MP_REACH duplicate", nil, d(W, "bgp/attr-duplicate", bgp.AttrMPReach), ann, dispReset},
		{"MP_UNREACH NLRI", nil, d(E, "bgp/nlri-length", bgp.AttrMPUnreach), ann, dispReset},
		{"withdraw and reset: reset", nil, both(d(W, "bgp/attr-length", bgp.AttrMED), d(E, "bgp/nlri-length", bgp.AttrMPReach)), ann, dispReset},
		{"update length", d(E, "bgp/update-length", 0), nil, ann, dispReset},
		{"NLRI length", d(E, "bgp/nlri-length", 0), nil, ann, dispReset},
		{"message cut short", d(E, "bgp/message-truncated", 0), nil, ann, dispReset},
		{"an unknown Warning not about an attribute", nil, d(W, "bgp/new-thing", 0), ann, dispWithdraw},
		{"an unknown Error", nil, d(E, "bgp/new-thing", bgp.AttrCommunities), ann, dispReset},
		{"§5.2: no NLRI, attributes, treat-as-withdraw: reset", nil, d(W, "bgp/attr-length", bgp.AttrCommunities), wdOnly, dispReset},
		{"§5.2: no NLRI, attribute framing: reset", nil, d(E, "bgp/attr-truncated", bgp.AttrCommunities), wdOnly, dispReset},
		{"§5.2: no NLRI, attribute discard only: used", nil, d(W, "bgp/attr-length", bgp.AttrAggregator), wdOnly, dispOK},
		{"§5.2: no NLRI, no error: used", nil, nil, wdOnly, dispOK},
		{"§5.2: only MP_UNREACH_NLRI, so not escalated", nil, d(W, "bgp/new-thing", 0), mpUnreachOnly, dispWithdraw},
	}
	for _, tc := range tests {
		if got := classify(tc.upd, tc.attrs, tc.f); got != tc.want {
			t.Errorf("%s: classify = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Review Focus 1.
func TestSessionNotFirstAS(t *testing.T) {
	a := nlri("10.0.0.0/24")
	tests := []struct {
		name  string
		attrs []byte
		kept  bool
	}{
		{"X alone is a normal route", attrs4(asX), true},
		{"X prepended", attrs4(asX, asX, asY), true},
		{"another AS first", attrs4(asY, asX), false},
		{"empty path", slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(true), mrtgen.NextHop(nh4)), false},
		{"no AS_PATH attribute", slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.NextHop(nh4)), false},
		{"first segment AS_SET holding X", slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(true, mrtgen.Set(asX), mrtgen.Seq(asY)), mrtgen.NextHop(nh4)), false},
		{"first segment confederation", slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(true, mrtgen.ConfedSeq(65001), mrtgen.Seq(asX)), mrtgen.NextHop(nh4)), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// An earlier route for the key, then this announcement replacing it.
			obs, info := mustRun(t, selX, established(at(0)),
				upd(at(1), nil, a, attrs4(asX, asZ)),
				upd(at(2), nil, a, tc.attrs))
			if tc.kept {
				if len(obs) != 1 || info.NotFirstAS != 0 || !obs[0].Evidence.Time.Equal(at(2)) {
					t.Errorf("obs %+v, NotFirstAS %d", obs, info.NotFirstAS)
				}
				return
			}
			if len(obs) != 0 || info.NotFirstAS != 1 {
				t.Errorf("kept %v (the earlier route must go too), NotFirstAS %d", prefixes(obs), info.NotFirstAS)
			}
		})
	}
	// Counted per route: one UPDATE with three prefixes counts three.
	_, info := mustRun(t, selX, established(at(0)), upd(at(1), nil, nlri("10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"), attrs4(asY)))
	if info.NotFirstAS != 3 {
		t.Errorf("NotFirstAS = %d, want 3", info.NotFirstAS)
	}
}

func TestSessionSelects(t *testing.T) {
	other := netip.MustParseAddr("192.0.2.9")
	keepalive := append(bytes.Repeat([]byte{0xFF}, 16), 0, 19, 4)
	recs := [][]byte{
		// An earlier record of another peer: not the first selected one.
		msg(at(0), mrt.SubMessageAS4, asY, other, localAddr, mrtgen.Update(nil, nlri("10.1.0.0/24"), attrs4(asY), false)),
		established(at(0)),
		upd(at(1), nil, nlri("10.0.0.0/24"), attrs4(asX)),
		// What L sent X: ignored.
		msg(at(2), mrt.SubMessageAS4Local, asX, peerAddr, localAddr, mrtgen.Update(nil, nlri("10.2.0.0/24"), attrs4(asL), false)),
		msg(at(2), mrt.SubMessageAS4Local, asX, peerAddr, localAddr, mrtgen.Update(nlri("10.0.0.0/24"), nil, nil, false)),
		// Another peer's state change does not clear X's state.
		mrtgen.Header(mrt.TypeBGP4MP, mrt.SubStateChangeAS4, at(3), mrtgen.StateChange(mrt.SubStateChangeAS4, asY, asL, other, localAddr, mrt.StateEstablished, mrt.StateIdle)),
		// X on another address (a second session).
		msg(at(4), mrt.SubMessageAS4, asX, other, localAddr, mrtgen.Update(nil, nlri("10.3.0.0/24"), attrs4(asX), false)),
		// A KEEPALIVE from X, and a 2-byte-AS UPDATE from X.
		msg(at(5), mrt.SubMessageAS4, asX, peerAddr, localAddr, keepalive),
		msg(at(6), mrt.SubMessage, asX, peerAddr, localAddr, mrtgen.Update(nil, nlri("10.4.0.0/24"), slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(false, mrtgen.Seq(asX)), mrtgen.NextHop(nh4)), false)),
	}
	obs, info := mustRun(t, selX, recs...)
	if got, want := prefixes(obs), []string{"10.0.0.0/24", "10.3.0.0/24", "10.4.0.0/24"}; !slices.Equal(got, want) {
		t.Errorf("no PeerAddr: prefixes = %v, want %v", got, want)
	}
	if info.LocalAS != types.ASN(asL) || info.LocalAddr != localAddr || info.PeerAddr != peerAddr {
		t.Errorf("info = %+v", info)
	}
	// The second session's start is not in the capture.
	if !info.MidSession {
		t.Errorf("MidSession false with a second session seen only mid-way")
	}
	obs, info = mustRun(t, SessionSel{Peer: types.ASN(asX), PeerAddr: peerAddr}, recs...)
	if got, want := prefixes(obs), []string{"10.0.0.0/24", "10.4.0.0/24"}; !slices.Equal(got, want) || info.MidSession {
		t.Errorf("PeerAddr %v: prefixes = %v, want %v; MidSession %v", peerAddr, got, want, info.MidSession)
	}
	obs, info = mustRun(t, SessionSel{Peer: types.ASN(asX), PeerAddr: other}, recs...)
	if got := prefixes(obs); !slices.Equal(got, []string{"10.3.0.0/24"}) || info.PeerAddr != other || !info.MidSession {
		t.Errorf("PeerAddr %v: prefixes = %v, info %+v", other, got, info)
	}
	obs, info = mustRun(t, SessionSel{Peer: 64999}, recs...)
	if len(obs) != 0 || info.LocalAS != 0 || info.PeerAddr.IsValid() {
		t.Errorf("an absent peer: %v, %+v", prefixes(obs), info)
	}
}

// Review Focus 5.
func TestSessionAt(t *testing.T) {
	recs := [][]byte{
		established(at(10)),
		upd(at(11), nil, nlri("10.0.0.0/24"), attrs4(asX)),
		upd(at(12), nil, nlri("10.0.1.0/24"), attrs4(asX)),
		upd(at(13), nlri("10.0.0.0/24"), nil, nil),
	}
	tests := []struct {
		name  string
		at    time.Time
		want  []string
		empty bool // NoRecordsBeforeAt
	}{
		{"zero: end of capture", time.Time{}, []string{"10.0.1.0/24"}, false},
		{"before the first record", at(9), nil, true},
		{"exactly at the Established record", at(10), nil, false},
		{"exactly at a record: included", at(12), []string{"10.0.0.0/24", "10.0.1.0/24"}, false},
		{"between records", at(12).Add(500 * time.Millisecond), []string{"10.0.0.0/24", "10.0.1.0/24"}, false},
		{"after the last record", at(100), []string{"10.0.1.0/24"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			obs, info := mustRun(t, SessionSel{Peer: types.ASN(asX), At: tc.at}, recs...)
			if got := prefixes(obs); !slices.Equal(got, tc.want) {
				t.Errorf("prefixes = %v, want %v", got, tc.want)
			}
			if info.NoRecordsBeforeAt != tc.empty {
				t.Errorf("NoRecordsBeforeAt = %v, want %v", info.NoRecordsBeforeAt, tc.empty)
			}
			if info.MidSession {
				t.Errorf("MidSession")
			}
		})
	}
	// A down transition after At does not count.
	obs, info := mustRun(t, SessionSel{Peer: types.ASN(asX), At: at(12)}, append(recs, state(at(14), mrt.StateEstablished, mrt.StateIdle))...)
	if len(obs) != 2 || info.DownAtEnd {
		t.Errorf("down after At: %v, DownAtEnd %v", prefixes(obs), info.DownAtEnd)
	}
}

// tableDump is a legacy TABLE_DUMP (IPv4) record.
func tableDump(ts time.Time, p netip.Prefix, peer netip.Addr, peerAS bgp.ASN, attrs []byte) []byte {
	b := []byte{0, 0, 0, 1}
	a4 := p.Addr().As4()
	b = append(b, a4[:]...)
	b = append(b, byte(p.Bits()), 1)
	b = binary.BigEndian.AppendUint32(b, uint32(ts.Unix()))
	pa := peer.As4()
	b = append(b, pa[:]...)
	b = binary.BigEndian.AppendUint16(b, uint16(peerAS))
	b = binary.BigEndian.AppendUint16(b, uint16(len(attrs)))
	b = append(b, attrs...)
	return mrtgen.Header(mrt.TypeTableDump, mrt.SubAFIIPv4, ts, b)
}

func TestSessionRIB(t *testing.T) {
	other := netip.MustParseAddr("192.0.2.9")
	pit := mrtgen.Header(mrt.TypeTableDumpV2, mrt.SubPeerIndexTable, at(0), mrtgen.PeerIndexTable(
		netip.MustParseAddr("192.0.2.254"), "", []mrt.Peer{
			{BGPID: other, Addr: other, AS: asY},
			{BGPID: peerAddr, Addr: peerAddr, AS: asX},
			{BGPID: netip.MustParseAddr("192.0.2.3"), Addr: peer6, AS: asX},
		}))
	rib4 := mrtgen.Header(mrt.TypeTableDumpV2, mrt.SubRIBIPv4Unicast, at(0), mrtgen.RIB(mrt.SubRIBIPv4Unicast, 0, pfx("10.0.0.0/24"), []mrtgen.Entry{
		{PeerIndex: 0, Originated: at(-50), Attrs: attrs4(asY, asX)},
		{PeerIndex: 1, Originated: at(-40), Attrs: attrs4(asX, asZ)},
	}))
	rib4b := mrtgen.Header(mrt.TypeTableDumpV2, mrt.SubRIBIPv4Unicast, at(0), mrtgen.RIB(mrt.SubRIBIPv4Unicast, 1, pfx("10.0.1.0/24"), []mrtgen.Entry{
		{PeerIndex: 1, Originated: at(-30), Attrs: attrs4(asX)},
		{PeerIndex: 0, Originated: at(-30), Attrs: attrs4(asY)},
	}))
	rib4c := mrtgen.Header(mrt.TypeTableDumpV2, mrt.SubRIBIPv4Unicast, at(0), mrtgen.RIB(mrt.SubRIBIPv4Unicast, 2, pfx("10.0.2.0/24"), []mrtgen.Entry{
		{PeerIndex: 1, Originated: at(-30), Attrs: attrs4(asY, asX)}, // not X first
		{PeerIndex: 1, Originated: at(-30), Attrs: slices.Concat(attrs4(asX), mrtgen.Raw(mrtgen.FlagOptional|mrtgen.FlagTransitive, 8, []byte{1}))},
	}))
	rib6 := mrtgen.Header(mrt.TypeTableDumpV2, mrt.SubRIBIPv6UnicastAddPath, at(0), mrtgen.RIB(mrt.SubRIBIPv6UnicastAddPath, 3, pfx("2001:db8:1::/48"), []mrtgen.Entry{
		{PeerIndex: 2, Originated: at(-20), PathID: 4, Attrs: slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(true, mrtgen.Seq(asX)), mrtgen.MPReachAbbrev(nh6))},
		{PeerIndex: 9, Originated: at(-20), Attrs: attrs4(asX)}, // a peer index not in the table
	}))
	dump := [][]byte{pit, rib4, rib4b, rib4c, rib6}

	obs, _, err := run(t, selX, dump...)
	if !errors.Is(err, ErrRIBNotPrePolicy) || len(obs) != 0 {
		t.Fatalf("without PrePolicyRIB: %v, %v", prefixes(obs), err)
	}
	// Also after UPDATEs, and for a legacy TABLE_DUMP.
	_, _, err = run(t, selX, established(at(0)), upd(at(1), nil, nlri("10.9.0.0/24"), attrs4(asX)),
		tableDump(at(2), pfx("10.0.0.0/24"), peerAddr, asX, attrs4(asX)))
	if !errors.Is(err, ErrRIBNotPrePolicy) {
		t.Fatalf("TABLE_DUMP without PrePolicyRIB: %v", err)
	}

	pre := SessionSel{Peer: types.ASN(asX), PrePolicyRIB: true}
	obs, info := mustRun(t, pre, dump...)
	if got, want := prefixes(obs), []string{"10.0.0.0/24", "10.0.1.0/24", "2001:db8:1::/48"}; !slices.Equal(got, want) {
		t.Fatalf("PrePolicyRIB: prefixes = %v, want %v", got, want)
	}
	if info.NotFirstAS != 1 || info.Malformed != 1 || info.Skipped != 1 || info.MidSession {
		t.Errorf("info = %+v", info)
	}
	if o := obs[0]; !slices.Equal(o.Route.Path, asns(asX, asZ)) || !o.Evidence.Time.Equal(at(-40)) || !o.Route.CommsKnown {
		t.Errorf("RIB route = %+v", o)
	}
	if o := obs[2]; o.Family != v6u || !slices.Equal(o.Route.Path, asns(asX)) {
		t.Errorf("v6 RIB route = %+v", o)
	}

	// A bview plus updates: UPDATEs apply on top of the RIB.
	obs, info = mustRun(t, pre, append(slices.Clone(dump),
		upd(at(1), nlri("10.0.0.0/24"), nlri("10.0.5.0/24"), attrs4(asX)))...)
	if got, want := prefixes(obs), []string{"10.0.1.0/24", "10.0.5.0/24", "2001:db8:1::/48"}; !slices.Equal(got, want) || info.MidSession {
		t.Errorf("RIB + updates: prefixes = %v, want %v; MidSession %v", got, want, info.MidSession)
	}

	// PeerAddr selects the v4 peer's entries only.
	obs, _ = mustRun(t, SessionSel{Peer: types.ASN(asX), PeerAddr: peerAddr, PrePolicyRIB: true}, dump...)
	if got, want := prefixes(obs), []string{"10.0.0.0/24", "10.0.1.0/24"}; !slices.Equal(got, want) {
		t.Errorf("PeerAddr: prefixes = %v, want %v", got, want)
	}

	// A legacy TABLE_DUMP entry.
	obs, _ = mustRun(t, pre, tableDump(at(2), pfx("10.0.0.0/24"), peerAddr, asX, slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(false, mrtgen.Seq(asX, asY)))))
	if len(obs) != 1 || !slices.Equal(obs[0].Route.Path, asns(asX, asY)) {
		t.Errorf("TABLE_DUMP: %+v", obs)
	}
}

func TestSessionRecordErrors(t *testing.T) {
	// A BGP4MP record with AFI 3: mrt yields a *RecordError and goes on.
	bad := msg(at(1), mrt.SubMessageAS4, asX, peerAddr, localAddr, nil)
	bad[12+8+2+1] = 3 // the AFI's low byte: after the header, the two ASNs and the interface index
	obs, info, err := run(t, selX, established(at(0)), bad, upd(at(2), nil, nlri("10.0.0.0/24"), attrs4(asX)))
	if err != nil || info.Skipped != 1 || len(obs) != 1 {
		t.Errorf("a malformed record: %v, %+v, %v", prefixes(obs), info, err)
	}
	// A stream cut inside a record: the error, and no observations.
	rec := upd(at(2), nil, nlri("10.0.0.0/24"), attrs4(asX))
	obs, _, err = run(t, selX, established(at(0)), rec, rec[:len(rec)-3])
	if !errors.Is(err, mrt.ErrTruncated) || len(obs) != 0 {
		t.Errorf("a truncated stream: %v, %v", prefixes(obs), err)
	}
}

// The sequence stops when the consumer stops.
func TestSessionStopsEarly(t *testing.T) {
	seq, _ := Session(mrt.Records(bytes.NewReader(slices.Concat(established(at(0)),
		upd(at(1), nil, nlri("10.0.0.0/24", "10.0.1.0/24"), attrs4(asX))))), selX)
	n := 0
	for range seq {
		n++
		break
	}
	if n != 1 {
		t.Errorf("n = %d", n)
	}
}

// Ruling R10 (3): two sessions holding one key are two Adj-RIB-Outs, two
// observations, told apart by Evidence.PeerAddr, ordered by peer address.
func TestSessionSameKeyTwoSessions(t *testing.T) {
	second := netip.MustParseAddr("192.0.2.5")
	upd2 := func(ts time.Time, attrs []byte) []byte {
		return msg(ts, mrt.SubMessageAS4, asX, second, localAddr, mrtgen.Update(nil, nlri("10.0.0.0/24"), attrs, false))
	}
	st := mrt.SubStateChangeAS4
	est2 := mrtgen.Header(mrt.TypeBGP4MP, st, at(0), mrtgen.StateChange(st, asX, asL, second, localAddr, mrt.StateOpenConfirm, mrt.StateEstablished))
	for _, tc := range []struct {
		name  string
		attrs []byte
		path  []types.ASN
	}{
		{"identical routes", attrs4(asX, asY), asns(asX, asY)},
		{"different routes", attrs4(asX, asZ), asns(asX, asZ)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The second session's records come first: the order is by address, not arrival.
			obs, info := mustRun(t, selX, est2, established(at(0)), upd2(at(1), tc.attrs),
				upd(at(2), nil, nlri("10.0.0.0/24"), attrs4(asX, asY)))
			if len(obs) != 2 || info.MidSession {
				t.Fatalf("got %+v, MidSession %v", obs, info.MidSession)
			}
			if obs[0].Evidence.PeerAddr != peerAddr || obs[1].Evidence.PeerAddr != second {
				t.Errorf("peer addresses %v, %v; want %v, %v", obs[0].Evidence.PeerAddr, obs[1].Evidence.PeerAddr, peerAddr, second)
			}
			if !slices.Equal(obs[0].Route.Path, asns(asX, asY)) || !slices.Equal(obs[1].Route.Path, tc.path) {
				t.Errorf("paths %v, %v", obs[0].Route.Path, obs[1].Route.Path)
			}
		})
	}
}

// Ruling R10 (5): a RIB dump is a baseline. UPDATEs before it are superseded
// (also for a session the dump names with no entries), and MidSession is cleared.
func TestSessionRIBBaseline(t *testing.T) {
	second := netip.MustParseAddr("192.0.2.5")
	pit := mrtgen.Header(mrt.TypeTableDumpV2, mrt.SubPeerIndexTable, at(10), mrtgen.PeerIndexTable(
		netip.MustParseAddr("192.0.2.254"), "", []mrt.Peer{
			{BGPID: peerAddr, Addr: peerAddr, AS: asX},
			{BGPID: second, Addr: second, AS: asX},
		}))
	rib := mrtgen.Header(mrt.TypeTableDumpV2, mrt.SubRIBIPv4Unicast, at(10), mrtgen.RIB(mrt.SubRIBIPv4Unicast, 0, pfx("10.0.1.0/24"),
		[]mrtgen.Entry{{PeerIndex: 0, Originated: at(5), Attrs: attrs4(asX)}}))
	early := [][]byte{
		upd(at(1), nil, nlri("10.0.0.0/24", "10.0.1.0/24"), attrs4(asX, asY)), // mid-session
		msg(at(2), mrt.SubMessageAS4, asX, second, localAddr, mrtgen.Update(nil, nlri("10.0.9.0/24"), attrs4(asX), false)),
	}
	pre := SessionSel{Peer: types.ASN(asX), PrePolicyRIB: true}
	obs, info := mustRun(t, pre, append(slices.Clone(early), pit, rib)...)
	if got := prefixes(obs); !slices.Equal(got, []string{"10.0.1.0/24"}) || info.MidSession {
		t.Errorf("UPDATEs then a bview: %v, MidSession %v", got, info.MidSession)
	}
	if len(obs) == 1 && !slices.Equal(obs[0].Route.Path, asns(asX)) {
		t.Errorf("the RIB's route did not replace the UPDATE's: %v", obs[0].Route.Path)
	}
	// Without the bview the same UPDATEs are mid-session.
	_, info = mustRun(t, pre, early...)
	if !info.MidSession {
		t.Errorf("MidSession false before the bview")
	}
	// A bview after At does not apply.
	obs, _ = mustRun(t, SessionSel{Peer: types.ASN(asX), PrePolicyRIB: true, At: at(5)}, append(slices.Clone(early), pit, rib)...)
	if got := prefixes(obs); !slices.Equal(got, []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.9.0/24"}) {
		t.Errorf("bview after At: %v", got)
	}
	// Legacy TABLE_DUMP: a run of records is one baseline (both entries stay).
	obs, info = mustRun(t, pre, append(slices.Clone(early),
		tableDump(at(10), pfx("10.0.3.0/24"), peerAddr, asX, slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(false, mrtgen.Seq(asX)))),
		tableDump(at(10), pfx("10.0.4.0/24"), peerAddr, asX, slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(false, mrtgen.Seq(asX)))))...)
	// The second session is not named by a TABLE_DUMP, so its UPDATE stays.
	if got := prefixes(obs); !slices.Equal(got, []string{"10.0.3.0/24", "10.0.4.0/24", "10.0.9.0/24"}) {
		t.Errorf("TABLE_DUMP baseline: %v", got)
	}
}

// ribGeneric is a TABLE_DUMP_V2 RIB_GENERIC_ADDPATH record for one IPv4
// unicast prefix with path identifier id; its entries carry none (RFC 8050 §4.2).
func ribGeneric(ts time.Time, p netip.Prefix, id uint32, entries []mrtgen.Entry) []byte {
	b := binary.BigEndian.AppendUint32(nil, 7)
	b = binary.BigEndian.AppendUint16(b, uint16(bgp.AFIIPv4))
	b = append(b, byte(bgp.SAFIUnicast))
	b = append(b, mrtgen.PrefixBytes(p, id, true)...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(entries)))
	for _, e := range entries {
		b = binary.BigEndian.AppendUint16(b, e.PeerIndex)
		b = binary.BigEndian.AppendUint32(b, uint32(e.Originated.Unix()))
		b = binary.BigEndian.AppendUint16(b, uint16(len(e.Attrs)))
		b = append(b, e.Attrs...)
	}
	return mrtgen.Header(mrt.TypeTableDumpV2, mrt.SubRIBGenericAddPath, ts, b)
}

// Ruling R10 (8): add-path RIB subtypes take the path ID from each entry;
// RIB_GENERIC_ADDPATH from the record's NLRI.
func TestSessionRIBAddPath(t *testing.T) {
	pit := mrtgen.Header(mrt.TypeTableDumpV2, mrt.SubPeerIndexTable, at(0), mrtgen.PeerIndexTable(
		netip.MustParseAddr("192.0.2.254"), "", []mrt.Peer{{BGPID: peerAddr, Addr: peerAddr, AS: asX}}))
	st := mrt.SubRIBIPv4UnicastAddPath
	rib := mrtgen.Header(mrt.TypeTableDumpV2, st, at(0), mrtgen.RIB(st, 0, pfx("10.0.0.0/24"), []mrtgen.Entry{
		{PeerIndex: 0, Originated: at(-1), PathID: 5, Attrs: attrs4(asX, asY)},
		{PeerIndex: 0, Originated: at(-1), PathID: 6, Attrs: attrs4(asX, asZ)},
	}))
	gen := ribGeneric(at(0), pfx("10.0.1.0/24"), 9, []mrtgen.Entry{{PeerIndex: 0, Originated: at(-1), Attrs: attrs4(asX)}})
	pre := SessionSel{Peer: types.ASN(asX), PrePolicyRIB: true}
	ap := func(ts time.Time, withdrawn []bgp.NLRI) []byte {
		return msg(ts, mrt.SubMessageAS4AddPath, asX, peerAddr, localAddr, mrtgen.Update(withdrawn, nil, nil, true))
	}
	obs, _ := mustRun(t, pre, pit, rib, gen)
	if got := prefixes(obs); !slices.Equal(got, []string{"10.0.0.0/24", "10.0.0.0/24", "10.0.1.0/24"}) {
		t.Fatalf("prefixes = %v", got)
	}
	// The IDs are the keys: an add-path withdrawal of ID 5 and of ID 9 leaves ID 6 only.
	obs, _ = mustRun(t, pre, pit, rib, gen, ap(at(1), []bgp.NLRI{
		{Prefix: pfx("10.0.0.0/24"), PathID: 5, HasPathID: true},
		{Prefix: pfx("10.0.1.0/24"), PathID: 9, HasPathID: true},
	}))
	if len(obs) != 1 || !slices.Equal(obs[0].Route.Path, asns(asX, asZ)) {
		t.Fatalf("after withdrawing IDs 5 and 9: %+v", obs)
	}
	// Withdrawing ID 0 removes nothing.
	obs, _ = mustRun(t, pre, pit, rib, gen, ap(at(1), []bgp.NLRI{
		{Prefix: pfx("10.0.0.0/24"), HasPathID: true}, {Prefix: pfx("10.0.1.0/24"), HasPathID: true}}))
	if len(obs) != 3 {
		t.Fatalf("after withdrawing ID 0: %v", prefixes(obs))
	}
}
