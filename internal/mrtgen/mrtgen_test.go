package mrtgen_test

import (
	"bytes"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/rkolesnichenko/mrt"
	"github.com/rkolesnichenko/mrt/bgp"
	"github.com/rkolesnichenko/routecheck/internal/mrtgen"
)

var (
	t0    = time.Unix(1700000000, 0).UTC()
	a4    = netip.MustParseAddr("192.0.2.10")
	a6    = netip.MustParseAddr("2001:db8::11")
	ll    = netip.MustParseAddr("fe80::11")
	local = netip.MustParseAddr("192.0.2.1")
)

func records(t *testing.T, b []byte) []mrt.Record {
	t.Helper()
	var out []mrt.Record
	for r, err := range mrt.Records(bytes.NewReader(b)) {
		if err != nil {
			t.Fatalf("record error: %v", err)
		}
		out = append(out, r)
	}
	return out
}

func routes(t *testing.T, b []byte) []mrt.Route {
	t.Helper()
	var out []mrt.Route
	for rt, err := range mrt.Routes(mrt.Records(bytes.NewReader(b))) {
		if err != nil {
			t.Fatalf("route error: %v", err)
		}
		out = append(out, rt)
	}
	return out
}

// TestGenDecodes: every kept builder's output decodes, through mrt.Records,
// mrt.Routes and bgp.ParseUpdate, to the values it was given.
func TestGenDecodes(t *testing.T) {
	peers := []mrt.Peer{
		{BGPID: a4, Addr: a4, AS: 64500},
		{BGPID: netip.MustParseAddr("192.0.2.11"), Addr: a6, AS: 4200000001},
	}
	attrs := slices.Concat(mrtgen.Origin(bgp.OriginEGP),
		mrtgen.ASPath(true, mrtgen.Seq(64500, 64501), mrtgen.Set(64510, 64511), mrtgen.ConfedSeq(65001)),
		mrtgen.NextHop(a4), mrtgen.Communities(bgp.Community(64500<<16|100), bgp.Community(64500<<16|200)))
	v6attrs := slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.MPReachAbbrev(a6, ll))
	stream := bytes.Join([][]byte{
		mrtgen.Header(mrt.TypeTableDumpV2, mrt.SubPeerIndexTable, t0, mrtgen.PeerIndexTable(local, "v", peers)),
		mrtgen.Header(mrt.TypeTableDumpV2, mrt.SubRIBIPv4Unicast, t0, mrtgen.RIB(mrt.SubRIBIPv4Unicast, 5,
			netip.MustParsePrefix("198.51.100.0/24"), []mrtgen.Entry{{PeerIndex: 0, Originated: t0, PathID: 99, Attrs: attrs}})),
		mrtgen.Header(mrt.TypeTableDumpV2, mrt.SubRIBIPv6UnicastAddPath, t0, mrtgen.RIB(mrt.SubRIBIPv6UnicastAddPath, 6,
			netip.MustParsePrefix("2001:db8::/32"), []mrtgen.Entry{
				{PeerIndex: 1, Originated: t0, PathID: 3, Attrs: v6attrs},
				{PeerIndex: 1, Originated: t0, PathID: 4, Attrs: v6attrs}})),
	}, nil)
	recs := records(t, stream)
	if len(recs) != 3 {
		t.Fatalf("%d records", len(recs))
	}
	tab := recs[0].(mrt.PeerIndexTable)
	if tab.CollectorID != local || tab.ViewName != "v" || len(tab.Peers) != 2 || tab.Peers[0] != peers[0] || tab.Peers[1] != peers[1] {
		t.Errorf("table = %+v", tab)
	}
	r4 := recs[1].(mrt.RIB)
	if r4.Sequence != 5 || r4.Prefix.String() != "198.51.100.0/24" || r4.EntryCount() != 1 || r4.AddPath {
		t.Errorf("rib4 = %+v", r4)
	}
	for e, err := range r4.Entries() {
		if err != nil || e.PeerIndex != 0 || !e.Originated.Equal(t0) || e.PathID != 0 || !bytes.Equal(e.Attrs.Raw(), attrs) {
			t.Errorf("entry = %+v, %v", e, err)
		}
	}
	r6 := recs[2].(mrt.RIB)
	var ids []uint32
	for e, err := range r6.Entries() {
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, e.PathID)
	}
	if !r6.AddPath || !slices.Equal(ids, []uint32{3, 4}) {
		t.Errorf("rib6 add-path = %v ids %v", r6.AddPath, ids)
	}

	got := routes(t, stream)
	if len(got) != 3 {
		t.Fatalf("%d routes", len(got))
	}
	p := got[0].Path
	if got[0].Peer != peers[0] || p.ReceivedASPath.String() != "64500 64501 {64510,64511} (65001)" ||
		p.NextHop != a4 || p.Origin != bgp.OriginEGP ||
		!slices.Equal(p.Communities, []bgp.Community{64500<<16 | 100, 64500<<16 | 200}) {
		t.Errorf("route 0 = %+v (path %q)", got[0], p.ReceivedASPath.String())
	}
	if segs := p.ReceivedASPath.Segments; len(segs) != 3 || segs[0].Type != bgp.ASSequence ||
		segs[1].Type != bgp.ASSet || segs[2].Type != bgp.ASConfedSequence {
		t.Errorf("segments = %+v", segs)
	}
	mp := got[1].Path.MPReach
	if got[1].Peer != peers[1] || got[1].PathID != 3 || !got[1].HasPathID || mp == nil || !mp.Abbreviated || mp.NextHop != a6 || mp.LinkLocal != ll {
		t.Errorf("route 1 = %+v mp %+v", got[1], mp)
	}
}

func TestGenBGP4MP(t *testing.T) {
	attrs := slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(false, mrtgen.Seq(64500)), mrtgen.NextHop(a4))
	wd := []bgp.NLRI{{Prefix: netip.MustParsePrefix("10.0.0.0/8"), PathID: 9, HasPathID: true}}
	ann := []bgp.NLRI{{Prefix: netip.MustParsePrefix("203.0.113.0/24"), PathID: 1, HasPathID: true}}
	msg := mrtgen.Update(wd, ann, attrs, true)
	et := t0.Add(654321 * time.Microsecond)
	stream := bytes.Join([][]byte{
		mrtgen.Header(mrt.TypeBGP4MP, mrt.SubMessageAddPath, t0, mrtgen.BGP4MP(mrt.SubMessageAddPath, 64500, 64496, a4, local, msg)),
		mrtgen.Header(mrt.TypeBGP4MPET, mrt.SubMessageAS4AddPath, et, mrtgen.BGP4MP(mrt.SubMessageAS4AddPath, 4200000001, 64496, a6, netip.MustParseAddr("2001:db8::1"), msg)),
		mrtgen.Header(mrt.TypeBGP4MP, mrt.SubStateChangeAS4, t0, mrtgen.StateChange(mrt.SubStateChangeAS4, 4200000001, 64496, a4, local, mrt.StateActive, mrt.StateEstablished)),
		mrtgen.Header(mrt.TypeBGP4MPET, mrt.SubStateChange, et, mrtgen.StateChange(mrt.SubStateChange, 64500, 64496, a4, local, mrt.StateIdle, mrt.StateConnect)),
	}, nil)
	recs := records(t, stream)
	if len(recs) != 4 {
		t.Fatalf("%d records", len(recs))
	}
	m := recs[0].(mrt.BGP4MPMessage)
	if m.AS4 || !m.AddPath || m.PeerAS != 64500 || m.LocalAS != 64496 || m.PeerAddr != a4 || m.LocalAddr != local || !bytes.Equal(m.Message, msg) {
		t.Errorf("m = %+v", m)
	}
	u, diags := bgp.ParseUpdate(m.Message, m.Context())
	if len(diags) != 0 || len(u.Withdrawn) != 1 || u.Withdrawn[0] != wd[0] || len(u.Announced) != 1 || u.Announced[0] != ann[0] || !bytes.Equal(u.Attrs.Raw(), attrs) {
		t.Errorf("update = %+v %v", u, diags)
	}
	e := recs[1].(mrt.BGP4MPMessage)
	if !e.AS4 || e.PeerAS != 4200000001 || e.PeerAddr != a6 || !e.Header().Time.Equal(et) || e.Header().Type != mrt.TypeBGP4MPET {
		t.Errorf("e = %+v", e)
	}
	s := recs[2].(mrt.BGP4MPStateChange)
	if !s.AS4 || s.PeerAS != 4200000001 || s.Old != mrt.StateActive || s.New != mrt.StateEstablished {
		t.Errorf("s = %+v", s)
	}
	s2 := recs[3].(mrt.BGP4MPStateChange)
	if s2.AS4 || s2.PeerAS != 64500 || s2.Old != mrt.StateIdle || !s2.Header().Time.Equal(et) {
		t.Errorf("s2 = %+v", s2)
	}

	var kinds []mrt.Kind
	for _, rt := range routes(t, stream[:len(recs[0].Raw())]) {
		kinds = append(kinds, rt.Kind)
		if rt.PathID == 0 || !rt.HasPathID {
			t.Errorf("route %+v lacks its path ID", rt)
		}
	}
	if !slices.Equal(kinds, []mrt.Kind{mrt.KindWithdraw, mrt.KindAnnounce}) {
		t.Errorf("kinds = %v", kinds)
	}
}

// TestGenMPAndAS4: MP_REACH, MP_UNREACH, AS4_PATH and a long attribute (the
// extended-length flag) decode to what was passed in.
func TestGenMPAndAS4(t *testing.T) {
	fam6 := bgp.Family{AFI: 2, SAFI: 1}
	ann := []bgp.NLRI{{Prefix: netip.MustParsePrefix("2001:db8:1::/48"), PathID: 7, HasPathID: true}}
	wd := []bgp.NLRI{
		{Prefix: netip.MustParsePrefix("2001:db8:2::/48"), PathID: 8, HasPathID: true},
		{Prefix: netip.MustParsePrefix("2001:db8:3::/64"), PathID: 9, HasPathID: true},
	}
	attrs := slices.Concat(mrtgen.Origin(bgp.OriginIGP),
		mrtgen.ASPath(false, mrtgen.Seq(23456, 64500)), mrtgen.AS4PathAttr(mrtgen.Seq(4200000001, 64500)),
		mrtgen.MPReach(fam6, []netip.Addr{a6, ll}, ann, true),
		mrtgen.MPUnreach(fam6, wd, true))
	msg := mrtgen.Update(nil, nil, attrs, true)
	stream := mrtgen.Header(mrt.TypeBGP4MP, mrt.SubMessageAddPath, t0,
		mrtgen.BGP4MP(mrt.SubMessageAddPath, 64500, 64496, a6, netip.MustParseAddr("2001:db8::1"), msg))
	got := routes(t, stream)
	if len(got) != 3 {
		t.Fatalf("%d routes: %+v", len(got), got)
	}
	for i, w := range wd {
		r := got[i]
		if r.Kind != mrt.KindWithdraw || r.Family != fam6 || r.Prefix != w.Prefix || r.PathID != w.PathID {
			t.Errorf("withdraw %d = %+v", i, r)
		}
	}
	r := got[2]
	if r.Kind != mrt.KindAnnounce || r.Prefix != ann[0].Prefix || r.PathID != 7 {
		t.Errorf("announce = %+v", r)
	}
	mp := r.Path.MPReach
	if mp == nil || mp.NextHop != a6 || mp.LinkLocal != ll || mp.Abbreviated {
		t.Errorf("mp = %+v", mp)
	}
	if r.Path.AS4Path.String() != "4200000001 64500" || r.Path.ReceivedASPath.String() != "23456 64500" || r.Path.ASPath.String() != "4200000001 64500" {
		t.Errorf("as paths = %q %q %q", r.Path.ReceivedASPath, r.Path.AS4Path, r.Path.ASPath)
	}

	// A value over 255 bytes gets the extended-length flag and still frames.
	long := mrtgen.Raw(mrtgen.FlagOptional|mrtgen.FlagTransitive, 99, make([]byte, 300))
	if long[0]&mrtgen.FlagExtLen == 0 || len(long) != 4+300 {
		t.Errorf("long attribute header = % x len %d", long[:4], len(long))
	}
	short := mrtgen.Raw(mrtgen.FlagOptional, 99, []byte{1, 2})
	if !bytes.Equal(short, []byte{mrtgen.FlagOptional, 99, 2, 1, 2}) {
		t.Errorf("short attribute = % x", short)
	}
	u, diags := bgp.ParseUpdate(mrtgen.Update(nil, nil, slices.Concat(mrtgen.Origin(bgp.OriginIGP), long), false), bgp.Context{AS4: true})
	if len(diags) != 0 || len(u.Attrs.Raw()) != 4+300+4 {
		t.Errorf("update with long attribute: %v, %d attribute bytes", diags, len(u.Attrs.Raw()))
	}
}
