package observe

import (
	"bytes"
	"net/netip"
	"slices"
	"testing"

	"github.com/rkolesnichenko/mrt"
	"github.com/rkolesnichenko/mrt/bgp"
	"github.com/rkolesnichenko/routecheck/internal/mrtgen"
	"github.com/rkolesnichenko/rpsl/types"
)

// FuzzObserve replays arbitrary MRT bytes through Session and Collector. Neither
// may panic, and what each yields must hold its own promises: observations in
// order, each starting with X, an error only alone; for Session none when
// every session is down; for Collector no communities, no peer address, at
// least one collector peer, sorted unique neighbours and counts that add up.
func FuzzObserve(f *testing.F) {
	ap := []bgp.NLRI{{Prefix: pfx("10.0.0.0/24"), PathID: 1, HasPathID: true}}
	f.Add(slices.Concat(established(at(0)),
		upd(at(1), nil, nlri("10.0.0.0/24", "10.0.1.0/24"), slices.Concat(attrs4(asX, asY), mrtgen.Communities(1))),
		upd(at(2), nlri("10.0.1.0/24"), nil, nil),
		upd(at(3), nil, nil, slices.Concat(mrtgen.Origin(bgp.OriginIGP), mrtgen.ASPath(true, mrtgen.Seq(asX)),
			mrtgen.MPReach(v6u, []netip.Addr{nh6}, nlri("2001:db8::/32"), false))),
		msg(at(4), mrt.SubMessageAS4AddPath, asX, peerAddr, localAddr, mrtgen.Update(nil, ap, attrs4(asX), true)),
		state(at(5), mrt.StateEstablished, mrt.StateIdle)))
	f.Add(slices.Concat(
		mrtgen.Header(mrt.TypeTableDumpV2, mrt.SubPeerIndexTable, at(0), mrtgen.PeerIndexTable(
			netip.MustParseAddr("192.0.2.254"), "v", []mrt.Peer{{BGPID: peerAddr, Addr: peerAddr, AS: asX}})),
		mrtgen.Header(mrt.TypeTableDumpV2, mrt.SubRIBIPv4Unicast, at(0), mrtgen.RIB(mrt.SubRIBIPv4Unicast, 0, pfx("10.0.0.0/24"),
			[]mrtgen.Entry{{PeerIndex: 0, Originated: at(0), Attrs: attrs4(asX)}})),
		upd(at(1), nil, nlri("10.0.1.0/24"), attrs4(asX))))
	f.Add(tableDump(at(0), pfx("10.0.0.0/24"), peerAddr, asX, attrs4(asX)))
	f.Add(slices.Concat(
		pitRec(at(0), cpeer(1, asP1), cpeer(2, asX)),
		ribRec(at(0), "10.0.0.0/24", ent(0, mrtgen.Seq(asP1, asP2, asX, asY)), ent(1, mrtgen.Seq(asX, asX, asY))),
		ribRec(at(0), "10.0.1.0/24", ent(0, mrtgen.Set(asP1), mrtgen.Seq(asX), mrtgen.Set(asZ)), ent(0, mrtgen.Seq(asP1), mrtgen.Set(asX))),
		pitRec(at(1), cpeer(3, asP3)),
		ribRec(at(1), "10.0.0.0/24", ent(0, mrtgen.Seq(asP3, asX, asY, asX)))))
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzCollector(t, data)
		for _, pre := range []bool{false, true} {
			sel := SessionSel{Peer: types.ASN(asX), PrePolicyRIB: pre}
			seq, info := Session(mrt.Records(bytes.NewReader(data)), sel)
			var obs []Observation
			errs := 0
			for o, err := range seq {
				if err != nil {
					errs++
					continue
				}
				obs = append(obs, o)
			}
			in := info()
			if errs > 1 || (errs == 1 && len(obs) > 0) {
				t.Fatalf("%d errors with %d observations", errs, len(obs))
			}
			if in.DownAtEnd && len(obs) > 0 {
				t.Fatalf("DownAtEnd with %d observations", len(obs))
			}
			for i, o := range obs {
				if len(o.Route.Path) == 0 || o.Route.Path[0] != types.ASN(asX) {
					t.Fatalf("observation %d does not start with X: %v", i, o.Route.Path)
				}
				if !o.Route.Prefix.IsValid() || !o.Route.CommsKnown || !o.Evidence.PeerAddr.IsValid() {
					t.Fatalf("observation %d: %+v", i, o.Route)
				}
				if i > 0 {
					a, b := obs[i-1].Route.Prefix, o.Route.Prefix
					if c := a.Addr().Compare(b.Addr()); c > 0 || (c == 0 && a.Bits() > b.Bits()) {
						t.Fatalf("out of order: %v before %v", a, b)
					}
				}
			}
			if in.NotFirstAS < 0 || in.Malformed < 0 || in.MalformedResets < 0 || in.Skipped < 0 {
				t.Fatalf("info = %+v", in)
			}
		}
	})
}

func fuzzCollector(t *testing.T, data []byte) {
	seq, info := Collector(mrt.Records(bytes.NewReader(data)), types.ASN(asX))
	var obs []Observation
	errs := 0
	for o, err := range seq {
		if err != nil {
			errs++
			continue
		}
		obs = append(obs, o)
	}
	in := info()
	if errs > 1 || (errs == 1 && len(obs) > 0) {
		t.Fatalf("Collector: %d errors with %d observations", errs, len(obs))
	}
	if in.Entries < 0 || in.Skipped < 0 || in.Malformed < 0 || in.Malformed > in.Entries ||
		in.Through > in.Entries-in.Malformed || in.NotSequence < 0 || in.NotSequence > in.Through ||
		in.Direct < 0 || in.NoNeighbour < 0 || in.Direct+in.NoNeighbour > in.Through-in.NotSequence ||
		len(obs) > in.Through-in.NotSequence {
		t.Fatalf("Collector: info = %+v with %d observations", in, len(obs))
	}
	for i, o := range obs {
		ev := o.Evidence
		if len(o.Route.Path) == 0 || o.Route.Path[0] != types.ASN(asX) || !o.Route.Prefix.IsValid() ||
			o.Route.CommsKnown || len(o.Route.Communities) > 0 || ev.PeerAddr.IsValid() || ev.CollectorPeers < 1 {
			t.Fatalf("Collector: observation %d: %+v", i, o)
		}
		for j := 1; j < len(ev.Neighbours); j++ {
			if ev.Neighbours[j-1] >= ev.Neighbours[j] {
				t.Fatalf("Collector: observation %d: neighbours %v", i, ev.Neighbours)
			}
		}
		if !ev.Direct && len(ev.Neighbours) == 0 && in.NoNeighbour == 0 {
			t.Fatalf("Collector: observation %d has no neighbour, is not direct, and NoNeighbour is 0", i)
		}
		if i > 0 {
			p, q := obs[i-1], o
			a, b := p.Route.Prefix, q.Route.Prefix
			c := a.Addr().Compare(b.Addr())
			if c == 0 {
				c = a.Bits() - b.Bits()
			}
			if c == 0 && p.Family == q.Family {
				c = slices.Compare(p.Route.Path, q.Route.Path)
			}
			if c > 0 {
				t.Fatalf("Collector: out of order: %v %v before %v %v", a, p.Route.Path, b, q.Route.Path)
			}
		}
	}
}
