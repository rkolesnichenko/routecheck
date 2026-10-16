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

// FuzzObserve replays arbitrary MRT bytes. Session must never panic, and what
// it yields must hold its own promises: observations in order, each starting
// with X, none when every session is down, and an error only alone.
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
	f.Fuzz(func(t *testing.T, data []byte) {
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
