package verdict

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"testing"

	"github.com/rkolesnichenko/rpsl/resolve/peval"
	"github.com/rkolesnichenko/rpsl/types"
)

// fuzzFilters are the clauses of FuzzDecide's policy: prefix tests of both
// families, NOT, path tests (one a same-AS run over a sequence), community
// tests of both kinds, internet and a value out of range.
var fuzzFilters = []string{
	"AS-CUST^+ AND <^PeerAS AS-CUST+$>",
	"{10.0.0.0/8^16-24, 2001:db8::/32^+} AND NOT {10.1.0.0/16^+} AND community(65000:100, no_export)",
	"(<(AS64501 AS64502)~+> AND {172.16.0.0/12^+}) OR (community == {1:1, internet} AND {2001:db8::/32^+})",
	"NOT <AS64666> AND community(65536:1)",
	"<^PeerAS .* [AS64501 - AS64510]$> AND NOT community(no_advertise)",
	"{192.0.2.0/24^24-32} AND <AS64502~{2,3}>",
}

// fuzzASNs are the ASes a fuzzed path is drawn from, so paths meet the
// policy's regexps.
var fuzzASNs = []types.ASN{peer, 64501, 64502, 64503, 64666, 64505, 1, 4200000000}

// fuzzComms are the communities a fuzzed route carries, drawn the same way.
var fuzzComms = []uint32{comm(65000, 100), commNoExport, commNoAdvertise, commLocalAS, comm(1, 1), 0, 0xFFFFFFFF, comm(65535, 1)}

// FuzzDecide decides fuzzed routes against a fixed policy: Decide never
// panics, the outcome is one of the three, each carries what it must, and a
// compiled policy (its memo warm) agrees with a fresh Decide.
func FuzzDecide(f *testing.F) {
	clauses := make([]peval.Clause, len(fuzzFilters))
	for i, text := range fuzzFilters {
		clauses[i] = pclause(i, normal(f, types.AFIAny, text))
	}
	p := pol(clauses...)
	c := Compile(p)

	f.Add(uint8(0b0110), []byte{192, 0, 2, 0}, uint8(24), []byte{0, 1}, []byte{})
	f.Add(uint8(0b0111), []byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, uint8(48), []byte{0, 3, 2}, []byte{0, 1})
	f.Add(uint8(0b0110), []byte{10, 2, 0, 0}, uint8(16), []byte{0, 1, 1}, []byte{0, 1})
	f.Add(uint8(0b0010), []byte{10, 2, 0, 0}, uint8(16), []byte{1, 2, 1, 2}, []byte{4, 2})
	f.Add(uint8(0b1000), []byte{}, uint8(0), []byte{}, []byte{})
	f.Add(uint8(0b0110), []byte{192, 0, 2, 0}, uint8(28), []byte{0, 6, 2, 2, 2}, []byte{2})
	f.Add(uint8(0b0110), []byte{203, 0, 113, 0}, uint8(24), []byte{0, 4}, []byte{})
	f.Fuzz(func(t *testing.T, flags uint8, addr []byte, bits uint8, path []byte, comms []byte) {
		r := Route{
			PathKnown:  flags&2 != 0,
			CommsKnown: flags&4 != 0,
			OriginSet:  flags&8 != 0,
		}
		switch {
		case len(addr) >= 16 && flags&1 != 0:
			r.Prefix = netip.PrefixFrom(netip.AddrFrom16([16]byte(addr[:16])), int(bits))
		case len(addr) >= 4:
			r.Prefix = netip.PrefixFrom(netip.AddrFrom4([4]byte(addr[:4])), int(bits))
		}
		for i, b := range path {
			if b&0x80 != 0 && i+4 < len(path) {
				// A raw AS, now and then.
				r.Path = append(r.Path, types.ASN(binary.BigEndian.Uint32(path[i:])))
				continue
			}
			r.Path = append(r.Path, fuzzASNs[int(b)%len(fuzzASNs)])
		}
		for _, b := range comms {
			r.Communities = append(r.Communities, fuzzComms[int(b)%len(fuzzComms)])
		}

		v := c.Decide(r)
		switch v.Outcome {
		case Accepted:
			if v.Clause < 0 || v.Clause >= len(p.Clauses) {
				t.Fatalf("Accepted by clause %d of %d", v.Clause, len(p.Clauses))
			}
			for _, rs := range v.Reasons {
				if rs.Kind != ReasonPeval || rs.Index > p.Clauses[v.Clause].Index {
					t.Fatalf("Accepted by clause %d with reason %+v", v.Clause, rs)
				}
			}
			for _, e := range v.EarlierUndecided {
				if e < 0 || e >= v.Clause {
					t.Fatalf("earlier undecided %d, accepted by %d", e, v.Clause)
				}
			}
		case Rejected:
			if len(v.Fails) != len(p.Clauses) {
				t.Fatalf("Rejected with %d fails for %d clauses", len(v.Fails), len(p.Clauses))
			}
			for i, f := range v.Fails {
				if f.Clause != i || f.Test == "" {
					t.Fatalf("fail %d: %+v", i, f)
				}
			}
		case Undecided:
			if len(v.Reasons) == 0 {
				t.Fatalf("Undecided with no reason: %+v", v)
			}
		default:
			t.Fatalf("outcome %d", v.Outcome)
		}
		if fresh := Decide(p, r); !reflect.DeepEqual(fresh, v) {
			t.Fatalf("compiled %+v, fresh %+v", v, fresh)
		}
	})
}
