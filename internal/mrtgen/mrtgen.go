// Package mrtgen is a test-only MRT encoder, copied from
// github.com/rkolesnichenko/mrt v0.1.0 internal/mrtgen (MIT), trimmed to what
// observe's tests build captures with. Tests use it for cases real collector
// files lack.
//
// Every builder encodes exactly what it is given and validates nothing, so
// tests can also build malformed data. Builders for record bodies
// (PeerIndexTable, RIB, BGP4MP, ...) return the body only; Header wraps a body
// into a whole record.
package mrtgen

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"time"

	"github.com/rkolesnichenko/mrt"
	"github.com/rkolesnichenko/mrt/bgp"
)

// Entry is one RIB entry. PathID is written only for the add-path subtypes.
type Entry struct {
	PeerIndex  uint16
	Originated time.Time
	PathID     uint32
	Attrs      []byte
}

func u16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }
func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

// Header returns a whole MRT record: the common header, the microsecond field
// for the *_ET types (taken from ts), and body.
func Header(t mrt.Type, st mrt.Subtype, ts time.Time, body []byte) []byte {
	et := t == mrt.TypeBGP4MPET || t == mrt.TypeISISET || t == mrt.TypeOSPFv3ET
	n := len(body)
	if et {
		n += 4
	}
	b := binary.BigEndian.AppendUint32(nil, uint32(ts.Unix()))
	b = binary.BigEndian.AppendUint16(b, uint16(t))
	b = binary.BigEndian.AppendUint16(b, uint16(st))
	b = binary.BigEndian.AppendUint32(b, uint32(n))
	if et {
		b = binary.BigEndian.AppendUint32(b, uint32(ts.Nanosecond()/1000))
	}
	return append(b, body...)
}

func addrBytes(a netip.Addr) []byte {
	if a.Is4() {
		b := a.As4()
		return b[:]
	}
	b := a.As16()
	return b[:]
}

// PeerIndexTable returns the body of a PEER_INDEX_TABLE. A peer's address
// family follows Addr, and its AS is written in 4 bytes when it is above 65535.
func PeerIndexTable(collector netip.Addr, view string, peers []mrt.Peer) []byte {
	b := append(addrBytes(collector), u16(uint16(len(view)))...)
	b = append(b, view...)
	b = append(b, u16(uint16(len(peers)))...)
	for _, p := range peers {
		var t byte
		if p.Addr.Is6() {
			t |= 1
		}
		if p.AS > 0xFFFF {
			t |= 2
		}
		b = append(b, t)
		b = append(b, addrBytes(p.BGPID)...)
		b = append(b, addrBytes(p.Addr)...)
		if p.AS > 0xFFFF {
			b = append(b, u32(uint32(p.AS))...)
		} else {
			b = append(b, u16(uint16(p.AS))...)
		}
	}
	return b
}

// PrefixBytes encodes p as BGP NLRI: an optional 4-byte path identifier, the
// length in bits and ceil(bits/8) address bytes.
func PrefixBytes(p netip.Prefix, pathID uint32, addPath bool) []byte {
	var b []byte
	if addPath {
		b = u32(pathID)
	}
	b = append(b, byte(p.Bits()))
	return append(b, addrBytes(p.Addr())[:(p.Bits()+7)/8]...)
}

// NLRIBytes encodes a run of NLRI; with addPath each carries its PathID.
func NLRIBytes(n []bgp.NLRI, addPath bool) []byte {
	var b []byte
	for _, x := range n {
		b = append(b, PrefixBytes(x.Prefix, x.PathID, addPath)...)
	}
	return b
}

func ribEntries(st mrt.Subtype, entries []Entry) []byte {
	b := u16(uint16(len(entries)))
	for _, e := range entries {
		b = append(b, u16(e.PeerIndex)...)
		b = append(b, u32(uint32(e.Originated.Unix()))...)
		if st >= mrt.SubRIBIPv4UnicastAddPath && st <= mrt.SubRIBIPv6MulticastAddPath {
			b = append(b, u32(e.PathID)...)
		}
		b = append(b, u16(uint16(len(e.Attrs)))...)
		b = append(b, e.Attrs...)
	}
	return b
}

// RIB returns the body of a prefix-keyed RIB record (subtypes 2-5, 8-11).
// Entries carry a path identifier exactly when st is an add-path subtype.
func RIB(st mrt.Subtype, seq uint32, p netip.Prefix, entries []Entry) []byte {
	b := append(u32(seq), PrefixBytes(p, 0, false)...)
	return append(b, ribEntries(st, entries)...)
}

func isAS4(st mrt.Subtype) bool {
	switch st {
	case mrt.SubMessageAS4, mrt.SubStateChangeAS4, mrt.SubMessageAS4Local,
		mrt.SubMessageAS4AddPath, mrt.SubMessageAS4LocalAddPath:
		return true
	}
	return false
}

func bgp4mpFixed(st mrt.Subtype, peerAS, localAS bgp.ASN, peer, local netip.Addr) []byte {
	var b []byte
	if isAS4(st) {
		b = append(u32(uint32(peerAS)), u32(uint32(localAS))...)
	} else {
		b = append(u16(uint16(peerAS)), u16(uint16(localAS))...)
	}
	b = append(b, u16(0)...) // interface index
	afi := uint16(1)
	if peer.Is6() {
		afi = 2
	}
	b = append(b, u16(afi)...)
	b = append(b, addrBytes(peer)...)
	return append(b, addrBytes(local)...)
}

// BGP4MP returns the body of a BGP4MP message record; the AS width follows st.
func BGP4MP(st mrt.Subtype, peerAS, localAS bgp.ASN, peer, local netip.Addr, msg []byte) []byte {
	return append(bgp4mpFixed(st, peerAS, localAS, peer, local), msg...)
}

// StateChange returns the body of a BGP4MP state change record.
func StateChange(st mrt.Subtype, peerAS, localAS bgp.ASN, peer, local netip.Addr, old, new mrt.State) []byte {
	b := bgp4mpFixed(st, peerAS, localAS, peer, local)
	return append(b, append(u16(uint16(old)), u16(uint16(new))...)...)
}

// Update returns a BGP UPDATE message with the 0xFF marker. With addPath
// every NLRI, withdrawn or announced, carries its PathID.
func Update(withdrawn, nlri []bgp.NLRI, attrs []byte, addPath bool) []byte {
	w := NLRIBytes(withdrawn, addPath)
	body := append(u16(uint16(len(w))), w...)
	body = append(body, u16(uint16(len(attrs)))...)
	body = append(body, attrs...)
	body = append(body, NLRIBytes(nlri, addPath)...)
	msg := slices.Repeat([]byte{0xFF}, 16)
	msg = append(msg, u16(uint16(19+len(body)))...)
	msg = append(msg, 2)
	return append(msg, body...)
}

// Path attribute flag bits.
const (
	FlagOptional   = 0x80
	FlagTransitive = 0x40
	FlagExtLen     = 0x10
)

// Raw encodes one attribute with the given flags. The extended-length flag is
// added when v is longer than 255 bytes, since a 1-byte length cannot hold it.
func Raw(flags, code uint8, v []byte) []byte {
	if len(v) > 255 {
		flags |= FlagExtLen
	}
	b := []byte{flags, code}
	if flags&FlagExtLen != 0 {
		b = append(b, u16(uint16(len(v)))...)
	} else {
		b = append(b, byte(len(v)))
	}
	return append(b, v...)
}

// Origin is the ORIGIN attribute.
func Origin(o bgp.Origin) []byte { return Raw(FlagTransitive, 1, []byte{byte(o)}) }

func segments(as4 bool, segs []bgp.Segment) []byte {
	var b []byte
	for _, s := range segs {
		b = append(b, byte(s.Type), byte(len(s.ASNs)))
		for _, a := range s.ASNs {
			if as4 {
				b = append(b, u32(uint32(a))...)
			} else {
				b = append(b, u16(uint16(a))...)
			}
		}
	}
	return b
}

// ASPath is the AS_PATH attribute, with 4-byte ASNs when as4.
func ASPath(as4 bool, segs ...bgp.Segment) []byte {
	return Raw(FlagTransitive, 2, segments(as4, segs))
}

// AS4PathAttr is the AS_PATH-like AS4_PATH attribute (always 4-byte ASNs).
func AS4PathAttr(segs ...bgp.Segment) []byte {
	return Raw(FlagOptional|FlagTransitive, 17, segments(true, segs))
}

// Seq builds an AS_SEQUENCE segment.
func Seq(asns ...bgp.ASN) bgp.Segment { return bgp.Segment{Type: bgp.ASSequence, ASNs: asns} }

// Set builds an AS_SET segment.
func Set(asns ...bgp.ASN) bgp.Segment { return bgp.Segment{Type: bgp.ASSet, ASNs: asns} }

// ConfedSeq builds an AS_CONFED_SEQUENCE segment.
func ConfedSeq(asns ...bgp.ASN) bgp.Segment {
	return bgp.Segment{Type: bgp.ASConfedSequence, ASNs: asns}
}

// NextHop is the NEXT_HOP attribute.
func NextHop(a netip.Addr) []byte { return Raw(FlagTransitive, 3, addrBytes(a)) }

func nextHops(nh []netip.Addr) []byte {
	var b []byte
	for _, a := range nh {
		b = append(b, addrBytes(a)...)
	}
	return b
}

// MPReach is the full-form MP_REACH_NLRI attribute. nh is one address, or two
// (global, link-local) for a 32-byte next hop. With addPath the NLRI carry
// their PathID.
func MPReach(fam bgp.Family, nh []netip.Addr, nlri []bgp.NLRI, addPath bool) []byte {
	h := nextHops(nh)
	v := append(u16(uint16(fam.AFI)), byte(fam.SAFI), byte(len(h)))
	v = append(v, h...)
	v = append(v, 0) // reserved
	v = append(v, NLRIBytes(nlri, addPath)...)
	return Raw(FlagOptional, 14, v)
}

// MPReachAbbrev is MP_REACH_NLRI as an RIB entry carries it (RFC 6396 section
// 4.3.4): the next hop length and next hop only.
func MPReachAbbrev(nh ...netip.Addr) []byte {
	h := nextHops(nh)
	return Raw(FlagOptional, 14, append([]byte{byte(len(h))}, h...))
}

// MPUnreach is the MP_UNREACH_NLRI attribute.
func MPUnreach(fam bgp.Family, withdrawn []bgp.NLRI, addPath bool) []byte {
	v := append(u16(uint16(fam.AFI)), byte(fam.SAFI))
	v = append(v, NLRIBytes(withdrawn, addPath)...)
	return Raw(FlagOptional, 15, v)
}

// Communities is the COMMUNITIES attribute.
func Communities(c ...bgp.Community) []byte {
	var v []byte
	for _, x := range c {
		v = append(v, u32(uint32(x))...)
	}
	return Raw(FlagOptional|FlagTransitive, 8, v)
}
