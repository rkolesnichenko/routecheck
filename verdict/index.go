package verdict

import (
	"encoding/binary"
	"math/bits"
	"net/netip"

	"github.com/rkolesnichenko/rpsl/types"
)

// prefixIndex answers "does some range hold this prefix" for a set of
// prefix ranges, without a scan of the ranges: one path-compressed binary
// trie per family over the ranges' base prefixes, each node holding the
// lengths its ranges accept as a bitmask. A range r holds p exactly when
// r's base prefix is a prefix of p (as bits) and p's length is within
// r.Lo()..r.Hi() (types.PrefixRange.Contains); so a lookup walks p's bits
// from the root, and at each node on the way whose base prefix p extends
// tests p's length against the node's mask. The walk visits at most one
// node per bit of p, and compression keeps the node count under twice the
// number of distinct base prefixes.
type prefixIndex struct {
	v4, v6 trie
}

// trie is one family's trie. nodes[0] is the root, the empty prefix; a
// child index of 0 means no child, since the root is no node's child.
type trie struct {
	nodes []node
	lens  []lenMask
}

// node is a trie node: a base prefix (key's first bits bits; the rest are
// zero), its two children by the next bit, and the index in trie.lens of
// the lengths its ranges accept (-1: no range has this base prefix).
type node struct {
	key   key
	child [2]int32
	lens  int32
	bits  uint8
}

// key is an address as 128 bits, most significant first; an IPv4 address
// fills the first 32.
type key [2]uint64

// lenMask has bit n set when a range at its node accepts length n
// (0..128).
type lenMask [3]uint64

func (m *lenMask) set(lo, hi int) {
	for n := lo; n <= hi; n++ {
		m[n>>6] |= 1 << (n & 63)
	}
}

func (m *lenMask) has(n int) bool { return m[n>>6]&(1<<(n&63)) != 0 }

// newPrefixIndex indexes ranges. Empty ranges (types.PrefixRange.IsEmpty)
// hold no prefix and are left out.
func newPrefixIndex(ranges []types.PrefixRange) *prefixIndex {
	x := &prefixIndex{}
	for _, r := range ranges {
		if r.IsEmpty() {
			continue
		}
		p := r.Prefix()
		if !p.IsValid() {
			continue
		}
		t := x.family(p.Addr())
		if t.nodes == nil {
			t.nodes = []node{{lens: -1}}
		}
		n := t.insert(keyOf(p.Addr()), p.Bits())
		if t.nodes[n].lens < 0 {
			t.nodes[n].lens = int32(len(t.lens))
			t.lens = append(t.lens, lenMask{})
		}
		t.lens[t.nodes[n].lens].set(r.Lo(), r.Hi())
	}
	return x
}

func (x *prefixIndex) family(a netip.Addr) *trie {
	if a.Is4() {
		return &x.v4
	}
	return &x.v6
}

// contains reports whether some indexed range holds p (host bits ignored).
// An invalid p is in none.
func (x *prefixIndex) contains(p netip.Prefix) bool {
	if !p.IsValid() {
		return false
	}
	return x.family(p.Addr()).contains(keyOf(p.Masked().Addr()), p.Bits())
}

// insert returns the node of the base prefix (k, n), adding it, and the node
// that splits a compressed edge for it, when missing.
func (t *trie) insert(k key, n int) int32 {
	at := int32(0)
	for {
		cur := t.nodes[at]
		if int(cur.bits) == n {
			return at
		}
		// cur's prefix is a prefix of k, and n > cur.bits.
		b := k.bit(int(cur.bits))
		c := cur.child[b]
		if c == 0 {
			leaf := t.add(k, n)
			t.nodes[at].child[b] = leaf
			return leaf
		}
		next := t.nodes[c]
		common := commonLen(next.key, k, min(int(next.bits), n))
		if common == int(next.bits) {
			at = c
			continue
		}
		// k leaves next's edge at common (> cur.bits: both have bit b
		// there): split the edge with a node of that length.
		mid := t.add(k.mask(common), common)
		t.nodes[mid].child[next.key.bit(common)] = c
		t.nodes[at].child[b] = mid
		if common == n {
			return mid
		}
		leaf := t.add(k, n)
		t.nodes[mid].child[k.bit(common)] = leaf
		return leaf
	}
}

func (t *trie) add(k key, n int) int32 {
	t.nodes = append(t.nodes, node{key: k.mask(n), bits: uint8(n), lens: -1})
	return int32(len(t.nodes) - 1)
}

// contains reports whether a range in t holds the prefix of length n whose
// masked address is k.
func (t *trie) contains(k key, n int) bool {
	if len(t.nodes) == 0 {
		return false
	}
	at := int32(0)
	for {
		cur := &t.nodes[at]
		if cur.lens >= 0 && t.lens[cur.lens].has(n) {
			return true
		}
		if int(cur.bits) >= n {
			return false
		}
		c := cur.child[k.bit(int(cur.bits))]
		if c == 0 {
			return false
		}
		next := &t.nodes[c]
		if int(next.bits) > n || commonLen(next.key, k, int(next.bits)) < int(next.bits) {
			return false
		}
		at = c
	}
}

func keyOf(a netip.Addr) key {
	if a.Is4() {
		b := a.As4()
		return key{uint64(binary.BigEndian.Uint32(b[:])) << 32, 0}
	}
	b := a.As16()
	return key{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
}

// bit returns bit i (0 is the most significant).
func (k key) bit(i int) int {
	if i < 64 {
		return int(k[0] >> (63 - i) & 1)
	}
	return int(k[1] >> (127 - i) & 1)
}

// mask keeps k's first n bits.
func (k key) mask(n int) key {
	switch {
	case n <= 0:
		return key{}
	case n < 64:
		return key{k[0] &^ (^uint64(0) >> n), 0}
	case n == 64:
		return key{k[0], 0}
	case n < 128:
		return key{k[0], k[1] &^ (^uint64(0) >> (n - 64))}
	}
	return k
}

// commonLen is the number of leading bits a and b share, at most limit.
func commonLen(a, b key, limit int) int {
	n := 128
	if x := a[0] ^ b[0]; x != 0 {
		n = bits.LeadingZeros64(x)
	} else if x := a[1] ^ b[1]; x != 0 {
		n = 64 + bits.LeadingZeros64(x)
	}
	return min(n, limit)
}
