package verdict

import (
	"slices"
	"strconv"
	"strings"

	"github.com/rkolesnichenko/rpsl/policy"
	"github.com/rkolesnichenko/rpsl/resolve"
)

// The well-known communities RPSL names (RFC 1997 values). local_as is
// rpsl's dictionary's spelling (policy/dict.go) of the third, which RFC 1997
// calls NO_EXPORT_SUBCONFED and IRRToolSet no_export_subconfed.
const (
	commNoExport    = 0xFFFFFF01
	commNoAdvertise = 0xFFFFFF02
	commLocalAS     = 0xFFFFFF03
)

// parseCommunity reads one community value as a policy writes it: a 4-byte
// decimal integer ("100"), "hi:lo" with each half a decimal at most 65535
// (hi<<16|lo; space around the colon is allowed, since RPSL does not tell
// it apart), or a keyword in any case: no_export, no_advertise, local_as.
// The kind is "" for a value read, ReasonCommInternet for internet, which
// RFC 2622 gives no value, and ReasonCommValue for anything else.
func parseCommunity(s string) (uint32, string) {
	t := strings.TrimSpace(s)
	switch {
	case strings.EqualFold(t, "internet"):
		return 0, ReasonCommInternet
	case strings.EqualFold(t, "no_export"):
		return commNoExport, ""
	case strings.EqualFold(t, "no_advertise"):
		return commNoAdvertise, ""
	case strings.EqualFold(t, "local_as"):
		return commLocalAS, ""
	}
	if hi, lo, ok := strings.Cut(t, ":"); ok {
		h, okh := decimal(strings.TrimSpace(hi), 16)
		l, okl := decimal(strings.TrimSpace(lo), 16)
		if !okh || !okl {
			return 0, ReasonCommValue
		}
		return h<<16 | l, ""
	}
	v, ok := decimal(t, 32)
	if !ok {
		return 0, ReasonCommValue
	}
	return v, ""
}

// decimal reads s, ASCII digits only, as an unsigned integer of size bits.
func decimal(s string, size int) (uint32, bool) {
	if s == "" {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	v, err := strconv.ParseUint(s, 10, size)
	return uint32(v), err == nil
}

// commTest is a compiled CommunityMatch: its values read once, sorted and
// deduplicated, or the reason the first unreadable one cannot be.
type commTest struct {
	negated bool
	equals  bool
	values  []uint32
	reason  string // ReasonCommInternet or ReasonCommValue; "" when every value was read
	text    string // Fail.Test and Reason.Term
}

func compileComm(m resolve.CommunityMatch) commTest {
	t := commTest{negated: m.Negated, equals: m.Test.Op == policy.CommunityEquals, text: m.Test.String()}
	if m.Negated {
		t.text = "NOT " + t.text
	}
	for _, s := range m.Test.Values {
		v, kind := parseCommunity(s)
		if kind != "" {
			t.reason = kind
			t.values = nil
			return t
		}
		t.values = append(t.values, v)
	}
	slices.Sort(t.values)
	t.values = slices.Compact(t.values)
	return t
}

// eval decides the test for r: yes or no, or undecided with the reason
// kind. A value that cannot be read is the reason before unknown
// communities, since it holds in every mode.
func (t *commTest) eval(r *Route) (tri, string) {
	if t.reason != "" {
		return undecidedT, t.reason
	}
	if !r.CommsKnown {
		return undecidedT, ReasonCommsUnknown
	}
	ok := true
	for _, v := range t.values {
		if !slices.Contains(r.Communities, v) {
			ok = false
			break
		}
	}
	if ok && t.equals {
		for _, v := range r.Communities {
			if _, found := slices.BinarySearch(t.values, v); !found {
				ok = false
				break
			}
		}
	}
	if ok != t.negated {
		return yes, ""
	}
	return no, ""
}
