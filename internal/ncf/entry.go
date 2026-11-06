// Package ncf manages Network Cloud Firewall alias entries as reviewed
// desired state.
//
// The model: live is state, git is intent. There is no state file. A desired
// file names aliases by name, pins them by id, asserts their type, and lists
// their entries; the tool touches only the aliases it names and never prunes
// what the file omits. Each alias's activeVersion at plan time is the
// conflict token apply checks before writing.
package ncf

import (
	"cmp"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Kind is what an entry denotes.
type Kind int

const (
	KindPrefix Kind = iota // an IPv4 or IPv6 prefix
	KindGeo                // GEO::<ISO 3166-1 alpha-2>
	KindASN                // ASN::<number>
)

// Value is one normalised alias entry. The zero Value is invalid.
type Value struct {
	kind   Kind
	prefix netip.Prefix
	geo    string
	asn    uint32
}

// Kind reports what v denotes.
func (v Value) Kind() Kind { return v.kind }

// Prefix is v's prefix, for KindPrefix.
func (v Value) Prefix() netip.Prefix { return v.prefix }

// ASN is v's AS number, for KindASN.
func (v Value) ASN() uint32 { return v.asn }

// Is4 reports whether v is an IPv4 prefix.
func (v Value) Is4() bool { return v.kind == KindPrefix && v.prefix.Addr().Is4() }

// String is the canonical form: "192.0.2.0/24", "2001:db8::/32", "GEO::US",
// "ASN::64500". Both sides of a diff are compared in this form.
func (v Value) String() string {
	switch v.kind {
	case KindGeo:
		return "GEO::" + v.geo
	case KindASN:
		return "ASN::" + strconv.FormatUint(uint64(v.asn), 10)
	default:
		return v.prefix.String()
	}
}

// Compare orders values: IPv4 prefixes, then IPv6, by address then length;
// then GEO codes; then ASNs numerically.
func Compare(a, b Value) int {
	if c := cmp.Compare(a.rank(), b.rank()); c != 0 {
		return c
	}
	switch a.kind {
	case KindGeo:
		return cmp.Compare(a.geo, b.geo)
	case KindASN:
		return cmp.Compare(a.asn, b.asn)
	default:
		if c := a.prefix.Addr().Compare(b.prefix.Addr()); c != 0 {
			return c
		}
		return cmp.Compare(a.prefix.Bits(), b.prefix.Bits())
	}
}

func (v Value) rank() int {
	switch {
	case v.kind == KindGeo:
		return 2
	case v.kind == KindASN:
		return 3
	case v.prefix.Addr().Is4():
		return 0
	default:
		return 1
	}
}

// ParseAuthored parses an entry a person or agent wrote. It is strict: a
// prefix with host bits set is rejected (it is almost always a typo, and
// masking it would silently change what is blocked), GEO codes must be ISO
// 3166-1 alpha-2, ASNs numeric, and nothing may follow "::" but the value.
// Lower-case GEO codes and bare addresses are accepted and normalised.
func ParseAuthored(s string) (Value, error) {
	return parse(s, true)
}

// ParseLive parses an entry read from the API. It normalises rather than
// rejects: host bits are masked, so live and desired compare equal however
// the server spells them.
func ParseLive(s string) (Value, error) {
	return parse(s, false)
}

func parse(s string, strict bool) (Value, error) {
	if s != strings.TrimSpace(s) {
		if strict {
			return Value{}, fmt.Errorf("%q has surrounding whitespace", s)
		}
		s = strings.TrimSpace(s)
	}
	if s == "" {
		return Value{}, fmt.Errorf("empty entry")
	}
	if tag, rest, ok := strings.Cut(s, "::"); ok && (strings.EqualFold(tag, "GEO") || strings.EqualFold(tag, "ASN")) {
		if rest != strings.TrimSpace(rest) || rest == "" {
			return Value{}, fmt.Errorf("%q: %s:: must be followed by the value alone", s, strings.ToUpper(tag))
		}
		if strings.EqualFold(tag, "GEO") {
			code := strings.ToUpper(rest)
			if !isCountry(code) {
				return Value{}, fmt.Errorf("%q: %q is not an ISO 3166-1 alpha-2 country code", s, rest)
			}
			return Value{kind: KindGeo, geo: code}, nil
		}
		n, err := strconv.ParseUint(rest, 10, 32)
		if err != nil || n == 0 {
			return Value{}, fmt.Errorf("%q: ASN must be a number from 1 to 4294967295", s)
		}
		return Value{kind: KindASN, asn: uint32(n)}, nil
	}

	var p netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		if p, err = netip.ParsePrefix(s); err != nil {
			return Value{}, fmt.Errorf("%q is not a prefix, GEO:: code or ASN:: number", s)
		}
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return Value{}, fmt.Errorf("%q is not a prefix, GEO:: code or ASN:: number", s)
		}
		if a.Zone() != "" {
			return Value{}, fmt.Errorf("%q: zoned addresses are not allowed", s)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	p = unmapPrefix(p)
	if m := p.Masked(); m != p {
		if strict {
			return Value{}, fmt.Errorf("%q has host bits set; did you mean %s?", s, m)
		}
		p = m
	}
	return Value{kind: KindPrefix, prefix: p}, nil
}

// countries are the ISO 3166-1 alpha-2 assigned codes.
var countries = func() map[string]bool {
	const codes = `AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ
CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR
GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP
KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT
MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW
SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG
UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW`
	m := map[string]bool{}
	for _, c := range strings.Fields(codes) {
		m[c] = true
	}
	return m
}()

func isCountry(code string) bool { return countries[code] }

// unmapPrefix turns an IPv4-mapped IPv6 prefix (::ffff:198.51.100.0/120)
// into the IPv4 prefix it covers, so it compares with IPv4 entries. Shorter
// prefixes cover more than mapped space and stay IPv6.
func unmapPrefix(p netip.Prefix) netip.Prefix {
	if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
		return netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	return p
}
