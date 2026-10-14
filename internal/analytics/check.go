package analytics

import (
	"cmp"
	"net/netip"
	"slices"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// Expect is what a propagation check wants of a prefix.
type Expect string

const (
	// ExpectPresent wants every expected session to carry the prefix.
	ExpectPresent Expect = "present"
	// ExpectAbsent wants no expected session to carry it.
	ExpectAbsent Expect = "absent"
)

// ParseExpect validates an --expect value.
func ParseExpect(s string) (Expect, error) {
	switch e := Expect(s); e {
	case ExpectPresent, ExpectAbsent:
		return e, nil
	}
	return "", apperr.New(apperr.Usage, "--expect must be present or absent, not %q", s)
}

// SessionCheck is one expected session and whether it carries the prefix.
type SessionCheck struct {
	Customer   string `json:"customer"`
	DataCenter string `json:"dataCenter"`
	RouterName string `json:"routerName"`
	Peer       string `json:"peer" doc:"The session's customer BGP peer of the prefix's address family."`
	Carried    bool   `json:"carried" doc:"Whether Akamai holds a route for exactly the prefix from this peer."`
}

// SkippedSession is a session the prefix cannot travel over: it has no BGP
// peer of the prefix's address family.
type SkippedSession struct {
	Customer   string `json:"customer"`
	DataCenter string `json:"dataCenter"`
	RouterName string `json:"routerName"`
}

// CheckResult is the outcome of one evaluation.
type CheckResult struct {
	Sessions []SessionCheck   // the expected sessions, sorted
	Skipped  []SkippedSession // sessions with no peer of the prefix's family, sorted
	// Off counts the expected sessions that contradict the expectation:
	// those not carrying the prefix for ExpectPresent, those carrying it for
	// ExpectAbsent.
	Off int
}

// Satisfied reports whether there is at least one expected session and none
// is off. With no expected sessions nothing was checked, so it is false.
func (r CheckResult) Satisfied() bool { return len(r.Sessions) > 0 && r.Off == 0 }

// EvaluateCheck joins sessions to routes for a propagation check.
//
// prefix is compared exactly after masking: a covering or covered route does
// not count. The prefix's address family picks the session peer field
// (customerBgpPeerIpv4 or customerBgpPeerIpv6); sessions with no peer of that
// family are Skipped, not expected. sites, when non-empty, keeps only
// sessions whose dataCenter is listed. A session carries the prefix when a
// route of the same customer has that peer (compared as an address, so
// "2001:db8::0:1" equals "2001:db8::1") and that prefix.
func EvaluateCheck(sessions []BGPSession, routes []Route, prefix netip.Prefix, expect Expect, sites []string) CheckResult {
	prefix = prefix.Masked()
	type key struct {
		customer string
		peer     netip.Addr
	}
	carriers := map[key]bool{}
	for _, r := range routes {
		peer, err := netip.ParseAddr(r.CustomerBgpPeerIp)
		if err != nil || !SamePrefix(r.Prefix, prefix) {
			continue
		}
		carriers[key{r.Customer, peer}] = true
	}

	var res CheckResult
	for _, s := range sessions {
		if len(sites) > 0 && !slices.Contains(sites, s.DataCenter) {
			continue
		}
		raw := s.CustomerBgpPeerIpv4
		if prefix.Addr().Is6() {
			raw = s.CustomerBgpPeerIpv6
		}
		peer, err := netip.ParseAddr(raw)
		if err != nil || peer.Is6() != prefix.Addr().Is6() {
			res.Skipped = append(res.Skipped, SkippedSession{s.Customer, s.DataCenter, s.RouterName})
			continue
		}
		carried := carriers[key{s.Customer, peer}]
		res.Sessions = append(res.Sessions, SessionCheck{
			Customer: s.Customer, DataCenter: s.DataCenter, RouterName: s.RouterName,
			Peer: peer.String(), Carried: carried,
		})
		if carried != (expect == ExpectPresent) {
			res.Off++
		}
	}
	slices.SortStableFunc(res.Sessions, func(x, y SessionCheck) int {
		return cmp.Or(cmp.Compare(x.Customer, y.Customer), cmp.Compare(x.DataCenter, y.DataCenter),
			cmp.Compare(x.RouterName, y.RouterName), cmp.Compare(x.Peer, y.Peer))
	})
	slices.SortStableFunc(res.Skipped, func(x, y SkippedSession) int {
		return cmp.Or(cmp.Compare(x.Customer, y.Customer), cmp.Compare(x.DataCenter, y.DataCenter),
			cmp.Compare(x.RouterName, y.RouterName))
	})
	return res
}
