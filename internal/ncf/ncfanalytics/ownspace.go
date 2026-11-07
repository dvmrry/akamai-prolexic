// Package ncfanalytics implements ncf.LiveOwnSpace over Prolexic Analytics:
// the account's protected prefixes and own AS numbers, for the own-space
// checks a plan runs (AGENTS.md, invariant 5).
package ncfanalytics

import (
	"context"
	"fmt"

	"github.com/dvmrry/akamai-prolexic/internal/analytics"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
)

// Client returns the Analytics client when the plan first needs it, so a plan
// that stops at its offline checks never needs Analytics credentials.
type Client func() (*analytics.Client, error)

// Source is the live own space from Prolexic Analytics.
func Source(client Client) ncf.LiveOwnSpace {
	return ncf.LiveOwnSpaceFunc(func(ctx context.Context) (ncf.LiveOwnSpaceResult, error) {
		c, err := client()
		if err != nil {
			return ncf.LiveOwnSpaceResult{}, err
		}
		return Fetch(ctx, c)
	})
}

// Fetch reads every customer name's protected prefixes and own AS numbers:
// the same data `prolexic protected` shows. Every name counts, in use or not,
// since an inactive name's space is still ours. A failed name fails the
// fetch, because the own-space check can't be partial.
func Fetch(ctx context.Context, c *analytics.Client) (ncf.LiveOwnSpaceResult, error) {
	names, err := analytics.AllCustomers(ctx, c, nil)
	if err != nil {
		return ncf.LiveOwnSpaceResult{}, err
	}
	rows, _, err := analytics.FanOut(ctx, names, func(ctx context.Context, name string) ([]analytics.Protected, error) {
		p, err := c.ProtectedFor(ctx, name)
		return []analytics.Protected{p}, err
	})
	if err != nil {
		return ncf.LiveOwnSpaceResult{}, err
	}
	var out ncf.LiveOwnSpaceResult
	for _, p := range rows {
		for _, prefix := range p.Prefixes {
			out.Prefixes = append(out.Prefixes, ncf.OwnSpacePrefix{Prefix: prefix, Source: "analytics " + p.Customer + "/" + p.Site})
		}
		for _, asn := range p.ASNs {
			out.ASNs = append(out.ASNs, ncf.OwnASN{ASN: uint32(asn), Source: "analytics " + p.Customer})
		}
		// Empty means unknown, not "nothing protected": say so.
		if len(p.Prefixes) == 0 {
			out.Findings = append(out.Findings, ncf.Finding{Severity: ncf.Warning, Code: "own_space_analytics_empty",
				Message: fmt.Sprintf("Prolexic Analytics reports no protected prefixes for customer name %s", p.Customer)})
		}
		// A subnet that isn't a prefix is own space nothing can check against:
		// a deny entry could cover it unseen, so the plan can't pass.
		if p.Unparsable > 0 {
			out.Findings = append(out.Findings, ncf.Finding{Severity: ncf.Error, Code: "own_space_unreadable",
				Message: fmt.Sprintf("Prolexic Analytics reports %d protected subnets for customer name %s that aren't prefixes; own space would be incomplete", p.Unparsable, p.Customer)})
		}
		// Likewise a BGP session without a usable AS number: a deny entry for
		// the AS it stands for would go unchecked.
		if p.UnusableASNs > 0 {
			out.Findings = append(out.Findings, ncf.Finding{Severity: ncf.Error, Code: "own_space_unreadable",
				Message: fmt.Sprintf("Prolexic Analytics reports %d BGP sessions for customer name %s without a usable AS number; own AS numbers would be incomplete", p.UnusableASNs, p.Customer)})
		}
		if p.NoRouted {
			out.Findings = append(out.Findings, ncf.Finding{Severity: ncf.Warning, Code: "own_space_asn_unknown",
				Message: fmt.Sprintf("Prolexic Analytics has no BGP sessions for customer name %s (404); its AS numbers weren't checked", p.Customer)})
		}
	}
	return out, nil
}
