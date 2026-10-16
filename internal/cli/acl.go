package cli

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf/ncfapi"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// ACLVersionsDoc lists the ACL versions.
type ACLVersionsDoc struct {
	output.Header
	Versions []ncfapi.ACLVersionInfo `json:"versions" doc:"Newest first."`
}

func (*ACLVersionsDoc) SchemaID() string { return "prolexic.acl-versions.v1" }

func (d *ACLVersionsDoc) WriteText(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "VERSION\tSTATE\tRULES\tUPDATED\tBY\tDESCRIPTION")
	for _, v := range d.Versions {
		fmt.Fprintf(tw, "%d\t%s\t%d\t%s\t%s\t%s\n", v.Version, dash(v.State), v.RulesCount, dash(v.Updated), dash(v.UpdatedBy), dash(v.Description))
	}
	return tw.Flush()
}

func newACLVersionsCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "versions",
		Short: "every ACL version",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return aclVersions(ctx, a)
		}),
	}
}

func aclVersions(ctx context.Context, a *app) (output.Document, error) {
	api, err := a.ncfV2()
	if err != nil {
		return nil, err
	}
	rows, err := api.ListACLVersions(ctx)
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(rows, func(x, y ncfapi.ACLVersionInfo) int { return cmp.Compare(y.Version, x.Version) })
	return &ACLVersionsDoc{Versions: nonNil(rows)}, nil
}

// ACLRuleRow is one rule of an ACL version.
type ACLRuleRow struct {
	Index            int    `json:"index"`
	Action           string `json:"action,omitempty" doc:"Empty for a remark, which has no parsed form."`
	Source           string `json:"source,omitempty" doc:"As live names it: a source alias is qualified SRC::<account>::<name>, a destination alias is bare."`
	Destination      string `json:"destination,omitempty"`
	Protocol         string `json:"protocol,omitempty" doc:"Name for the common numbers (icmp, tcp, udp, gre), else the number or min-max; ip for 0-255."`
	SourcePorts      string `json:"sourcePorts,omitempty" doc:"TCP or UDP source port range."`
	DestinationPorts string `json:"destinationPorts,omitempty" doc:"TCP or UDP destination port range."`
	IPVersion        string `json:"ipVersion,omitempty"`
	Comment          string `json:"comment,omitempty"`
	ACLText          string `json:"aclText,omitempty"`
	RuleUUID         string `json:"ruleUuid,omitempty"`
}

// ACLDoc is one ACL version with its rules.
type ACLDoc struct {
	output.Header
	Version     int          `json:"version"`
	State       string       `json:"state"`
	Production  bool         `json:"production" doc:"This is the version deployment status reports in production."`
	Description string       `json:"description,omitempty"`
	UpdatedBy   string       `json:"updatedBy,omitempty"`
	Updated     string       `json:"updated,omitempty"`
	Rules       []ACLRuleRow `json:"rules" doc:"In index order."`
}

func (*ACLDoc) SchemaID() string { return "prolexic.acl.v1" }

func (d *ACLDoc) WriteText(w io.Writer) error {
	fmt.Fprintf(w, "ACL version %d, state %s", d.Version, dash(d.State))
	if d.Production {
		fmt.Fprint(w, " (production)")
	}
	fmt.Fprintf(w, ", %d rules\n", len(d.Rules))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "INDEX\tACTION\tPROTOCOL\tSOURCE\tSRC PORTS\tDESTINATION\tDST PORTS\tCOMMENT")
	for _, r := range d.Rules {
		if r.Action == "" {
			fmt.Fprintf(tw, "%d\t-\t-\t-\t-\t-\t-\t%s\n", r.Index, dash(cmp.Or(r.Comment, r.ACLText)))
			continue
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.Index, r.Action, dash(r.Protocol), dash(r.Source), dash(r.SourcePorts),
			dash(r.Destination), dash(r.DestinationPorts), dash(r.Comment))
	}
	return tw.Flush()
}

var protocolNames = map[int]string{1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 58: "icmpv6"}

// protocolString names the rule's protocols: ip for all of them, a name for
// the common numbers, else the number or min-max.
func protocolString(p *ncfapi.ACLParsed) string {
	s, ok := p.Protocols()
	switch {
	case !ok:
		return ""
	case s == ncfapi.AllProtocols:
		return "ip"
	case s.Min == s.Max:
		return cmp.Or(protocolNames[s.Min], strconv.Itoa(s.Min))
	}
	return fmt.Sprintf("%d-%d", s.Min, s.Max)
}

// spanString is a port restriction: empty when there is none.
func spanString(s ncfapi.Span, ok bool) string {
	switch {
	case !ok:
		return ""
	case s.Min == s.Max:
		return strconv.Itoa(s.Min)
	}
	return fmt.Sprintf("%d-%d", s.Min, s.Max)
}

func ruleRow(r ncfapi.ACLRuleDetail) ACLRuleRow {
	row := ACLRuleRow{Index: r.Index, IPVersion: r.IPVersion, Comment: r.Comment, ACLText: r.ACLText, RuleUUID: r.RuleUUID}
	p := r.Parsed
	if p == nil {
		return row
	}
	row.Action, row.Source, row.Destination = p.Action, p.SourceAddress, p.DestinationAddress
	row.Protocol = protocolString(p)
	row.IPVersion = cmp.Or(row.IPVersion, strings.ToUpper(p.IPVersion))
	// One column per side: TCP's restriction, else UDP's.
	for _, pr := range []*ncfapi.PortRange{p.TCP, p.UDP} {
		row.SourcePorts = cmp.Or(row.SourcePorts, spanString(pr.SourcePorts()))
		row.DestinationPorts = cmp.Or(row.DestinationPorts, spanString(pr.DestinationPorts()))
	}
	return row
}

func newACLShowCmd(a *app) *cobra.Command {
	var version int
	cmd := &cobra.Command{
		Use:   "show",
		Short: "one ACL version's rules (default: production)",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return aclShow(ctx, a, version)
		}),
	}
	cmd.Flags().IntVar(&version, "version", 0, "ACL version number (default: the version in production)")
	return cmd
}

func aclShow(ctx context.Context, a *app, version int) (output.Document, error) {
	if version < 0 {
		return nil, apperr.New(apperr.Usage, "--version must be positive")
	}
	api, err := a.ncfV2()
	if err != nil {
		return nil, err
	}
	sets, err := api.DeploymentSets(ctx)
	if err != nil {
		return nil, err
	}
	prod, perr := ncfapi.ProductionVersion(sets)
	v := version
	if v == 0 {
		if perr != nil {
			return nil, perr
		}
		v = prod
	}
	got, err := api.ACLVersion(ctx, v)
	if err != nil {
		return nil, err
	}
	doc := &ACLDoc{Version: cmp.Or(got.Version, v), State: got.State, Production: perr == nil && v == prod,
		Description: got.Description, UpdatedBy: got.UpdatedBy, Updated: got.Updated, Rules: []ACLRuleRow{}}
	for _, r := range got.Rules {
		doc.Rules = append(doc.Rules, ruleRow(r))
	}
	slices.SortStableFunc(doc.Rules, func(x, y ACLRuleRow) int { return cmp.Compare(x.Index, y.Index) })
	return doc, nil
}

// ACLDeploymentDoc is the ACL deployment status.
type ACLDeploymentDoc struct {
	output.Header
	Production int                    `json:"production" doc:"The version in production; 0 when none is."`
	RuleSets   []ncfapi.DeploymentSet `json:"ruleSets" doc:"Newest version first, then by status."`
}

func (*ACLDeploymentDoc) SchemaID() string { return "prolexic.acl-deployment.v1" }

func (d *ACLDeploymentDoc) WriteText(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "VERSION\tSTATUS\tTOTAL\tINSTALLED\tNOT INSTALLED\tFAILED\tRETRIEVED\t")
	for _, rs := range d.RuleSets {
		mark := ""
		if rs.Status == "PRODUCTION" && rs.Version == d.Production {
			mark = "<- production"
		}
		fmt.Fprintf(tw, "%d\t%s\t%d\t%d\t%d\t%d\t%s\t%s\n", rs.Version, rs.Status, rs.Stats.Total, rs.Stats.Installed,
			rs.Stats.NotInstalled, rs.Stats.Failed, dash(rs.Retrieved), mark)
	}
	return tw.Flush()
}

func newACLDeploymentCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "deployment",
		Short: "deployment-status rulesets and which is in production",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return aclDeployment(ctx, a)
		}),
	}
}

func aclDeployment(ctx context.Context, a *app) (output.Document, error) {
	api, err := a.ncfV2()
	if err != nil {
		return nil, err
	}
	sets, err := api.DeploymentSets(ctx)
	if err != nil {
		return nil, err
	}
	prod, _ := ncfapi.ProductionVersion(sets)
	// Newest version first, then status: stable whatever order the API sent.
	slices.SortStableFunc(sets, func(x, y ncfapi.DeploymentSet) int {
		return cmp.Or(cmp.Compare(y.Version, x.Version), cmp.Compare(x.Status, y.Status))
	})
	return &ACLDeploymentDoc{Production: prod, RuleSets: sets}, nil
}
