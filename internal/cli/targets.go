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

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/networkhealth"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// networkHealth is the Network Health client, over the read credentials.
func (a *app) networkHealth() (*networkhealth.Client, error) {
	c, err := a.readClient()
	if err != nil {
		return nil, err
	}
	return networkhealth.New(c), nil
}

// TargetsDoc lists the account's Network Health targets.
type TargetsDoc struct {
	output.Header
	Targets []networkhealth.Target `json:"targets" doc:"Sorted by targetName, targetId."`
}

func (*TargetsDoc) SchemaID() string { return "prolexic.targets.v1" }

func (d *TargetsDoc) WriteText(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNAME\tTYPE\tTARGET\tPORTS\tTESTS")
	for _, t := range d.Targets {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", t.TargetID, t.TargetName, dash(t.TestType), dash(targetOf(t)),
			dash(joinInts(t.Ports)), dash(joinInts(t.TestIDs)))
	}
	return tw.Flush()
}

// targetOf is the address or domain a target monitors.
func targetOf(t networkhealth.Target) string {
	return cmp.Or(t.TargetIP, t.TargetDomain)
}

func joinInts(n []int) string {
	s := make([]string, len(n))
	for i, v := range n {
		s[i] = strconv.Itoa(v)
	}
	return strings.Join(s, ",")
}

func runTargetsList(ctx context.Context, a *app, args []string) (output.Document, error) {
	fs := a.flags()
	if err := a.parse(fs, args, false); err != nil {
		return nil, err
	}
	api, err := a.networkHealth()
	if err != nil {
		return nil, err
	}
	rows, err := api.Targets(ctx)
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(rows, func(x, y networkhealth.Target) int {
		return cmp.Or(cmp.Compare(x.TargetName, y.TargetName), cmp.Compare(x.TargetID, y.TargetID))
	})
	return &TargetsDoc{Targets: nonNil(rows)}, nil
}

// TargetDoc is one Network Health target.
type TargetDoc struct {
	output.Header
	Target networkhealth.Target `json:"target"`
}

func (*TargetDoc) SchemaID() string { return "prolexic.target.v1" }

func (d *TargetDoc) WriteText(w io.Writer) error {
	t := d.Target
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, kv := range [][2]string{
		{"id", t.TargetID}, {"name", t.TargetName}, {"account", t.AccountID}, {"type", t.TestType},
		{"ip", t.TargetIP}, {"domain", t.TargetDomain}, {"ports", joinInts(t.Ports)}, {"tests", joinInts(t.TestIDs)},
		{"created", t.CreatedTime}, {"created by", t.CreatedBy}, {"modified", t.ModifiedTime}, {"modified by", t.ModifiedBy},
	} {
		fmt.Fprintf(tw, "%s\t%s\n", kv[0], dash(kv[1]))
	}
	return tw.Flush()
}

func runTargetsShow(ctx context.Context, a *app, args []string) (output.Document, error) {
	fs := a.flags()
	id := fs.String("id", "", "target id (required)")
	if err := a.parse(fs, args, false); err != nil {
		return nil, err
	}
	if *id == "" {
		return nil, apperr.New(apperr.Usage, "--id is required\n%s", flagUsage(fs))
	}
	api, err := a.networkHealth()
	if err != nil {
		return nil, err
	}
	t, err := api.Target(ctx, *id)
	if err != nil {
		return nil, err
	}
	return &TargetDoc{Target: *t}, nil
}
