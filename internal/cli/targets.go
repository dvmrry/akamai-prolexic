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

func newTargetsListCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "every target of the account",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return targetsList(ctx, a)
		}),
	}
}

func targetsList(ctx context.Context, a *app) (output.Document, error) {
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

func newTargetsShowCmd(a *app) *cobra.Command {
	var id string
	cmd := &cobra.Command{
		Use:   "show",
		Short: "one target by id",
		Args:  cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return targetsShow(ctx, a, id)
		}),
	}
	cmd.Flags().StringVar(&id, "id", "", "target id (required)")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

func targetsShow(ctx context.Context, a *app, id string) (output.Document, error) {
	api, err := a.networkHealth()
	if err != nil {
		return nil, err
	}
	t, err := api.Target(ctx, id)
	if err != nil {
		return nil, err
	}
	return &TargetDoc{Target: *t}, nil
}
