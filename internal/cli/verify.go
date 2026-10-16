package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// VerifyDoc compares a saved plan's expected end state with a fresh read.
type VerifyDoc struct {
	output.Header
	PlanFile string `json:"planFile"`
	ncf.VerifyResult
}

func (*VerifyDoc) SchemaID() string { return "prolexic.verify.v1" }

func (d *VerifyDoc) Outcome() error {
	if d.Verified {
		return nil
	}
	var off []string
	for _, a := range d.Aliases {
		if !a.Verified {
			off = append(off, a.Name)
		}
	}
	return apperr.New(apperr.Drift, "%d of %d aliases don't match the plan: %s", len(off), len(d.Aliases), strings.Join(off, ", "))
}

func (d *VerifyDoc) WriteText(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ALIAS\tID\tVERIFIED\tACTIVE\tPRODUCTION\tPROBLEMS")
	for _, a := range d.Aliases {
		fmt.Fprintf(tw, "%s\t%d\t%t\t%s\t%s\t%s\n", a.Name, a.ID, a.Verified, dash(a.ActiveVersion), dash(a.ProdVersion), dash(strings.Join(a.Problems, "; ")))
	}
	return tw.Flush()
}

func newVerifyCmd(a *app) *cobra.Command {
	var planFile string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "check a saved plan's expected end state against a fresh read (read-only)",
		Long: "Reads every alias in a saved plan (prolexic plan's JSON) fresh and checks the plan's expected end state: " +
			"each added entry is live, each removed entry is gone, the entry count is the plan's unchanged plus added (nothing extra), " +
			"and production carries the active version. Run it after apply, against the plan that was reviewed. " +
			"Exits 7 when anything doesn't match.",
		Example: "  prolexic plan --file desired.json > plan.json\n  prolexic apply --file desired.json --expect-digest <digest>\n  prolexic verify --plan plan.json",
		Args:    cobra.NoArgs,
		RunE: a.run(func(ctx context.Context, _ []string) (output.Document, error) {
			return verify(ctx, a, planFile)
		}),
	}
	cmd.Flags().StringVar(&planFile, "plan", "", "the saved plan document (JSON from prolexic plan)")
	return cmd
}

func verify(ctx context.Context, a *app, planFile string) (output.Document, error) {
	p, err := readPlan(planFile)
	if err != nil {
		return nil, err
	}
	store, err := a.ncfRead()
	if err != nil {
		return nil, err
	}
	res, err := ncf.Verify(ctx, store, p)
	if err != nil {
		return nil, err
	}
	return &VerifyDoc{PlanFile: planFile, VerifyResult: *res}, nil
}

// readPlan reads a saved plan document.
func readPlan(path string) (*ncf.Plan, error) {
	if path == "" {
		return nil, apperr.New(apperr.Usage, "--plan is required")
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, apperr.New(apperr.NotFound, "no plan file %s", path)
	}
	if err != nil {
		return nil, apperr.Wrap(apperr.Usage, err, "read %s", path)
	}
	var doc struct {
		Schema string `json:"schema"`
		ncf.Plan
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, apperr.Wrap(apperr.Usage, err, "%s: not a plan document", path)
	}
	if want := (&PlanDoc{}).SchemaID(); doc.Schema != want {
		return nil, apperr.New(apperr.Usage, "%s: schema %q, want %s (save prolexic plan's JSON output)", path, doc.Schema, want)
	}
	return &doc.Plan, nil
}
