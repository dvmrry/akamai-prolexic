package mcpfront

import (
	"context"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/ncf"
	"github.com/dvmrry/akamai-prolexic/internal/ops"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// tools are every tool the front offers. There is deliberately no apply:
// see the package comment.
func tools() []registrar {
	return []registrar{
		statusTool,
		routedCheckTool,
		attacksTool,
		validateTool,
		addTool,
		planTool,
	}
}

var statusTool = tool[struct{}]{
	name: "status", title: "Firewall status",
	description: "The account's Network Cloud Firewall state: the deployed ACL version and its health, every alias with its active and production versions, and the alias limits.",
	run: func(ctx context.Context, f *front, _ struct{}) (output.Document, error) {
		return output.Doc(f.rt.Status(ctx))
	},
}

type routedCheckArgs struct {
	customersArg
	Sites    []string `json:"sites,omitempty" doc:"Only sessions in these data centers; default all."`
	Prefix   string   `json:"prefix" doc:"The prefix to check; a bare address means /32 or /128."`
	Expect   *string  `json:"expect,omitempty" enum:"present,absent" default:"present" doc:"present: every expected BGP session carries the prefix; absent: none does."`
	Wait     string   `json:"wait,omitempty" doc:"Keep checking until satisfied or this long has passed, e.g. 10m; default: check once."`
	Interval *string  `json:"interval,omitempty" default:"30s" doc:"Time between checks while waiting."`
}

var routedCheckTool = tool[routedCheckArgs]{
	name: "routed_check", title: "Prefix propagation check",
	description: "Checks, per BGP session, that a prefix is announced to Akamai (expect present) or withdrawn (expect absent). With wait, it keeps checking until satisfied or the time runs out.",
	run: func(ctx context.Context, f *front, a routedCheckArgs) (output.Document, error) {
		in := ops.RoutedCheckInput{Customers: a.Customers, Sites: a.Sites, Prefix: a.Prefix,
			Expect: orDefault(a.Expect, "present")}
		var err error
		if a.Wait != "" {
			if in.Wait, err = duration("wait", a.Wait); err != nil {
				return nil, err
			}
		}
		if in.Interval, err = duration("interval", orDefault(a.Interval, ops.DefaultCheckInterval.String())); err != nil {
			return nil, err
		}
		return output.Doc(f.rt.RoutedCheck(ctx, in))
	},
}

type attacksArgs struct {
	customersArg
	windowArg
}

var attacksTool = tool[attacksArgs]{
	name: "attacks_list", title: "Attack reports",
	description: "Attack reports per customer name in a time window (default the last " + short(ops.AttacksDefaultSince) + "), with each attack's types and targets.",
	run: func(ctx context.Context, f *front, a attacksArgs) (output.Document, error) {
		win, err := a.window()
		if err != nil {
			return nil, err
		}
		return output.Doc(f.rt.Attacks(ctx, ops.AttacksInput{Customers: a.Customers, Window: win}))
	},
}

type fileArg struct {
	File string `json:"file" doc:"The desired file, relative to the working directory."`
}

var validateTool = tool[fileArg]{
	name: "validate", title: "Validate the desired file", local: true,
	description: "Offline checks of the desired file: entries, own space, bogons, metadata, canonical form. No API calls.",
	run: func(_ context.Context, f *front, a fileArg) (output.Document, error) {
		p, err := f.path(a.File)
		if err != nil {
			return nil, err
		}
		return output.Doc(f.rt.Validate(ops.ValidateInput{File: p}))
	},
}

type addArgs struct {
	fileArg
	Alias   string   `json:"alias" doc:"The alias to add to, by name."`
	Entries []string `json:"entries" doc:"Prefixes, addresses, GEO::<country> or ASN::<number>."`
	Ticket  string   `json:"ticket" doc:"The ticket authorising the change."`
	Reason  string   `json:"reason" doc:"Why the entries are added."`
	Expires string   `json:"expires,omitempty" doc:"YYYY-MM-DD after which the entries are flagged as expired."`
}

var addTool = tool[addArgs]{
	name: "add", title: "Add entries to the desired file", writes: true, local: true,
	description: "Adds entries, with ticket, reason and date metadata, to one alias of the local desired file, and rewrites it in canonical form. Nothing is written on any error, or on a warning about an added entry. This changes only the file: the change reaches the firewall through a reviewed pull request and CI's apply.",
	run: func(_ context.Context, f *front, a addArgs) (output.Document, error) {
		p, err := f.path(a.File)
		if err != nil {
			return nil, err
		}
		in := ops.AddInput{File: p}
		in.Alias, in.Entries, in.Ticket, in.Reason, in.Expires = a.Alias, a.Entries, a.Ticket, a.Reason, a.Expires
		return output.Doc(f.rt.Add(in))
	},
}

type planArgs struct {
	fileArg
	MaxRemovals      *int   `json:"maxRemovals,omitempty" default:"10" doc:"Most entries one alias may lose; -1 for no limit."`
	SkipLiveOwnSpace bool   `json:"skipLiveOwnSpace,omitempty" doc:"Leave Prolexic Analytics' protected prefixes and own AS numbers out of the own-space checks; the plan records it."`
	Out              string `json:"out,omitempty" doc:"Also save the plan's JSON to this file, relative to the working directory, for review and CI."`
}

var planTool = tool[planArgs]{
	name: "plan", title: "Plan the desired file against live",
	description: "Diffs the desired file against live state and runs every offline and live check, giving the changes, the findings and the plan's digest. Reads only; with out it also saves the plan. Applying a plan is not available here: it goes through a reviewed pull request and CI.",
	writes:      true,
	run: func(ctx context.Context, f *front, a planArgs) (output.Document, error) {
		p, err := f.path(a.File)
		if err != nil {
			return nil, err
		}
		out, err := f.path(a.Out)
		if err != nil {
			return nil, err
		}
		return output.Doc(f.rt.Plan(ctx, ops.PlanInput{File: p, MaxRemovals: orDefault(a.MaxRemovals, ncf.DefaultMaxRemovals), SkipLiveOwnSpace: a.SkipLiveOwnSpace, Out: out}))
	},
}

// short renders a default window for a description: 24h, not 24h0m0s.
func short(d time.Duration) string {
	s := d.String()
	for _, z := range []string{"0s", "0m"} {
		if len(s) > len(z) && s[len(s)-len(z):] == z {
			s = s[:len(s)-len(z)]
		}
	}
	return s
}
