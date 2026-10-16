package mcpfront

import (
	"context"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/analytics"
	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
	"github.com/dvmrry/akamai-prolexic/internal/ncf/ncfapi"
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
		aliasesListTool,
		aliasShowTool,
		aliasVersionsTool,
		aclVersionsTool,
		aclShowTool,
		aclDeploymentTool,
		aclTestTool,
		managedACLTool,
		managedRuleHitsTool,
		ruleHitsListTool,
		ruleHitShowTool,
		attackShowTool,
		eventsTool,
		metricsTool,
		timeSeriesTool,
		protectedTool,
		customersTool,
		scrubCentersTool,
		routedSessionsTool,
		routedRoutesTool,
		routedHealthTool,
		targetsListTool,
		targetShowTool,
		fmtTool,
		removeTool,
		exportTool,
		verifyTool,
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
	Wait     *string  `json:"wait,omitempty" doc:"Keep checking until satisfied or this long has passed, e.g. 10m, at most 1h; default: check once."`
	Interval *string  `json:"interval,omitempty" default:"30s" doc:"Time between checks while waiting, at least 5s."`
}

var routedCheckTool = tool[routedCheckArgs]{
	name: "routed_check", title: "Prefix propagation check",
	description: "Checks, per BGP session, that a prefix is announced to Akamai (expect present) or withdrawn (expect absent). With wait, it keeps checking until satisfied or the time runs out.",
	run: func(ctx context.Context, f *front, a routedCheckArgs) (output.Document, error) {
		in := ops.RoutedCheckInput{Customers: a.Customers, Sites: a.Sites, Prefix: a.Prefix,
			Expect: orDefault(a.Expect, string(analytics.ExpectPresent))}
		var err error
		if a.Wait != nil {
			if in.Wait, err = duration("wait", *a.Wait); err != nil {
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
	File string `json:"file" doc:"The desired file, relative to the root."`
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
	MaxRemovals *int   `json:"maxRemovals,omitempty" default:"10" minimum:"0" maximum:"10" doc:"Most entries one alias may lose, from 0 up to the default: a plan made here can tighten the removal limit, never loosen it."`
	Out         string `json:"out,omitempty" doc:"Also save the plan's JSON to this file, relative to the root: a new file, or a saved plan to replace."`
}

var planTool = tool[planArgs]{
	name: "plan", title: "Plan the desired file against live",
	description: "Diffs the desired file against live state and runs every offline and live check, giving the changes, the findings and the plan's digest. Reads live state; with out it also writes the plan to that file. Applying a plan is not available here: it goes through a reviewed pull request and CI.",
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
		// CI's apply runs with the reviewed plan's settings, so an agent's plan
		// may only tighten them: the live own-space check always runs, and
		// the removal limit can't be raised or lifted. A person loosens them
		// deliberately, with the CLI.
		limit := orDefault(a.MaxRemovals, ncf.DefaultMaxRemovals)
		if limit < 0 || limit > ncf.DefaultMaxRemovals {
			return nil, apperr.New(apperr.Usage, "maxRemovals must be between 0 and %d here: a plan made by an agent can tighten the removal limit, not loosen it", ncf.DefaultMaxRemovals)
		}
		return output.Doc(f.rt.Plan(ctx, ops.PlanInput{File: p, MaxRemovals: limit, Out: out}))
	},
}

type aliasesListArgs struct {
	EditableOnly bool `json:"editableOnly,omitempty" doc:"Only customer-editable aliases, leaving out the Akamai-managed ones."`
}

var aliasesListTool = tool[aliasesListArgs]{
	name: "aliases_list", title: "Aliases",
	description: "Every alias of the account, without entries.",
	run: func(ctx context.Context, f *front, a aliasesListArgs) (output.Document, error) {
		return output.Doc(f.rt.Aliases(ctx, ops.AliasesInput{EditableOnly: a.EditableOnly}))
	},
}

// aliasRefArg names one alias: exactly one of name and id, which the
// operation checks.
type aliasRefArg struct {
	Name string `json:"name,omitempty" doc:"The alias name; give exactly one of name and id."`
	ID   int64  `json:"id,omitempty" doc:"The alias id; give exactly one of name and id."`
}

type aliasShowArgs struct {
	aliasRefArg
	Version string `json:"version,omitempty" doc:"The version id, e.g. V3; default the alias's active version."`
}

var aliasShowTool = tool[aliasShowArgs]{
	name: "alias_show", title: "Alias entries",
	description: "One alias's entries at a version (default the active version).",
	run: func(ctx context.Context, f *front, a aliasShowArgs) (output.Document, error) {
		return output.Doc(f.rt.Alias(ctx, ops.AliasInput{Name: a.Name, ID: a.ID, Version: a.Version}))
	},
}

var aliasVersionsTool = tool[aliasRefArg]{
	name: "alias_versions", title: "Alias version history",
	description: "One alias's version history.",
	run: func(ctx context.Context, f *front, a aliasRefArg) (output.Document, error) {
		return output.Doc(f.rt.AliasVersions(ctx, ops.AliasVersionsInput{Name: a.Name, ID: a.ID}))
	},
}

var aclVersionsTool = tool[struct{}]{
	name: "acl_versions", title: "ACL versions",
	description: "Every version of the Network Cloud Firewall ACL.",
	run: func(ctx context.Context, f *front, _ struct{}) (output.Document, error) {
		return output.Doc(f.rt.ACLVersions(ctx))
	},
}

type aclVersionArg struct {
	Version int `json:"version,omitempty" doc:"The ACL version number; 0 or absent: the version in production."`
}

var aclShowTool = tool[aclVersionArg]{
	name: "acl_show", title: "ACL rules",
	description: "One ACL version with its rules (default the version in production).",
	run: func(ctx context.Context, f *front, a aclVersionArg) (output.Document, error) {
		return output.Doc(f.rt.ACLShow(ctx, ops.ACLShowInput{Version: a.Version}))
	},
}

var aclDeploymentTool = tool[struct{}]{
	name: "acl_deployment", title: "ACL deployment",
	description: "The ACL's deployment state.",
	run: func(ctx context.Context, f *front, _ struct{}) (output.Document, error) {
		return output.Doc(f.rt.ACLDeployment(ctx))
	},
}

type aclTestArgs struct {
	aclVersionArg
	Packets []ncfapi.PacketTest `json:"packets" doc:"1 to 5 simulated packets, all of one IP family."`
}

var aclTestTool = tool[aclTestArgs]{
	name: "acl_test", title: "Test packets against the ACL",
	description: "Tests simulated packets against an ACL version (default the one in production) and returns, per packet, the decision and the first rule that matched. Nothing is changed.",
	run: func(ctx context.Context, f *front, a aclTestArgs) (output.Document, error) {
		return output.Doc(f.rt.ACLTest(ctx, ops.ACLTestInput{Version: a.Version, Packets: a.Packets}))
	},
}

type managedACLArgs struct {
	PolicyDomain string `json:"policyDomain" doc:"The policy domain."`
}

var managedACLTool = tool[managedACLArgs]{
	name: "managed_acl", title: "Managed ACL",
	description: "A policy domain's latest managed-services ACL version.",
	run: func(ctx context.Context, f *front, a managedACLArgs) (output.Document, error) {
		return output.Doc(f.rt.ManagedACL(ctx, ops.ManagedACLInput{PolicyDomain: a.PolicyDomain}))
	},
}

type managedRuleHitsArgs struct {
	windowArg
	PolicyDomain string `json:"policyDomain" doc:"The policy domain."`
	Rule         string `json:"rule,omitempty" doc:"One rule's id (its uuid); default every rule, with no time series."`
}

var managedRuleHitsTool = tool[managedRuleHitsArgs]{
	name: "managed_rule_hits", title: "Managed rule hits",
	description: "A policy domain's rule match statistics. With rule it also returns that rule's time series (default the last " + short(ops.ManagedRuleHitsDefaultSince) + "); a window needs a rule.",
	run: func(ctx context.Context, f *front, a managedRuleHitsArgs) (output.Document, error) {
		win, err := a.window()
		if err != nil {
			return nil, err
		}
		return output.Doc(f.rt.ManagedRuleHits(ctx, ops.ManagedRuleHitsInput{PolicyDomain: a.PolicyDomain, Rule: a.Rule, Window: win}))
	},
}

var ruleHitsListTool = tool[struct{}]{
	name: "rule_hits_list", title: "ACL rule hits",
	description: "Match statistics for every rule of the deployed ACL.",
	run: func(ctx context.Context, f *front, _ struct{}) (output.Document, error) {
		return output.Doc(f.rt.RuleHits(ctx))
	},
}

type ruleHitShowArgs struct {
	windowArg
	Rule string `json:"rule" doc:"The rule id (the ruleId that rule_hits_list returns)."`
}

var ruleHitShowTool = tool[ruleHitShowArgs]{
	name: "rule_hit_show", title: "ACL rule hit",
	description: "One rule's match statistics. With a window (since, or start and end) it also returns the rule's time series; without one, there is none.",
	run: func(ctx context.Context, f *front, a ruleHitShowArgs) (output.Document, error) {
		win, err := a.window()
		if err != nil {
			return nil, err
		}
		return output.Doc(f.rt.RuleHit(ctx, ops.RuleHitInput{Rule: a.Rule, Window: win}))
	},
}

type attackShowArgs struct {
	Customer string `json:"customer" doc:"The customer name the attack belongs to."`
	ID       int64  `json:"id" doc:"The attack id."`
}

var attackShowTool = tool[attackShowArgs]{
	name: "attack_show", title: "Attack detail",
	description: "One attack's detail report: a row per location and target.",
	run: func(ctx context.Context, f *front, a attackShowArgs) (output.Document, error) {
		return output.Doc(f.rt.Attack(ctx, ops.AttackInput{Customer: a.Customer, ID: a.ID}))
	},
}

type eventsArgs struct {
	customersArg
	windowArg
	CriticalOnly bool `json:"criticalOnly,omitempty" doc:"Only critical events."`
}

var eventsTool = tool[eventsArgs]{
	name: "events", title: "Events",
	description: "Critical events and events per customer name. With a window it keeps the events whose span overlaps it; without one it returns every event.",
	run: func(ctx context.Context, f *front, a eventsArgs) (output.Document, error) {
		win, err := a.window()
		if err != nil {
			return nil, err
		}
		return output.Doc(f.rt.Events(ctx, ops.EventsInput{Customers: a.Customers, CriticalOnly: a.CriticalOnly, Window: win}))
	},
}

type metricsArgs struct {
	customersArg
	windowArg
	Types   []string `json:"types" doc:"SERVICE:METRIC, or fbm:METRIC:PROTOCOL."`
	Subnet  string   `json:"subnet,omitempty" doc:"The subnet fbm types report on; fbm types need a subnet or an ip."`
	IP      string   `json:"ip,omitempty" doc:"The IP address fbm types report on."`
	Samples *int     `json:"samples,omitempty" default:"100" doc:"Data points to return, at least 1."`
}

var metricsTool = tool[metricsArgs]{
	name: "metrics", title: "Traffic metrics",
	description: "Traffic metrics per customer name in a time window (default the last " + short(ops.MetricsDefaultSince) + ").",
	run: func(ctx context.Context, f *front, a metricsArgs) (output.Document, error) {
		win, err := a.window()
		if err != nil {
			return nil, err
		}
		return output.Doc(f.rt.Metrics(ctx, ops.MetricsInput{Customers: a.Customers, Types: a.Types, Subnet: a.Subnet, IP: a.IP,
			Samples: orDefault(a.Samples, ops.MetricsDefaultSamples), Window: win}))
	},
}

type timeSeriesArgs struct {
	windowArg
	Destinations []string `json:"destinations" doc:"Addresses or CIDR blocks."`
	Locations    []string `json:"locations,omitempty" doc:"Data centers such as mia4, or agr for all aggregated; default agr."`
	Source       *string  `json:"source,omitempty" enum:"both,access_flow,border_flow" default:"both" doc:"both, access_flow (Akamai router) or border_flow (customer router)."`
	Sum          bool     `json:"sum,omitempty" doc:"Also return the aggregated data."`
	Samples      int      `json:"samples,omitempty" doc:"Timestamps to return; 0 or absent: all in the window."`
}

var timeSeriesTool = tool[timeSeriesArgs]{
	name: "time_series", title: "Flow time series",
	description: "Flow-based usage and attack traffic for destinations in a time window (default the last " + short(ops.TimeSeriesDefaultSince) + ").",
	run: func(ctx context.Context, f *front, a timeSeriesArgs) (output.Document, error) {
		win, err := a.window()
		if err != nil {
			return nil, err
		}
		return output.Doc(f.rt.TimeSeries(ctx, ops.TimeSeriesInput{Destinations: a.Destinations, Locations: a.Locations,
			Source: orDefault(a.Source, ops.TimeSeriesDefaultSource), Sum: a.Sum, Samples: a.Samples, Window: win}))
	},
}

var protectedTool = tool[customersArg]{
	name: "protected", title: "Protected space",
	description: "The prefixes and AS numbers treated as own space, per customer name: FBM subnets and BGP-session AS numbers.",
	run: func(ctx context.Context, f *front, a customersArg) (output.Document, error) {
		return output.Doc(f.rt.Protected(ctx, ops.ProtectedInput{Customers: a.Customers}))
	},
}

var customersTool = tool[struct{}]{
	name: "customers", title: "Customer names",
	description: "The customer names of the account, and which are in use.",
	run: func(ctx context.Context, f *front, _ struct{}) (output.Document, error) {
		return output.Doc(f.rt.Customers(ctx))
	},
}

var scrubCentersTool = tool[struct{}]{
	name: "scrub_centers", title: "Scrubbing centers",
	description: "The Prolexic scrubbing centers.",
	run: func(ctx context.Context, f *front, _ struct{}) (output.Document, error) {
		return output.Doc(f.rt.ScrubCenters(ctx))
	},
}

var routedSessionsTool = tool[customersArg]{
	name: "routed_sessions", title: "BGP sessions",
	description: "The BGP sessions of each customer name.",
	run: func(ctx context.Context, f *front, a customersArg) (output.Document, error) {
		return output.Doc(f.rt.RoutedSessions(ctx, ops.RoutedSessionsInput{Customers: a.Customers}))
	},
}

type routedRoutesArgs struct {
	customersArg
	Prefix string `json:"prefix,omitempty" doc:"Only routes for exactly this prefix; a bare address means /32 or /128. Default all."`
}

var routedRoutesTool = tool[routedRoutesArgs]{
	name: "routed_routes", title: "Announced routes",
	description: "The routes announced to Akamai per customer name, optionally only for one prefix.",
	run: func(ctx context.Context, f *front, a routedRoutesArgs) (output.Document, error) {
		return output.Doc(f.rt.RoutedRoutes(ctx, ops.RoutedRoutesInput{Customers: a.Customers, Prefix: a.Prefix}))
	},
}

var routedHealthTool = tool[customersArg]{
	name: "routed_health", title: "Tunnel health",
	description: "Healthy and total tunnels per location and router, per customer name.",
	run: func(ctx context.Context, f *front, a customersArg) (output.Document, error) {
		return output.Doc(f.rt.RoutedHealth(ctx, ops.RoutedHealthInput{Customers: a.Customers}))
	},
}

var targetsListTool = tool[struct{}]{
	name: "targets_list", title: "Network Health targets",
	description: "Every Network Health target of the account.",
	run: func(ctx context.Context, f *front, _ struct{}) (output.Document, error) {
		return output.Doc(f.rt.Targets(ctx))
	},
}

type targetShowArgs struct {
	ID string `json:"id" doc:"The target id."`
}

var targetShowTool = tool[targetShowArgs]{
	name: "target_show", title: "Network Health target",
	description: "One Network Health target.",
	run: func(ctx context.Context, f *front, a targetShowArgs) (output.Document, error) {
		return output.Doc(f.rt.Target(ctx, ops.TargetInput{ID: a.ID}))
	},
}

type fmtArgs struct {
	fileArg
	Check bool `json:"check,omitempty" doc:"Write nothing; a file that isn't in canonical form is reported as an outcome."`
}

var fmtTool = tool[fmtArgs]{
	name: "fmt", title: "Format the desired file", writes: true, local: true,
	description: "Rewrites the local desired file in canonical form, or with check only reports whether it is. No API calls. This changes only the file: a change reaches the firewall through a reviewed pull request and CI's apply.",
	run: func(_ context.Context, f *front, a fmtArgs) (output.Document, error) {
		p, err := f.path(a.File)
		if err != nil {
			return nil, err
		}
		return output.Doc(f.rt.Fmt(ops.FmtInput{File: p, Check: a.Check}))
	},
}

type removeArgs struct {
	fileArg
	Alias   string   `json:"alias" doc:"The alias to remove from, by name."`
	Entries []string `json:"entries" doc:"The entries to remove: prefixes, addresses, GEO::<country> or ASN::<number>."`
	Ticket  string   `json:"ticket" doc:"The ticket authorising the change."`
}

var removeTool = tool[removeArgs]{
	name: "remove", title: "Remove entries from the desired file", writes: true, local: true,
	description: "Removes entries from one alias of the local desired file and rewrites it in canonical form. Nothing is written on any error or blocking finding. This changes only the file: the change reaches the firewall through a reviewed pull request and CI's apply.",
	run: func(_ context.Context, f *front, a removeArgs) (output.Document, error) {
		p, err := f.path(a.File)
		if err != nil {
			return nil, err
		}
		return output.Doc(f.rt.Remove(ops.RemoveInput{File: p, RemoveRequest: ncf.RemoveRequest{Alias: a.Alias, Entries: a.Entries, Ticket: a.Ticket}}))
	},
}

type exportArgs struct {
	fileArg
	All  bool    `json:"all,omitempty" doc:"Also add the editable live aliases the file doesn't name."`
	Role *string `json:"role,omitempty" enum:"deny,allow" default:"deny" doc:"The role of an alias no deployed rule references; deployed rules decide the rest."`
}

var exportTool = tool[exportArgs]{
	name: "export", title: "Export live aliases to the desired file", writes: true,
	description: "Reads live state and writes the editable aliases to the local desired file in canonical form: a missing or empty file is bootstrapped, an existing one is updated to the live entries of the aliases it names. This changes only the file: the change reaches the firewall through a reviewed pull request and CI's apply.",
	run: func(ctx context.Context, f *front, a exportArgs) (output.Document, error) {
		p, err := f.path(a.File)
		if err != nil {
			return nil, err
		}
		return output.Doc(f.rt.Export(ctx, ops.ExportInput{File: p, All: a.All, Role: ncf.Role(orDefault(a.Role, string(ncf.RoleDeny)))}))
	},
}

type verifyArgs struct {
	Plan string `json:"plan" doc:"A saved plan's file, relative to the root."`
}

var verifyTool = tool[verifyArgs]{
	name: "verify", title: "Verify a saved plan",
	description: "Reads every alias in a saved plan fresh and checks the plan's end state. Reads only.",
	run: func(ctx context.Context, f *front, a verifyArgs) (output.Document, error) {
		p, err := f.path(a.Plan)
		if err != nil {
			return nil, err
		}
		return output.Doc(f.rt.Verify(ctx, ops.VerifyInput{Plan: p}))
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
