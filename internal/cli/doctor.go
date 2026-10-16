package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/edgegrid"
	"github.com/dvmrry/akamai-prolexic/internal/output"
	"github.com/dvmrry/akamai-prolexic/internal/version"
)

// DoctorDoc says which credentials resolved. Without --live it never contacts
// the network. It never carries a credential value, or the API host (which embeds a
// token).
type DoctorDoc struct {
	output.Header
	Version version.Info   `json:"version"`
	Clients []ClientStatus `json:"clients"`
	Proxy   ProxyStatus    `json:"proxy"`
	APIs    []APIStatus    `json:"apis,omitempty" doc:"With --live: one read per API, in the order ncf, analytics, networkHealth."`
}

// ClientStatus is one API client's resolution.
type ClientStatus struct {
	Role       string           `json:"role" enum:"read,write"`
	Section    string           `json:"section"`
	Resolved   bool             `json:"resolved"`
	Source     *edgegrid.Source `json:"source,omitempty"`
	AccountKey bool             `json:"accountKey" doc:"Whether an accountSwitchKey is set (not its value)."`
	Error      string           `json:"error,omitempty"`
}

// APIStatus is one API's live check: a single cheap read with the read
// credentials.
type APIStatus struct {
	API     string `json:"api" enum:"ncf,analytics,networkHealth"`
	OK      bool   `json:"ok"`
	Kind    string `json:"kind,omitempty" doc:"The apperr kind of the failure; empty when ok."`
	Message string `json:"message,omitempty"`
}

// ProxyStatus says whether a proxy is configured, never its URL (which can
// carry credentials).
type ProxyStatus struct {
	HTTPSProxy bool `json:"httpsProxy"`
	NoProxy    bool `json:"noProxy"`
}

func (*DoctorDoc) SchemaID() string { return "prolexic.doctor.v1" }

// Outcome: missing write credentials are normal (read-only use, PR builds);
// missing read credentials make every other command fail.
func (d *DoctorDoc) Outcome() error {
	if !d.Clients[0].Resolved {
		return apperr.New(apperr.Credentials, "read credentials not resolved")
	}
	var failed []string
	kind := apperr.Kind("")
	for _, s := range d.APIs {
		if s.OK {
			continue
		}
		k := apperr.Kind(s.Kind)
		switch {
		case kind == "":
			kind = k
		case kind != k:
			kind = apperr.Upstream
		}
		failed = append(failed, s.API)
	}
	if len(failed) == 0 {
		return nil
	}
	return apperr.New(kind, "%d of %d APIs failed: %s", len(failed), len(d.APIs), strings.Join(failed, ", "))
}

func (d *DoctorDoc) WriteText(w io.Writer) error {
	fmt.Fprintf(w, "prolexic %s\n\n", d.Version.Version)
	for _, c := range d.Clients {
		switch {
		case c.Resolved && c.Source.Kind == "env":
			fmt.Fprintf(w, "%-5s  [%s]  ok, from the environment\n", c.Role, c.Section)
		case c.Resolved:
			fmt.Fprintf(w, "%-5s  [%s]  ok, from %s\n", c.Role, c.Section, c.Source.Path)
		default:
			fmt.Fprintf(w, "%-5s  [%s]  not resolved: %s\n", c.Role, c.Section, c.Error)
		}
	}
	proxy := "none"
	if d.Proxy.HTTPSProxy {
		proxy = "HTTPS_PROXY is set"
	}
	if len(d.APIs) > 0 {
		fmt.Fprintln(w)
	}
	for _, s := range d.APIs {
		if s.OK {
			fmt.Fprintf(w, "%-12s  ok\n", s.API)
		} else {
			fmt.Fprintf(w, "%-12s  FAILED (%s): %s\n", s.API, s.Kind, s.Message)
		}
	}
	_, err := fmt.Fprintf(w, "\nproxy: %s\n", proxy)
	return err
}

func newDoctorCmd(a *app) *cobra.Command {
	var live bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "show which credentials resolve (offline unless --live)",
		Long:  "Shows which credentials resolve for the read and write sections, and whether a proxy is configured. It never prints a credential value or the API host. It is offline unless --live is set; --live also makes one read per API (NCF, Analytics, Network Health) with the read credentials and reports which APIs they can use.",
		Args:  cobra.NoArgs,
		RunE:  a.run(func(ctx context.Context, _ []string) (output.Document, error) { return doctor(ctx, a, live) }),
	}
	cmd.Flags().BoolVar(&live, "live", false, "make one read per API with the read credentials and report which APIs they can use")
	return cmd
}

func doctor(ctx context.Context, a *app, live bool) (output.Document, error) {
	doc := &DoctorDoc{
		Version: version.Current(),
		Clients: []ClientStatus{a.clientStatus("read", a.section), a.clientStatus("write", a.writeSection)},
		Proxy: ProxyStatus{
			HTTPSProxy: a.env.Getenv("HTTPS_PROXY") != "" || a.env.Getenv("https_proxy") != "",
			NoProxy:    a.env.Getenv("NO_PROXY") != "" || a.env.Getenv("no_proxy") != "",
		},
	}
	if live && doc.Clients[0].Resolved {
		doc.APIs = a.liveChecks(ctx)
	}
	return doc, nil
}

func (a *app) clientStatus(role, section string) ClientStatus {
	st := ClientStatus{Role: role, Section: section}
	c, src, err := a.credentials(section)
	if err != nil {
		st.Error = err.Error()
		return st
	}
	st.Resolved, st.Source, st.AccountKey = true, &src, c.AccountKey != ""
	return st
}

// liveChecks makes one read per API, in turn. The transport's own retries
// apply and nothing more.
func (a *app) liveChecks(ctx context.Context) []APIStatus {
	return []APIStatus{
		apiStatus("ncf", "NCF", func() error {
			s, err := a.ncfRead()
			if err != nil {
				return err
			}
			_, err = s.ListAliases(ctx)
			return err
		}),
		apiStatus("analytics", "Analytics", func() error {
			c, err := a.analytics()
			if err != nil {
				return err
			}
			_, err = c.CustomerNames(ctx)
			return err
		}),
		apiStatus("networkHealth", "Network Health", func() error {
			c, err := a.networkHealth()
			if err != nil {
				return err
			}
			_, err = c.Targets(ctx)
			return err
		}),
	}
}

// apiStatus runs one check. The message is written here, never taken from
// the error, which can name the API host.
func apiStatus(id, name string, check func() error) APIStatus {
	err := check()
	if err == nil {
		return APIStatus{API: id, OK: true}
	}
	kind := apperr.KindOf(err)
	st := APIStatus{API: id, Kind: string(kind)}
	switch kind {
	case apperr.Credentials:
		st.Message = fmt.Sprintf("the read credentials can't use this API; ask for %s read access on the API client", name)
	case apperr.NotFound:
		st.Message = fmt.Sprintf("%s answered not found; check that the API is enabled for this account", name)
	case apperr.Cancelled:
		st.Message = "cancelled before the check finished"
	default:
		st.Message = fmt.Sprintf("the %s read failed; retry, or check the network and proxy", name)
	}
	return st
}
