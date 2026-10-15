package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
	"github.com/dvmrry/akamai-prolexic/internal/edgegrid"
	"github.com/dvmrry/akamai-prolexic/internal/output"
	"github.com/dvmrry/akamai-prolexic/internal/version"
)

// DoctorDoc says which credentials resolved. It never contacts the network
// and never carries a credential value, or the API host (which embeds a
// token).
type DoctorDoc struct {
	output.Header
	Version version.Info   `json:"version"`
	Clients []ClientStatus `json:"clients"`
	Proxy   ProxyStatus    `json:"proxy"`
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

// ProxyStatus says whether a proxy is configured, never its URL (which can
// carry credentials).
type ProxyStatus struct {
	HTTPSProxy bool `json:"httpsProxy"`
	NoProxy    bool `json:"noProxy"`
}

func (*DoctorDoc) SchemaID() string { return "prolexic.doctor.v1" }

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
	_, err := fmt.Fprintf(w, "\nproxy: %s\n", proxy)
	return err
}

func newDoctorCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "show which credentials resolve (offline)",
		Long:  "Shows which credentials resolve for the read and write sections, and whether a proxy is configured. It never contacts the network and never prints a credential value or the API host.",
		Args:  cobra.NoArgs,
		RunE:  a.run(func(context.Context, []string) (output.Document, error) { return doctor(a) }),
	}
}

func doctor(a *app) (output.Document, error) {
	doc := &DoctorDoc{
		Version: version.Current(),
		Clients: []ClientStatus{a.clientStatus("read", a.section), a.clientStatus("write", a.writeSection)},
		Proxy: ProxyStatus{
			HTTPSProxy: a.env.Getenv("HTTPS_PROXY") != "" || a.env.Getenv("https_proxy") != "",
			NoProxy:    a.env.Getenv("NO_PROXY") != "" || a.env.Getenv("no_proxy") != "",
		},
	}
	// Missing write credentials are normal (read-only use, PR builds);
	// missing read credentials make every other command fail.
	if !doc.Clients[0].Resolved {
		return doc, apperr.New(apperr.Credentials, "read credentials not resolved")
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
