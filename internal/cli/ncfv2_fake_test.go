package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
)

// fakeNCF is a stateful NCF v2 account. Registered on a fakeAPI it serves
// the alias list, the version endpoints, activation, deployment-status and
// stats. An activation reaches production after prodLag alias-list polls,
// and deployment-status reports PROCESSING until then.
type fakeNCF struct {
	mu      sync.Mutex
	aliases []*fakeAlias
	// Creates records each create-version request body, decoded.
	Creates []map[string]any
	// Activated records "id/version" for each activation.
	Activated []string
}

type fakeAlias struct {
	ID       int64
	Name     string
	Type     string
	IPVer    string
	Editable bool
	Count    int        // entriesCount of a managed alias
	Versions [][]string // Versions[i] is version V(i+1); empty for managed aliases
	Active   int        // 1-based; 0 for managed aliases
	Prod     int
	lag      int
}

const prodLag = 1

func vname(i int) string { return "V" + strconv.Itoa(max(i, 1)) }

func (a *fakeAlias) names() []string {
	out := []string{}
	for i := len(a.Versions); i >= 1; i-- {
		out = append(out, vname(i))
	}
	return out
}

func (a *fakeAlias) count(i int) int {
	if i == 0 {
		return a.Count
	}
	return len(a.Versions[i-1])
}

func (a *fakeAlias) listItem() map[string]any {
	return map[string]any{
		"accountId": "A-EXAMPLE", "aliasId": a.ID, "aliasName": a.Name, "aliasType": a.Type,
		"ipVersion": a.IPVer, "isCustomerEditable": a.Editable, "inUse": true,
		"activeVersion": map[string]any{"version": vname(a.Active), "entriesCount": a.count(a.Active)},
		"prodVersion":   map[string]any{"version": vname(a.Prod), "entriesCount": a.count(a.Prod), "aclRules": []int{1}},
		"versions":      a.names(),
		"createdBy":     "example-user",
	}
}

func (a *fakeAlias) versionBody(i int) map[string]any {
	entries := []string{}
	if i > 0 {
		entries = a.Versions[i-1]
	}
	return map[string]any{
		"aliasId": a.ID, "aliasName": a.Name, "aliasType": a.Type, "ipVersion": a.IPVer,
		"version": vname(i), "isActive": i == a.Active, "entries": entries, "entriesCount": len(entries),
	}
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		json.NewEncoder(w).Encode(v)
	}
}

// ncfV2 registers the fake's routes and returns its state. Editable aliases
// get the version endpoints; managed ones are listed only, so a fetch of
// their entries fails the test with a 404.
func (f *fakeAPI) ncfV2(aliases ...*fakeAlias) *fakeNCF {
	n := &fakeNCF{aliases: aliases}
	const base = "/network-cloud-firewall/v2"
	f.routes["GET "+base+"/aliases"] = func(w http.ResponseWriter, _ *http.Request) {
		n.mu.Lock()
		defer n.mu.Unlock()
		out := []map[string]any{}
		for _, a := range n.aliases {
			if a.Prod != a.Active { // an activation is propagating
				if a.lag > 0 {
					a.lag--
				} else {
					a.Prod = a.Active
				}
			}
			out = append(out, a.listItem())
		}
		reply(w, 200, out)
	}
	f.routes["GET "+base+"/acls/versions/deployment-status"] = func(w http.ResponseWriter, _ *http.Request) {
		n.mu.Lock()
		defer n.mu.Unlock()
		sets := []map[string]any{{"deploymentStatus": "PRODUCTION", "version": 7, "rulesDeployStats": map[string]any{"failed": 0, "installed": 10, "total": 10}}}
		for _, a := range n.aliases {
			if a.Prod != a.Active {
				sets = append(sets, map[string]any{"deploymentStatus": "PROCESSING", "version": 8, "rulesDeployStats": map[string]any{"failed": 0}})
				break
			}
		}
		reply(w, 200, map[string]any{"accountId": "A-EXAMPLE", "ruleSets": sets})
	}
	f.json("GET "+base+"/stats", 200, `{"aliases":[
	  {"type":"SOURCE","limit":100,"enabledCount":3,"disabledCount":1},
	  {"type":"BIG","limit":5,"enabledCount":1,"disabledCount":0}]}`)

	for _, a := range aliases {
		if !a.Editable {
			continue
		}
		p := base + "/aliases/" + strconv.FormatInt(a.ID, 10) + "/versions"
		f.routes["GET "+p+"/active"] = func(w http.ResponseWriter, _ *http.Request) {
			n.mu.Lock()
			defer n.mu.Unlock()
			reply(w, 200, a.versionBody(a.Active))
		}
		f.routes["GET "+p] = func(w http.ResponseWriter, _ *http.Request) {
			n.mu.Lock()
			defer n.mu.Unlock()
			content := []map[string]any{}
			for i := len(a.Versions); i >= 1; i-- {
				content = append(content, map[string]any{"aliasId": a.ID, "aliasName": a.Name, "version": vname(i), "isActive": i == a.Active, "entriesCount": len(a.Versions[i-1])})
			}
			reply(w, 200, map[string]any{"content": content, "last": true})
		}
		f.routes["POST "+p] = func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			var req struct {
				Entries  []string `json:"entries"`
				IsActive bool     `json:"isActive"`
			}
			var raw map[string]any
			if json.Unmarshal(body, &req) != nil || json.Unmarshal(body, &raw) != nil {
				reply(w, 400, map[string]any{"title": "Bad Request"})
				return
			}
			n.mu.Lock()
			defer n.mu.Unlock()
			n.Creates = append(n.Creates, raw)
			a.Versions = append(a.Versions, req.Entries)
			if req.IsActive {
				a.Active = len(a.Versions)
			}
			reply(w, 201, a.versionBody(len(a.Versions)))
		}
		for i := 1; i <= 12; i++ {
			f.routes["GET "+p+"/"+vname(i)] = func(w http.ResponseWriter, _ *http.Request) {
				n.mu.Lock()
				defer n.mu.Unlock()
				if i > len(a.Versions) {
					reply(w, 404, map[string]any{"title": "Not Found"})
					return
				}
				reply(w, 200, a.versionBody(i))
			}
			f.routes["PATCH "+p+"/"+vname(i)+"/activate"] = func(w http.ResponseWriter, _ *http.Request) {
				n.mu.Lock()
				defer n.mu.Unlock()
				if i > len(a.Versions) {
					reply(w, 404, map[string]any{"title": "Not Found"})
					return
				}
				n.Activated = append(n.Activated, fmt.Sprintf("%d/%s", a.ID, vname(i)))
				a.Active, a.lag = i, prodLag
				w.WriteHeader(204)
			}
		}
	}
	return n
}

// editableAlias is an editable SOURCE alias at V1 holding entries.
func editableAlias(id int64, name, ipVersion string, entries ...string) *fakeAlias {
	return &fakeAlias{ID: id, Name: name, Type: "SOURCE", IPVer: ipVersion, Editable: true, Versions: [][]string{entries}, Active: 1, Prod: 1}
}

// managedAlias is an Akamai-managed BIG alias; its entries are never served.
func managedAlias(id int64, name string, count int) *fakeAlias {
	return &fakeAlias{ID: id, Name: name, Type: "BIG", IPVer: "V4", Count: count}
}
