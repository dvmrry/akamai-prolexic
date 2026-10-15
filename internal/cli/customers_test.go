package cli

import (
	"strings"
	"testing"
)

func TestCustomers(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /prolexic-analytics/v2/customer/names", 200, `{"customerNames":[
	  {"name":"example-b","contractId":"C-EXAMPLE-2","accountName":"Example","inUse":false},
	  {"name":"example-a","contractId":"C-EXAMPLE","accountName":"Example","inUse":true}]}`)
	r := runCLI(t, ncfEnv(api.env()), "customers")
	if r.code != 0 {
		t.Fatalf("exit = %d: %s%s", r.code, r.stdout, r.stderr)
	}
	doc := decode[CustomersDoc](t, r.stdout, "prolexic.customers.v1")
	if len(doc.Customers) != 2 || doc.Customers[0].Name != "example-a" || !doc.Customers[0].InUse ||
		doc.Customers[1].ContractID != "C-EXAMPLE-2" || doc.Customers[1].InUse || doc.Customers[1].AccountName != "Example" {
		t.Errorf("customers = %+v", doc.Customers)
	}
	if r := runCLI(t, ncfEnv(api.env()), "customers", "--format", "text"); !strings.Contains(r.stdout, "example-b") || !strings.Contains(r.stdout, "false") {
		t.Errorf("text:\n%s", r.stdout)
	}
}

func TestCustomersEmptyIsAnEmptyList(t *testing.T) {
	api := newFakeAPI(t)
	api.json("GET /prolexic-analytics/v2/customer/names", 200, `{"customerNames":[]}`)
	r := runCLI(t, ncfEnv(api.env()), "customers")
	if r.code != 0 || !strings.Contains(r.stdout, `"customers": []`) {
		t.Errorf("exit %d:\n%s", r.code, r.stdout)
	}
}
