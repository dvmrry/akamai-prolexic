package cli

import (
	"github.com/dvmrry/akamai-prolexic/internal/jsonschema"
	"github.com/dvmrry/akamai-prolexic/internal/ncf"
	"github.com/dvmrry/akamai-prolexic/internal/output"
)

// documents lists every Document the CLI can emit. Each has a committed
// schema at schemas/<SchemaID>.json; TestSchemas fails when a type and its
// schema drift apart (`make schemas` regenerates them). Add new documents
// here.
func documents() []output.Document {
	return []output.Document{
		&output.ErrorDoc{},
		&AliasesDoc{},
		&AliasDoc{},
		&AliasVersionsDoc{},
		&ApplyDoc{},
		&AttackDoc{},
		&AttacksDoc{},
		&ChangeDoc{},
		&EventsDoc{},
		&ExportDoc{},
		&FmtDoc{},
		&MetricsDoc{},
		&PlanDoc{},
		&DoctorDoc{},
		&ProtectedDoc{},
		&RoutedCheckDoc{},
		&RoutedHealthDoc{},
		&RoutedRoutesDoc{},
		&RoutedSessionsDoc{},
		&ScrubCentersDoc{},
		&StatusDoc{},
		&TargetDoc{},
		&TargetsDoc{},
		&TimeSeriesDoc{},
		&VersionDoc{},
		&ValidateDoc{},
	}
}

// inputs lists the schema'd files the CLI reads, by schema id.
func inputs() map[string]any {
	return map[string]any{ncf.DesiredSchemaID: &ncf.File{}}
}

// Schemas renders every published schema, keyed by schema id.
func Schemas() (map[string][]byte, error) {
	out := map[string][]byte{}
	add := func(id string, v any) error {
		b, err := jsonschema.Marshal(jsonschema.For(v, id, ""))
		out[id] = b
		return err
	}
	for _, d := range documents() {
		if err := add(d.SchemaID(), d); err != nil {
			return nil, err
		}
	}
	for id, v := range inputs() {
		if err := add(id, v); err != nil {
			return nil, err
		}
	}
	return out, nil
}
