package analytics

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
)

// ScrubCenters lists the active scrub centers (GET /scrub-centers), sorted and
// deduplicated. A 404 means none. Entries that aren't strings are skipped.
func (c *Client) ScrubCenters(ctx context.Context) ([]string, error) {
	var raw []json.RawMessage
	if err := c.c.Do(ctx, akamai.Request{Method: http.MethodGet, Path: basePath + "/scrub-centers"}, &raw); err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, r := range raw {
		var s string
		if json.Unmarshal(r, &s) == nil && s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out, nil
}
