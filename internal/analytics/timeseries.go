package analytics

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// TimeSeriesPoint is one value of a destination's facet. Key is the map key
// the API used, normally an epoch timestamp.
type TimeSeriesPoint struct {
	Destination string `json:"destination"`
	Facet       string `json:"facet" doc:"The report facet; aggregatedData holds the sums."`
	Key         string `json:"key" doc:"The key the API used, normally epoch seconds."`
	Time        Epoch  `json:"time,omitempty" doc:"Key read as an epoch time, seconds UTC (normalised); absent when the key isn't one."`
	Value       Number `json:"value"`
}

// TimeSeries returns the flattened points of GET /time-series-data, sorted by
// destination, facet, then time (then key). A query with samples 0 omits samplingSize, so the API returns
// everything in the window. A 404 means no data. A response
// entry that isn't a map of maps of numbers is skipped.
func (c *Client) TimeSeries(ctx context.Context, q TimeSeriesQuery) ([]TimeSeriesPoint, error) {
	if !q.ok {
		return nil, apperr.New(apperr.Bug, "TimeSeries: query not from ParseTimeSeriesQuery")
	}
	v := url.Values{}
	v.Set("destinations", strings.Join(q.destinations, ","))
	v.Set("locations", strings.Join(q.locations, ","))
	v.Set("source", q.source)
	v.Set("sum", strconv.FormatBool(q.sum))
	v.Set("startTime", strconv.FormatInt(q.start.Unix(), 10))
	v.Set("endTime", strconv.FormatInt(q.end.Unix(), 10))
	if q.samples > 0 {
		v.Set("samplingSize", strconv.Itoa(q.samples))
	}
	var resp map[string]json.RawMessage
	if err := c.c.Do(ctx, akamai.Request{Method: http.MethodGet, Path: basePath + "/time-series-data", Query: v}, &resp); err != nil {
		if apperr.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []TimeSeriesPoint
	for dest, raw := range resp {
		var facets map[string]map[string]Number
		if json.Unmarshal(raw, &facets) != nil {
			continue
		}
		for facet, points := range facets {
			for key, val := range points {
				p := TimeSeriesPoint{Destination: dest, Facet: facet, Key: key, Value: val}
				if n, err := strconv.ParseInt(key, 10, 64); err == nil {
					p.Time = fromNumber(n)
				}
				out = append(out, p)
			}
		}
	}
	slices.SortFunc(out, func(x, y TimeSeriesPoint) int {
		if c := strings.Compare(x.Destination, y.Destination); c != 0 {
			return c
		}
		if c := strings.Compare(x.Facet, y.Facet); c != 0 {
			return c
		}
		if x.Time != y.Time {
			if x.Time < y.Time {
				return -1
			}
			return 1
		}
		return strings.Compare(x.Key, y.Key)
	})
	return out, nil
}
