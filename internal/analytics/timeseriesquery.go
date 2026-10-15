package analytics

import (
	"regexp"
	"slices"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// locationRE is the API's own pattern for one location.
var locationRE = regexp.MustCompile(`^([a-z]{3}[0-9]|agr)$`)

// TimeSeriesSources are the router types GET /time-series-data accepts.
var TimeSeriesSources = []string{"both", "access_flow", "border_flow"}

// TimeSeriesQuery is GET /time-series-data's query. Only ParseTimeSeriesQuery
// makes one, so TimeSeries never sends a query that wasn't checked.
type TimeSeriesQuery struct {
	destinations []string
	locations    []string
	source       string
	sum          bool
	samples      int
	start        time.Time
	end          time.Time
	ok           bool
}

// Destinations are the addresses or CIDR blocks, as given.
func (q TimeSeriesQuery) Destinations() []string { return slices.Clone(q.destinations) }

// Locations are the data centers; agr when none were given.
func (q TimeSeriesQuery) Locations() []string { return slices.Clone(q.locations) }

// Source is both, access_flow or border_flow.
func (q TimeSeriesQuery) Source() string { return q.source }

// Sum reports whether the aggregatedData facet is also returned.
func (q TimeSeriesQuery) Sum() bool { return q.sum }

// Samples is the number of timestamps requested; 0 means all in the window.
func (q TimeSeriesQuery) Samples() int { return q.samples }

// Start is the window start.
func (q TimeSeriesQuery) Start() time.Time { return q.start }

// End is the window end.
func (q TimeSeriesQuery) End() time.Time { return q.end }

// ParseTimeSeriesQuery checks a time-series request. There must be at least
// one destination, each an address or CIDR block; locations default to agr and
// each is a data center like mia4 or agr; source is one of TimeSeriesSources;
// samples is not negative (0 means all); start must be before end. Errors are
// usage errors naming the bad value.
func ParseTimeSeriesQuery(destinations, locations []string, source string, sum bool, samples int, start, end time.Time) (TimeSeriesQuery, error) {
	if len(destinations) == 0 {
		return TimeSeriesQuery{}, apperr.New(apperr.Usage, "no destinations")
	}
	for _, d := range destinations {
		if _, err := ParsePrefix(d); err != nil {
			return TimeSeriesQuery{}, apperr.New(apperr.Usage, "destination %q: not an address or CIDR block", d)
		}
	}
	if len(locations) == 0 {
		locations = []string{"agr"}
	}
	for _, l := range locations {
		if !locationRE.MatchString(l) {
			return TimeSeriesQuery{}, apperr.New(apperr.Usage, "location %q: want a data center like mia4, or agr", l)
		}
	}
	if !slices.Contains(TimeSeriesSources, source) {
		return TimeSeriesQuery{}, apperr.New(apperr.Usage, "source %q: want both, access_flow or border_flow", source)
	}
	if samples < 0 {
		return TimeSeriesQuery{}, apperr.New(apperr.Usage, "samples %d: can't be negative", samples)
	}
	if !start.Before(end) {
		return TimeSeriesQuery{}, apperr.New(apperr.Usage, "the window starts at %s, not before its end %s", start.Format(time.RFC3339), end.Format(time.RFC3339))
	}
	return TimeSeriesQuery{
		destinations: slices.Clone(destinations), locations: slices.Clone(locations), source: source,
		sum: sum, samples: samples, start: start, end: end, ok: true,
	}, nil
}
