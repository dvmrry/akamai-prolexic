package analytics

import (
	"cmp"
	"slices"
	"strings"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// MetricsMaxSpan is the longest window POST /metrics accepts.
const MetricsMaxSpan = 90 * 24 * time.Hour

// MetricTypeSyntax is the form of one metric type, for help and errors.
const MetricTypeSyntax = "SERVICE:METRIC, or fbm:METRIC:PROTOCOL"

// metricServices are the non-FBM services of the request and their metrics.
var metricServices = map[string][]string{
	"connect":        {"bandwidthIn", "packetsIn"},
	"mitigationPost": {"packets", "bandwidth"},
	"mitigationPre":  {"packets", "bandwidth"},
	"proxy":          {"latency", "bandwidthIn", "bandwidthOut", "connections", "packetsOut", "requests", "packetsIn"},
	"routed":         {"bandwidthIn", "packetsIn"},
}

var fbmProtocols = []string{"total", "icmp", "igmp", "udp", "tcp"}

// MetricQuery selects what POST /metrics returns for one customer name: the
// services and their metrics, the FBM metrics, a window of at most
// MetricsMaxSpan and a sample count. Only ParseMetricQuery makes one, so
// Metrics never sends a query that wasn't checked, whichever front built it.
type MetricQuery struct {
	services map[string][]string
	fbm      []FBMMetric
	start    time.Time
	end      time.Time
	samples  int
	ok       bool
}

// Services maps a service (connect, mitigationPost, mitigationPre, proxy,
// routed) to its sorted metric names. FBM metrics are not included.
func (q MetricQuery) Services() map[string][]string {
	out := make(map[string][]string, len(q.services))
	for k, v := range q.services {
		out[k] = slices.Clone(v)
	}
	return out
}

// FBM returns the Flow Based Monitoring metrics, sorted by metric then protocol.
func (q MetricQuery) FBM() []FBMMetric { return slices.Clone(q.fbm) }

// Start is the window start.
func (q MetricQuery) Start() time.Time { return q.start }

// End is the window end.
func (q MetricQuery) End() time.Time { return q.end }

// Samples is the number of data points requested (at least 1).
func (q MetricQuery) Samples() int { return q.samples }

// ParseMetricQuery checks a metrics request. Each type is SERVICE:METRIC or
// fbm:METRIC:PROTOCOL; duplicates collapse. FBM types need exactly one of
// subnet or ip, and subnet and ip apply to FBM types only. The window must be
// positive and at most MetricsMaxSpan; samples at least 1. Errors are usage
// errors naming the bad value.
func ParseMetricQuery(types []string, subnet, ip string, start, end time.Time, samples int) (MetricQuery, error) {
	if len(types) == 0 {
		return MetricQuery{}, apperr.New(apperr.Usage, "no metric types: want %s", MetricTypeSyntax)
	}
	if subnet != "" && ip != "" {
		return MetricQuery{}, apperr.New(apperr.Usage, "subnet and ip are exclusive")
	}
	services := map[string][]string{}
	var fbm []FBMMetric
	for _, t := range types {
		parts := strings.Split(t, ":")
		svc := parts[0]
		if svc == "fbm" {
			if len(parts) != 3 || !slices.Contains([]string{"bandwidth", "packets"}, parts[1]) || !slices.Contains(fbmProtocols, parts[2]) {
				return MetricQuery{}, apperr.New(apperr.Usage, "metric type %q: want fbm:bandwidth|packets:%s", t, strings.Join(fbmProtocols, "|"))
			}
			m := FBMMetric{Metric: parts[1], Protocol: parts[2], Subnet: subnet, IP: ip}
			if !slices.Contains(fbm, m) {
				fbm = append(fbm, m)
			}
			continue
		}
		allowed, ok := metricServices[svc]
		if !ok || len(parts) != 2 || !slices.Contains(allowed, parts[1]) {
			return MetricQuery{}, apperr.New(apperr.Usage, "metric type %q: want %s", t, MetricTypeSyntax)
		}
		if !slices.Contains(services[svc], parts[1]) {
			services[svc] = append(services[svc], parts[1])
		}
	}
	if (subnet != "" || ip != "") && len(fbm) == 0 {
		return MetricQuery{}, apperr.New(apperr.Usage, "subnet and ip apply to fbm types only")
	}
	if len(fbm) > 0 && subnet == "" && ip == "" {
		// The API rejects every such request (400 ILLEGAL_ARGUMENT): catch it here.
		return MetricQuery{}, apperr.New(apperr.Usage, "fbm types need a subnet or an ip")
	}
	if samples < 1 {
		return MetricQuery{}, apperr.New(apperr.Usage, "samples %d: must be at least 1", samples)
	}
	if !start.Before(end) {
		return MetricQuery{}, apperr.New(apperr.Usage, "the window starts at %s, not before its end %s", start.Format(time.RFC3339), end.Format(time.RFC3339))
	}
	if end.Sub(start) > MetricsMaxSpan {
		return MetricQuery{}, apperr.New(apperr.Usage, "the window is longer than the API's maximum of %d days", int(MetricsMaxSpan/(24*time.Hour)))
	}
	for _, ms := range services {
		slices.Sort(ms)
	}
	slices.SortFunc(fbm, func(x, y FBMMetric) int {
		return cmp.Or(cmp.Compare(x.Metric, y.Metric), cmp.Compare(x.Protocol, y.Protocol))
	})
	return MetricQuery{services: services, fbm: fbm, start: start, end: end, samples: samples, ok: true}, nil
}
