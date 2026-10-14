package analytics

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
)

// Event kinds of an EventRow.
const (
	KindCritical = "critical"
	KindEvent    = "event"
)

// CriticalEvent is one entry of the critical events list. Times are the
// wire's UNIX epoch seconds (UTC).
type CriticalEvent struct {
	EventID          string `json:"eventId,omitempty"`
	AttackID         string `json:"attackId,omitempty"`
	Summary          string `json:"summary,omitempty"`
	Description      string `json:"description,omitempty"`
	Notes            string `json:"notes,omitempty"`
	Source           string `json:"source,omitempty"`
	Location         string `json:"location,omitempty"`
	Node             string `json:"node,omitempty"`
	Instance         string `json:"instance,omitempty"`
	InterfaceName    string `json:"interfaceName,omitempty"`
	IP               string `json:"ip,omitempty"`
	SiteName         string `json:"siteName,omitempty"`
	SiteType         string `json:"siteType,omitempty"`
	SiteCustomerName string `json:"siteCustomerName,omitempty"`
	Count            int64  `json:"count,omitempty"`
	Importance       int64  `json:"importance,omitempty"`
	State            int64  `json:"state,omitempty"`
	Acknowledged     int64  `json:"acknowledged,omitempty"`
	FirstOccur       int64  `json:"firstOccur,omitempty" doc:"Epoch seconds UTC."`
	RecentOccur      int64  `json:"recentOccur,omitempty" doc:"Epoch seconds UTC."`
	Expires          int64  `json:"expires,omitempty" doc:"Epoch seconds UTC."`
}

// EventInfo is the detail of an Event. The traffic breakdowns are kept as the
// API sends them: their shapes drift from the spec between event kinds.
type EventInfo struct {
	AttackID            string          `json:"attackId,omitempty"`
	AttackEventID       string          `json:"attackEventId,omitempty"`
	AttackType          string          `json:"attackType,omitempty"`
	EventTicketID       string          `json:"eventTicketId,omitempty"`
	AlertInfo           string          `json:"alertInfo,omitempty"`
	Location            string          `json:"location,omitempty"`
	DestinationIPs      string          `json:"destinationIPs,omitempty"`
	StartTime           int64           `json:"startTime,omitempty" doc:"Epoch seconds UTC."`
	LastOccurred        int64           `json:"lastOccurred,omitempty" doc:"Epoch seconds UTC."`
	EndTime             json.RawMessage `json:"endTime,omitempty" doc:"Epoch seconds UTC, or false while the event is ongoing."`
	TopSourceIPs        json.RawMessage `json:"topSourceIPs,omitempty"`
	TopNetProtocols     json.RawMessage `json:"topNetProtocols,omitempty"`
	TopDestinationPorts json.RawMessage `json:"topDestinationPorts,omitempty"`
}

// Event is one entry of the events list (alerts and attacks).
type Event struct {
	EventTitle     string     `json:"eventTitle,omitempty"`
	EventType      string     `json:"eventType" doc:"alert or attack."`
	Service        string     `json:"service,omitempty" doc:"Mitigation for attacks; for alerts abm, abr, arb, bgp, fbm, int or man."`
	Severity       int64      `json:"severity,omitempty"`
	IsOngoing      bool       `json:"isOngoing"`
	EventStartTime int64      `json:"eventStartTime" doc:"Epoch seconds UTC."`
	EventEndTime   int64      `json:"eventEndTime,omitempty" doc:"Epoch seconds UTC."`
	EventInfo      *EventInfo `json:"eventInfo,omitempty"`
}

// EventRow is one critical event or event of one customer name. Exactly one
// of Critical and Event is set, as Kind says.
type EventRow struct {
	Customer string         `json:"customer" doc:"The customer name queried; added by prolexic."`
	Kind     string         `json:"kind" enum:"critical,event"`
	Time     string         `json:"time,omitempty" doc:"When it began (critical: most recent occurrence), RFC 3339 UTC."`
	Critical *CriticalEvent `json:"critical,omitempty"`
	Event    *Event         `json:"event,omitempty"`

	at, from, to int64 // epoch seconds: sort key, span start, span end (MaxInt64 while ongoing)
}

// At is the row's time as epoch seconds, the key to sort by.
func (r EventRow) At() int64 { return r.at }

// Overlaps reports whether the row's span intersects [start, end].
func (r EventRow) Overlaps(start, end time.Time) bool {
	return r.from <= end.Unix() && r.to >= start.Unix()
}

func rfc3339(sec int64) string {
	if sec <= 0 {
		return ""
	}
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}

// CriticalEvents lists one customer name's critical events. The API takes no
// time window.
func (c *Client) CriticalEvents(ctx context.Context, customer string) ([]EventRow, error) {
	path, err := contractPath("/critical-events/contract/", customer, "")
	if err != nil {
		return nil, err
	}
	var resp struct {
		envelope
		Data []CriticalEvent `json:"data"`
	}
	if err := c.c.Do(ctx, akamai.Request{Method: http.MethodGet, Path: path}, &resp); err != nil {
		return nil, err
	}
	if err := resp.err("critical events"); err != nil {
		return nil, err
	}
	rows := make([]EventRow, len(resp.Data))
	for i := range resp.Data {
		e := &resp.Data[i]
		at := e.RecentOccur
		if at == 0 {
			at = e.FirstOccur
		}
		from, to := e.FirstOccur, e.RecentOccur
		if from == 0 {
			from = at
		}
		if to == 0 {
			to = at
		}
		rows[i] = EventRow{Customer: customer, Kind: KindCritical, Time: rfc3339(at), Critical: e, at: at, from: from, to: to}
	}
	return rows, nil
}

// Events lists one customer name's events (alerts and attacks). The API takes
// no time window.
func (c *Client) Events(ctx context.Context, customer string) ([]EventRow, error) {
	path, err := contractPath("/events/contract/", customer, "")
	if err != nil {
		return nil, err
	}
	var resp struct {
		envelope
		Data []Event `json:"data"`
	}
	if err := c.c.Do(ctx, akamai.Request{Method: http.MethodGet, Path: path}, &resp); err != nil {
		return nil, err
	}
	if err := resp.err("events"); err != nil {
		return nil, err
	}
	rows := make([]EventRow, len(resp.Data))
	for i := range resp.Data {
		e := &resp.Data[i]
		to := e.EventEndTime
		if e.IsOngoing || to == 0 {
			to = math.MaxInt64
		}
		rows[i] = EventRow{Customer: customer, Kind: KindEvent, Time: rfc3339(e.EventStartTime), Event: e, at: e.EventStartTime, from: e.EventStartTime, to: to}
	}
	return rows, nil
}
