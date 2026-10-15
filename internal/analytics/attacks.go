package analytics

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/dvmrry/akamai-prolexic/internal/akamai"
	"github.com/dvmrry/akamai-prolexic/internal/apperr"
)

// envelope is the status wrapper of the report-style endpoints (attacks,
// events, metric types). A response that says status=false is a failure even
// on HTTP 200; a response that omits the field is taken as fine.
type envelope struct {
	CurrentContract string `json:"currentContract"`
	Status          *bool  `json:"status"`
	StatusMsg       string `json:"statusMsg"`
}

func (e envelope) err(what string) error {
	if e.Status != nil && !*e.Status {
		return apperr.New(apperr.Upstream, "%s: the API reported failure: %s", what, e.StatusMsg)
	}
	return nil
}

// contractPath builds a path with the customer name as the {contract}
// segment. akamai.Request.Path is an unescaped path, so the name goes in as
// is and the transport escapes it; akamai.PathSegment refuses a name that
// can't be one segment.
func contractPath(prefix, customer, suffix string) (string, error) {
	c, err := akamai.PathSegment("customer name", customer)
	if err != nil {
		return "", err
	}
	return basePath + prefix + c + suffix, nil
}

// Destination is a targeted address or subnet of an attack.
type Destination struct {
	IP      string `json:"ip"`
	Netmask int    `json:"netmask"`
}

// Peak is one location's peak statistics of an attack.
type Peak struct {
	Location    string `json:"location"`
	PeakID      int64  `json:"peakId"`
	Bandwidth   int64  `json:"bandwidth"`
	PPS         int64  `json:"pps"`
	Connections int64  `json:"connections,omitempty"`
}

// Attack is one attack report. Times are the wire's UNIX epoch seconds (UTC).
type Attack struct {
	Customer               string        `json:"customer" doc:"The customer name queried; added by prolexic."`
	AttackID               int64         `json:"attackId"`
	CustomerShortName      string        `json:"customerShortName,omitempty"`
	TicketID               int64         `json:"ticketId,omitempty"`
	EventID                int64         `json:"eventId"`
	EventType              string        `json:"eventType,omitempty" doc:"alert or attack."`
	EventTypes             []string      `json:"eventTypes" doc:"The attack types."`
	StartTime              Epoch         `json:"startTime" doc:"Attack start, epoch seconds UTC (normalised; 0 when the API sends a value prolexic can't read)."`
	EndTime                Epoch         `json:"endTime,omitempty" doc:"Attack end, epoch seconds UTC (normalised; 0 when the API sends a value prolexic can't read); absent while it is ongoing."`
	EventStartTime         Epoch         `json:"eventStartTime" doc:"Epoch seconds UTC (normalised; 0 when the API sends a value prolexic can't read)."`
	EventEndTime           Epoch         `json:"eventEndTime,omitempty" doc:"Epoch seconds UTC (normalised; 0 when the API sends a value prolexic can't read)."`
	EventStartTimeAsString string        `json:"eventStartTimeAsString" doc:"yyyy-MM-dd HH:mm:ss, as the API reports it."`
	EventEndTimeAsString   string        `json:"eventEndTimeAsString" doc:"yyyy-MM-dd HH:mm:ss, as the API reports it."`
	DestinationPort        string        `json:"destinationPort,omitempty"`
	Destinations           []Destination `json:"destinations,omitempty"`
	Peaks                  []Peak        `json:"peaks,omitempty"`
}

// AttackReports lists one customer name's attacks between start and end.
// The API rejects over-long spans with an invalid start/end error; that
// error is returned as is. A 404 means the window holds no attacks: zero
// rows, not a failure.
func (c *Client) AttackReports(ctx context.Context, customer string, start, end time.Time) ([]Attack, error) {
	path, err := contractPath("/attack-reports/contract/", customer,
		"/start/"+strconv.FormatInt(start.Unix(), 10)+"/end/"+strconv.FormatInt(end.Unix(), 10))
	if err != nil {
		return nil, err
	}
	var resp struct {
		envelope
		Data []Attack `json:"data"`
	}
	if err := c.c.Do(ctx, akamai.Request{Method: http.MethodGet, Path: path}, &resp); err != nil {
		// Live answers 404 NOT_FOUND, not an empty list, for a window with no attacks.
		if apperr.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if err := resp.err("attack reports"); err != nil {
		return nil, err
	}
	for i := range resp.Data {
		resp.Data[i].Customer = customer
	}
	return resp.Data, nil
}

// AttackRow is one location's row of a single attack's detail report.
type AttackRow struct {
	Customer        string `json:"customer" doc:"The customer name queried; added by prolexic."`
	AttackID        int64  `json:"attackId"`
	AttackTypeName  string `json:"attackTypeName,omitempty"`
	EventID         int64  `json:"eventId"`
	TicketID        int64  `json:"ticketId,omitempty"`
	Location        string `json:"location" doc:"Where in the Prolexic network the attack was seen."`
	IP              string `json:"ip" doc:"The target address."`
	Netmask         int    `json:"netmask"`
	DestinationPort Text   `json:"destinationPort,omitempty"`
	StartTime       Epoch  `json:"startTime" doc:"Epoch seconds UTC (normalised; 0 when the API sends a value prolexic can't read)."`
	EndTime         Epoch  `json:"endTime,omitempty" doc:"Epoch seconds UTC (normalised; 0 when the API sends a value prolexic can't read)."`
	EventStartTime  Epoch  `json:"eventStartTime,omitempty" doc:"Epoch seconds UTC (normalised; 0 when the API sends a value prolexic can't read)."`
	EventEndTime    Epoch  `json:"eventEndTime,omitempty" doc:"Epoch seconds UTC (normalised; 0 when the API sends a value prolexic can't read)."`
	EventPeakID     int64  `json:"eventPeakId,omitempty"`
	EventBw         int64  `json:"eventBw" doc:"Peak bandwidth of the event."`
	EventPps        int64  `json:"eventPps" doc:"Peak packets per second of the event."`
	EventCON        int64  `json:"eventCON,omitempty" doc:"Peak connections of the event."`
}

// Attack returns the detail rows of one attack of one customer name.
func (c *Client) Attack(ctx context.Context, customer string, attackID int64) ([]AttackRow, error) {
	path, err := contractPath("/attack-report/contract/", customer, "/attack-id/"+strconv.FormatInt(attackID, 10))
	if err != nil {
		return nil, err
	}
	var resp struct {
		envelope
		Data []AttackRow `json:"data"`
	}
	if err := c.c.Do(ctx, akamai.Request{Method: http.MethodGet, Path: path}, &resp); err != nil {
		return nil, err
	}
	if err := resp.err("attack report"); err != nil {
		return nil, err
	}
	for i := range resp.Data {
		resp.Data[i].Customer = customer
	}
	return resp.Data, nil
}
