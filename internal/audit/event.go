package audit

import "time"

type Severity string

const (
	Info     Severity = "info"
	Warning  Severity = "warning"
	Critical Severity = "critical"
)

// Source records where an event served by the trail came from: recorded live
// by this process, or recovered from the persisted event log at startup.
type Source string

const (
	SourceLive      Source = "live"
	SourceRecovered Source = "recovered"
)

type Event struct {
	ID        string         `json:"id"`
	At        time.Time      `json:"at"`
	Seq       uint64         `json:"seq"`
	Source    Source         `json:"source"`
	Component string         `json:"component"`
	Action    string         `json:"action"`
	Severity  Severity       `json:"severity"`
	Operation string         `json:"operation,omitempty"`
	Subject   string         `json:"subject,omitempty"`
	Fields    map[string]any `json:"fields,omitempty"`
}

// Query selects a page of events. Events are returned in ascending Seq order.
// After is a stable cursor: only events with Seq > After are returned, so
// pages already read never shift while new events are appended.
type Query struct {
	Component string
	Subject   string
	PassID    string
	Operation string
	Severity  Severity
	Since     time.Time
	Until     time.Time
	After     uint64
	Limit     int
}

// Gap is a range of sequence numbers [From, To] missing from the trail
// within the queried window, e.g. events lost to log corruption.
type Gap struct {
	From uint64 `json:"from"`
	To   uint64 `json:"to"`
}

// Page is one stable page of audit events. NextCursor is the Seq to pass as
// Query.After for the following page; it never moves backwards, so concurrent
// appends cannot shift pages that were already read.
type Page struct {
	Items      []Event `json:"items"`
	NextCursor uint64  `json:"next_cursor"`
	Gaps       []Gap   `json:"gaps,omitempty"`
}
