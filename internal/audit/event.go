package audit

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Severity string

const (
	Info     Severity = "info"
	Warning  Severity = "warning"
	Critical Severity = "critical"
)

// Rank orders severities so minimum-severity filters can compare levels.
func Rank(severity Severity) (int, bool) {
	switch severity {
	case Info:
		return 1, true
	case Warning:
		return 2, true
	case Critical:
		return 3, true
	}
	return 0, false
}

type Event struct {
	Seq       uint64         `json:"seq"`
	ID        string         `json:"id"`
	At        time.Time      `json:"at"`
	Component string         `json:"component"`
	Action    string         `json:"action"`
	Severity  Severity       `json:"severity"`
	Operation string         `json:"operation,omitempty"`
	Subject   string         `json:"subject,omitempty"`
	Fields    map[string]any `json:"fields,omitempty"`
}

// Query filters the trail. After is a cursor position: only events with a
// higher sequence number are returned, so pages already read never shift
// when new events are recorded.
type Query struct {
	Component   string
	Subject     string
	PassID      string
	Operation   string
	Severity    Severity
	MinSeverity Severity
	Since       time.Time
	Until       time.Time
	After       uint64
	Limit       int
}

// Source summarizes which component produced the matched events.
type Source struct {
	Component string `json:"component"`
	Events    int    `json:"events"`
}

// Gap marks a run of sequence numbers assigned to events that could not be
// persisted, so readers know the trail is incomplete there.
type Gap struct {
	FromSeq uint64 `json:"from_seq"`
	ToSeq   uint64 `json:"to_seq"`
	Missing int    `json:"missing"`
}

// Page is one stable cursor page plus provenance and gap metadata. Sources
// and Gaps describe the whole filtered range, independent of the cursor.
type Page struct {
	Items      []Event  `json:"items"`
	NextCursor string   `json:"next_cursor,omitempty"`
	Sources    []Source `json:"sources"`
	Gaps       []Gap    `json:"gaps"`
}

const cursorPrefix = "seq:"

// EncodeCursor renders the opaque cursor for the position after seq.
func EncodeCursor(seq uint64) string {
	return cursorPrefix + strconv.FormatUint(seq, 10)
}

// ParseCursor decodes a cursor produced by EncodeCursor. An empty cursor
// addresses the start of the trail.
func ParseCursor(value string) (uint64, error) {
	if value == "" {
		return 0, nil
	}
	rest, found := strings.CutPrefix(value, cursorPrefix)
	if !found {
		return 0, fmt.Errorf("invalid audit cursor %q", value)
	}
	seq, err := strconv.ParseUint(rest, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid audit cursor %q", value)
	}
	return seq, nil
}
