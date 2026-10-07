package audit

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"orbitlink/internal/store"
)

const defaultPageLimit = 100

type Trail struct {
	log *store.AppendLog
	mu  sync.RWMutex
	all []Event
	seq uint64
}

// NewTrail recovers previously persisted audit events so the sequence — and
// therefore cursor pagination — stays stable across restarts.
func NewTrail(log *store.AppendLog) (*Trail, error) {
	trail := &Trail{log: log, all: make([]Event, 0, 128)}
	persisted, _, err := log.ReadAll("audit")
	if err != nil {
		return nil, fmt.Errorf("recover audit trail: %w", err)
	}
	for _, stored := range persisted {
		event := eventFromStored(stored)
		if event.Seq == 0 || event.Seq <= trail.seq {
			event.Seq = trail.seq + 1
		}
		trail.seq = event.Seq
		trail.all = append(trail.all, event)
	}
	return trail, nil
}

func (t *Trail) Record(event Event) (Event, error) {
	if event.Component == "" || event.Action == "" {
		return Event{}, fmt.Errorf("audit component and action are required")
	}
	if event.ID == "" {
		event.ID = uuid.NewString()
	}
	if event.At.IsZero() {
		event.At = time.Now().UTC()
	}
	if event.Severity == "" {
		event.Severity = Info
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	event.Seq = t.seq + 1
	event.Source = SourceLive
	if err := t.log.Append(store.Event{
		ID: event.ID, Stream: "audit", Kind: event.Component + "." + event.Action,
		At: event.At, Seq: event.Seq, Severity: string(event.Severity), Subject: event.Subject,
		Fields: event.Fields, Operation: event.Operation,
	}); err != nil {
		return Event{}, err
	}
	t.seq = event.Seq
	t.all = append(t.all, event)
	return event, nil
}

// List returns events matching the query in ascending sequence order. The
// cursor (Query.After) refers to sequence numbers, which only ever increase,
// so appends happening between pages cannot shift pages already read.
func (t *Trail) List(query Query) Page {
	t.mu.RLock()
	defer t.mu.RUnlock()
	limit := query.Limit
	if limit <= 0 {
		limit = defaultPageLimit
	}
	page := Page{Items: make([]Event, 0, limit), NextCursor: query.After}
	for _, event := range t.all {
		if event.Seq <= query.After {
			continue
		}
		if !matches(query, event) {
			continue
		}
		page.Items = append(page.Items, event)
		if len(page.Items) == limit {
			break
		}
	}
	if len(page.Items) > 0 {
		page.NextCursor = page.Items[len(page.Items)-1].Seq
		page.Gaps = t.gapsBetween(query.After+1, page.NextCursor)
	}
	return page
}

// gapsBetween reports sequence numbers in [from, to] that are absent from the
// trail. Events merely filtered out of the page still exist in the trail and
// do not count as gaps.
func (t *Trail) gapsBetween(from, to uint64) []Gap {
	if from > to {
		return nil
	}
	var gaps []Gap
	expected := from
	for _, event := range t.all {
		if event.Seq < from {
			continue
		}
		if event.Seq > to {
			break
		}
		if event.Seq > expected {
			gaps = append(gaps, Gap{From: expected, To: event.Seq - 1})
		}
		expected = event.Seq + 1
	}
	return gaps
}

func matches(query Query, event Event) bool {
	if query.Component != "" && event.Component != query.Component {
		return false
	}
	if query.Subject != "" && event.Subject != query.Subject {
		return false
	}
	if query.Operation != "" && event.Operation != query.Operation {
		return false
	}
	if query.Severity != "" && event.Severity != query.Severity {
		return false
	}
	if query.PassID != "" && event.Subject != query.PassID && event.Fields["pass_id"] != query.PassID {
		return false
	}
	if !query.Since.IsZero() && event.At.Before(query.Since) {
		return false
	}
	if !query.Until.IsZero() && event.At.After(query.Until) {
		return false
	}
	return true
}

func eventFromStored(stored store.Event) Event {
	component, action, _ := strings.Cut(stored.Kind, ".")
	severity := Severity(stored.Severity)
	if severity == "" {
		severity = Info
	}
	return Event{
		ID: stored.ID, At: stored.At, Seq: stored.Seq, Source: SourceRecovered,
		Component: component, Action: action, Severity: severity,
		Operation: stored.Operation, Subject: stored.Subject, Fields: stored.Fields,
	}
}
