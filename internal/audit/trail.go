package audit

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"orbitlink/internal/store"
)

const (
	// DefaultPageSize applies when a query does not set a limit.
	DefaultPageSize = 50
	// MaxPageSize bounds a single page so one query cannot drain the trail.
	MaxPageSize = 500
)

type Trail struct {
	log     *store.AppendLog
	mu      sync.RWMutex
	all     []Event
	nextSeq uint64
	holes   []uint64
}

func NewTrail(log *store.AppendLog) *Trail {
	return &Trail{log: log, all: make([]Event, 0, 128)}
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
	// The sequence number is assigned before persisting, and the append
	// happens inside the same critical section, so in-memory order, log
	// order, and sequence order always agree. A failed append leaves the
	// sequence number in holes instead of silently renumbering later events.
	t.mu.Lock()
	t.nextSeq++
	event.Seq = t.nextSeq
	if err := t.log.Append(store.Event{
		ID: event.ID, Stream: "audit", Kind: event.Component + "." + event.Action,
		At: event.At, Fields: event.Fields, Operation: event.Operation,
	}); err != nil {
		t.holes = append(t.holes, event.Seq)
		t.mu.Unlock()
		return Event{}, err
	}
	t.all = append(t.all, event)
	t.mu.Unlock()
	return event, nil
}

// Query returns one stable page of the filtered trail. Events are ordered
// by sequence number; passing the previous page's NextCursor back as
// Query.After yields the next page. Because sequence numbers are assigned
// monotonically at record time and events are never mutated or removed,
// re-issuing a page already read returns exactly the same items even while
// new events are being recorded.
func (t *Trail) Query(query Query) Page {
	t.mu.RLock()
	defer t.mu.RUnlock()
	limit := query.Limit
	switch {
	case limit <= 0:
		limit = DefaultPageSize
	case limit > MaxPageSize:
		limit = MaxPageSize
	}
	filtered := make([]Event, 0, len(t.all))
	for _, event := range t.all {
		if matchesFilters(query, event) {
			filtered = append(filtered, event)
		}
	}
	page := Page{
		Items:   []Event{},
		Sources: sourcesOf(filtered),
		Gaps:    gapsWithin(t.holes, filtered),
	}
	from := 0
	for from < len(filtered) && filtered[from].Seq <= query.After {
		from++
	}
	remaining := filtered[from:]
	end := len(remaining)
	if end > limit {
		end = limit
	}
	page.Items = append(page.Items, remaining[:end]...)
	if len(remaining) > limit {
		page.NextCursor = EncodeCursor(remaining[end-1].Seq)
	}
	return page
}

func matchesFilters(query Query, event Event) bool {
	if query.Component != "" && event.Component != query.Component {
		return false
	}
	if query.Subject != "" && event.Subject != query.Subject {
		return false
	}
	// A pass owns events either directly (subject) or by reference
	// (fields.pass_id, used by receiver/rf/scheduler/recorder events).
	if query.PassID != "" && event.Subject != query.PassID && event.Fields["pass_id"] != query.PassID {
		return false
	}
	if query.Operation != "" && event.Operation != query.Operation {
		return false
	}
	if query.Severity != "" && event.Severity != query.Severity {
		return false
	}
	if query.MinSeverity != "" {
		rank, ok := Rank(event.Severity)
		minimum, valid := Rank(query.MinSeverity)
		if !ok || (valid && rank < minimum) {
			return false
		}
	}
	if !query.Since.IsZero() && event.At.Before(query.Since) {
		return false
	}
	if !query.Until.IsZero() && event.At.After(query.Until) {
		return false
	}
	return true
}

func sourcesOf(events []Event) []Source {
	counts := make(map[string]int)
	for _, event := range events {
		counts[event.Component]++
	}
	sources := make([]Source, 0, len(counts))
	for component, count := range counts {
		sources = append(sources, Source{Component: component, Events: count})
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].Component < sources[j].Component })
	return sources
}

// gapsWithin coalesces dropped sequence numbers that fall inside the
// sequence range covered by the filtered events. Holes outside that range
// cannot be attributed to the query and are not reported.
func gapsWithin(holes []uint64, filtered []Event) []Gap {
	if len(holes) == 0 || len(filtered) == 0 {
		return []Gap{}
	}
	low, high := filtered[0].Seq, filtered[len(filtered)-1].Seq
	gaps := make([]Gap, 0)
	for _, seq := range holes {
		if seq < low || seq > high {
			continue
		}
		if n := len(gaps); n > 0 && seq == gaps[n-1].ToSeq+1 {
			gaps[n-1].ToSeq = seq
			gaps[n-1].Missing++
		} else {
			gaps = append(gaps, Gap{FromSeq: seq, ToSeq: seq, Missing: 1})
		}
	}
	return gaps
}
