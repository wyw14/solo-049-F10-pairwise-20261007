package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"orbitlink/internal/store"
)

func newTestTrail(t *testing.T) (*Trail, string) {
	t.Helper()
	root := t.TempDir()
	return NewTrail(store.NewAppendLog(store.NewPaths(root))), root
}

func recordEvent(t *testing.T, trail *Trail, event Event) Event {
	t.Helper()
	recorded, err := trail.Record(event)
	if err != nil {
		t.Fatal(err)
	}
	return recorded
}

func eventIDs(page Page) []string {
	ids := make([]string, 0, len(page.Items))
	for _, item := range page.Items {
		ids = append(ids, item.ID)
	}
	return ids
}

func TestQueryFiltersPassOperationSeverityAndTimeRange(t *testing.T) {
	trail, _ := newTestTrail(t)
	base := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	recordEvent(t, trail, Event{Component: "pass", Action: "created", Subject: "PASS-1", At: base})
	recordEvent(t, trail, Event{Component: "receiver", Action: "attempt.started", Subject: "ATT-1", At: base.Add(time.Minute), Fields: map[string]any{"pass_id": "PASS-1"}})
	recordEvent(t, trail, Event{Component: "receiver", Action: "unlock.timeout", Subject: "RF-01", Severity: Warning, At: base.Add(2 * time.Minute), Fields: map[string]any{"pass_id": "PASS-1"}})
	recordEvent(t, trail, Event{Component: "weather", Action: "stow.completed", Subject: "ANT-01", Operation: "OP-9", At: base.Add(3 * time.Minute)})
	recordEvent(t, trail, Event{Component: "weather", Action: "stow.inhibit-failed", Subject: "ANT-01", Severity: Critical, Operation: "OP-9", At: base.Add(4 * time.Minute)})

	// Pass filter matches the subject or a fields.pass_id reference.
	page := trail.Query(Query{PassID: "PASS-1"})
	if len(page.Items) != 3 {
		t.Fatalf("pass filter returned %d events, want 3", len(page.Items))
	}
	wantSources := []Source{{Component: "pass", Events: 1}, {Component: "receiver", Events: 2}}
	if len(page.Sources) != len(wantSources) {
		t.Fatalf("sources = %#v, want %#v", page.Sources, wantSources)
	}
	for i, source := range wantSources {
		if page.Sources[i] != source {
			t.Fatalf("sources = %#v, want %#v", page.Sources, wantSources)
		}
	}

	if page := trail.Query(Query{Operation: "OP-9"}); len(page.Items) != 2 {
		t.Fatalf("operation filter returned %d events, want 2", len(page.Items))
	}
	if page := trail.Query(Query{Severity: Critical}); len(page.Items) != 1 {
		t.Fatalf("severity filter returned %d events, want 1", len(page.Items))
	}
	if page := trail.Query(Query{MinSeverity: Warning}); len(page.Items) != 2 {
		t.Fatalf("min_severity filter returned %d events, want 2", len(page.Items))
	}
	page = trail.Query(Query{Since: base.Add(time.Minute), Until: base.Add(3 * time.Minute)})
	if len(page.Items) != 3 {
		t.Fatalf("time range filter returned %d events, want 3", len(page.Items))
	}
	// Bounds are inclusive.
	if page.Items[0].At != base.Add(time.Minute) || page.Items[2].At != base.Add(3*time.Minute) {
		t.Fatalf("time range bounds not inclusive: %#v", eventIDs(page))
	}
	// Filters compose.
	if page := trail.Query(Query{PassID: "PASS-1", MinSeverity: Warning}); len(page.Items) != 1 {
		t.Fatalf("combined filter returned %d events, want 1", len(page.Items))
	}
}

func TestQueryCursorPagesStayStableWhileRecording(t *testing.T) {
	trail, _ := newTestTrail(t)
	for range 5 {
		recordEvent(t, trail, Event{Component: "pass", Action: "tick", Subject: "PASS-1"})
	}
	first := trail.Query(Query{Limit: 2})
	if len(first.Items) != 2 || first.NextCursor == "" {
		t.Fatalf("first page = %d items, cursor %q; want 2 items and a cursor", len(first.Items), first.NextCursor)
	}
	if first.Items[0].Seq != 1 || first.Items[1].Seq != 2 {
		t.Fatalf("first page seqs = %d,%d, want 1,2", first.Items[0].Seq, first.Items[1].Seq)
	}
	firstIDs := eventIDs(first)

	// New events are recorded after the first page was read.
	for range 3 {
		recordEvent(t, trail, Event{Component: "pass", Action: "tick", Subject: "PASS-1"})
	}

	// Re-reading the same page returns exactly the same items.
	again := trail.Query(Query{Limit: 2})
	for i, id := range firstIDs {
		if again.Items[i].ID != id {
			t.Fatalf("first page shifted after new writes: %v -> %v", firstIDs, eventIDs(again))
		}
	}

	// Walking the cursor covers the remaining events without repeats.
	seen := map[string]bool{firstIDs[0]: true, firstIDs[1]: true}
	cursor := first.NextCursor
	walked := 0
	for cursor != "" {
		after, err := ParseCursor(cursor)
		if err != nil {
			t.Fatal(err)
		}
		page := trail.Query(Query{Limit: 2, After: after})
		for _, item := range page.Items {
			if seen[item.ID] {
				t.Fatalf("event %s returned twice", item.ID)
			}
			seen[item.ID] = true
			walked++
		}
		cursor = page.NextCursor
	}
	if walked != 6 {
		t.Fatalf("cursor walk returned %d events, want 6", walked)
	}
	if len(seen) != 8 {
		t.Fatalf("saw %d distinct events, want 8", len(seen))
	}
}

func TestQueryReportsGapsForDroppedEvents(t *testing.T) {
	trail, root := newTestTrail(t)
	recordEvent(t, trail, Event{Component: "pass", Action: "created", Subject: "PASS-1"})
	recordEvent(t, trail, Event{Component: "pass", Action: "extended", Subject: "PASS-1"})

	// Break the append log so the next record is dropped after its
	// sequence number was assigned: a directory where the stream file
	// belongs cannot be opened for writing.
	streamPath := filepath.Join(root, "events", "audit.jsonl")
	if err := os.Remove(streamPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(streamPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := trail.Record(Event{Component: "pass", Action: "lost", Subject: "PASS-1"}); err == nil {
		t.Fatal("expected the append to fail")
	}
	if err := os.Remove(streamPath); err != nil {
		t.Fatal(err)
	}
	recordEvent(t, trail, Event{Component: "recorder", Action: "started", Subject: "SEG-1", Fields: map[string]any{"pass_id": "PASS-1"}})
	recordEvent(t, trail, Event{Component: "pass", Action: "finalized", Subject: "PASS-1"})

	page := trail.Query(Query{})
	if len(page.Items) != 4 {
		t.Fatalf("returned %d events, want 4", len(page.Items))
	}
	if len(page.Gaps) != 1 || page.Gaps[0] != (Gap{FromSeq: 3, ToSeq: 3, Missing: 1}) {
		t.Fatalf("gaps = %#v, want one missing event at seq 3", page.Gaps)
	}

	// A filtered view whose range excludes the hole reports no gap.
	narrow := trail.Query(Query{Component: "recorder"})
	if len(narrow.Items) != 1 || len(narrow.Gaps) != 0 {
		t.Fatalf("narrow query = %d items, gaps %#v; want 1 item and no gaps", len(narrow.Items), narrow.Gaps)
	}
}

func TestParseCursor(t *testing.T) {
	if seq, err := ParseCursor(""); err != nil || seq != 0 {
		t.Fatalf("empty cursor = %d, %v; want 0, nil", seq, err)
	}
	seq, err := ParseCursor(EncodeCursor(41))
	if err != nil || seq != 41 {
		t.Fatalf("round trip = %d, %v; want 41, nil", seq, err)
	}
	if _, err := ParseCursor("seq:not-a-number"); err == nil {
		t.Fatal("expected an error for a non-numeric cursor")
	}
	if _, err := ParseCursor("41"); err == nil {
		t.Fatal("expected an error for a cursor without the prefix")
	}
}
