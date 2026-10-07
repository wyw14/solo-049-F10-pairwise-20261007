package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"orbitlink/internal/store"
)

func newTestTrail(t *testing.T) (*Trail, store.Paths) {
	t.Helper()
	paths := store.NewPaths(t.TempDir())
	trail, err := NewTrail(store.NewAppendLog(paths))
	if err != nil {
		t.Fatal(err)
	}
	return trail, paths
}

func recordAll(t *testing.T, trail *Trail, events []Event) []Event {
	t.Helper()
	recorded := make([]Event, 0, len(events))
	for _, event := range events {
		value, err := trail.Record(event)
		if err != nil {
			t.Fatal(err)
		}
		recorded = append(recorded, value)
	}
	return recorded
}

func TestRecordAssignsMonotonicSeqAndLiveSource(t *testing.T) {
	trail, _ := newTestTrail(t)
	recorded := recordAll(t, trail, []Event{
		{Component: "pass", Action: "created", Subject: "PASS-1"},
		{Component: "rf", Action: "plan.applied", Subject: "RF-01", Fields: map[string]any{"pass_id": "PASS-1"}},
	})
	if recorded[0].Seq != 1 || recorded[1].Seq != 2 {
		t.Fatalf("expected seq 1,2 got %d,%d", recorded[0].Seq, recorded[1].Seq)
	}
	for _, event := range recorded {
		if event.Source != SourceLive {
			t.Fatalf("expected live source, got %q", event.Source)
		}
		if event.Severity != Info {
			t.Fatalf("expected default severity info, got %q", event.Severity)
		}
	}
}

func TestListFiltersPassOperationSeverityAndTimeRange(t *testing.T) {
	trail, _ := newTestTrail(t)
	base := time.Now().UTC()
	recordAll(t, trail, []Event{
		{Component: "pass", Action: "created", Subject: "PASS-1", At: base},
		{Component: "receiver", Action: "unlock.timeout", Subject: "RF-01", Severity: Warning, Operation: "op-7", Fields: map[string]any{"pass_id": "PASS-1"}, At: base.Add(time.Minute)},
		{Component: "receiver", Action: "unlocked", Subject: "RF-01", Operation: "op-8", Fields: map[string]any{"pass_id": "PASS-2"}, At: base.Add(2 * time.Minute)},
		{Component: "pass", Action: "finalized", Subject: "PASS-1", Severity: Critical, At: base.Add(3 * time.Minute)},
	})
	byPass := trail.List(Query{PassID: "PASS-1"})
	if len(byPass.Items) != 3 {
		t.Fatalf("pass filter returned %d events, want 3", len(byPass.Items))
	}
	byOperation := trail.List(Query{Operation: "op-7"})
	if len(byOperation.Items) != 1 || byOperation.Items[0].Action != "unlock.timeout" {
		t.Fatalf("operation filter returned %#v", byOperation.Items)
	}
	bySeverity := trail.List(Query{Severity: Critical})
	if len(bySeverity.Items) != 1 || bySeverity.Items[0].Action != "finalized" {
		t.Fatalf("severity filter returned %#v", bySeverity.Items)
	}
	byTime := trail.List(Query{Since: base.Add(30 * time.Second), Until: base.Add(90 * time.Second)})
	if len(byTime.Items) != 1 || byTime.Items[0].Action != "unlock.timeout" {
		t.Fatalf("time range filter returned %#v", byTime.Items)
	}
}

func TestCursorPagesAreStableWhileAppending(t *testing.T) {
	trail, _ := newTestTrail(t)
	recordAll(t, trail, []Event{
		{Component: "pass", Action: "created", Subject: "PASS-1"},
		{Component: "pass", Action: "extended", Subject: "PASS-1"},
		{Component: "pass", Action: "finalized", Subject: "PASS-1"},
	})
	first := trail.List(Query{Limit: 2})
	if len(first.Items) != 2 || first.NextCursor != 2 {
		t.Fatalf("first page: %d items, cursor %d", len(first.Items), first.NextCursor)
	}
	// New events arrive after the first page was read.
	recordAll(t, trail, []Event{
		{Component: "antenna", Action: "stowed", Subject: "ANT-01"},
		{Component: "antenna", Action: "claimed", Subject: "ANT-01"},
	})
	replayed := trail.List(Query{Limit: 2})
	if len(replayed.Items) != 2 || replayed.Items[0].Seq != first.Items[0].Seq || replayed.Items[1].Seq != first.Items[1].Seq {
		t.Fatal("already-read page shifted after concurrent appends")
	}
	second := trail.List(Query{After: first.NextCursor, Limit: 2})
	if len(second.Items) != 2 || second.Items[0].Action != "finalized" || second.Items[1].Action != "stowed" {
		t.Fatalf("second page: %#v", second.Items)
	}
	third := trail.List(Query{After: second.NextCursor, Limit: 2})
	if len(third.Items) != 1 || third.Items[0].Action != "claimed" {
		t.Fatalf("third page: %#v", third.Items)
	}
	if third.NextCursor != third.Items[0].Seq {
		t.Fatalf("cursor did not advance to last item: %d", third.NextCursor)
	}
	if empty := trail.List(Query{After: third.NextCursor}); len(empty.Items) != 0 || empty.NextCursor != third.NextCursor {
		t.Fatalf("exhausted trail should keep cursor, got %#v", empty)
	}
}

func TestRecoveryPreservesSeqSeveritySubjectAndMarksSource(t *testing.T) {
	paths := store.NewPaths(t.TempDir())
	trail, err := NewTrail(store.NewAppendLog(paths))
	if err != nil {
		t.Fatal(err)
	}
	recordAll(t, trail, []Event{
		{Component: "receiver", Action: "unlock.timeout", Subject: "RF-01", Severity: Warning, Operation: "op-1", Fields: map[string]any{"pass_id": "PASS-9"}},
		{Component: "pass", Action: "finalized", Subject: "PASS-9"},
	})
	recovered, err := NewTrail(store.NewAppendLog(paths))
	if err != nil {
		t.Fatal(err)
	}
	page := recovered.List(Query{})
	if len(page.Items) != 2 {
		t.Fatalf("recovered %d events, want 2", len(page.Items))
	}
	first := page.Items[0]
	if first.Seq != 1 || first.Source != SourceRecovered || first.Severity != Warning || first.Subject != "RF-01" || first.Operation != "op-1" {
		t.Fatalf("recovery lost event attributes: %#v", first)
	}
	if first.Component != "receiver" || first.Action != "unlock.timeout" {
		t.Fatalf("recovery mangled component/action: %#v", first)
	}
	// The sequence continues where the persisted log left off.
	next, err := recovered.Record(Event{Component: "pass", Action: "created", Subject: "PASS-10"})
	if err != nil {
		t.Fatal(err)
	}
	if next.Seq != 3 || next.Source != SourceLive {
		t.Fatalf("expected seq 3 live event, got %#v", next)
	}
}

func TestRecoveredGapsAreReportedWithinPageWindow(t *testing.T) {
	paths := store.NewPaths(t.TempDir())
	log := store.NewAppendLog(paths)
	at := time.Now().UTC()
	for _, seq := range []uint64{1, 2, 5, 6} {
		if err := log.Append(store.Event{ID: "e", Stream: "audit", Kind: "pass.created", At: at, Seq: seq, Subject: "PASS-1"}); err != nil {
			t.Fatal(err)
		}
	}
	trail, err := NewTrail(log)
	if err != nil {
		t.Fatal(err)
	}
	page := trail.List(Query{})
	if len(page.Items) != 4 {
		t.Fatalf("expected 4 events, got %d", len(page.Items))
	}
	if len(page.Gaps) != 1 || page.Gaps[0].From != 3 || page.Gaps[0].To != 4 {
		t.Fatalf("expected gap 3-4, got %#v", page.Gaps)
	}
	// Gaps are scoped to the queried window: a cursor past the gap sees none.
	rest := trail.List(Query{After: 4})
	if len(rest.Items) != 2 || len(rest.Gaps) != 0 {
		t.Fatalf("unexpected gaps after cursor: %#v", rest.Gaps)
	}
}

func TestRecoveryToleratesCorruptLogLines(t *testing.T) {
	paths := store.NewPaths(t.TempDir())
	trail, err := NewTrail(store.NewAppendLog(paths))
	if err != nil {
		t.Fatal(err)
	}
	recordAll(t, trail, []Event{{Component: "pass", Action: "created", Subject: "PASS-1"}})
	stream := paths.Events("audit")
	file, err := os.OpenFile(stream, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("{not-json\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := NewTrail(store.NewAppendLog(paths))
	if err != nil {
		t.Fatal(err)
	}
	if page := recovered.List(Query{}); len(page.Items) != 1 {
		t.Fatalf("corrupt line lost the stream: %#v", page.Items)
	}
	if _, err := recovered.Record(Event{Component: "pass", Action: "finalized", Subject: "PASS-1"}); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Clean(stream)); err != nil || info.Size() == 0 {
		t.Fatalf("stream not writable after recovery: %v", err)
	}
}
