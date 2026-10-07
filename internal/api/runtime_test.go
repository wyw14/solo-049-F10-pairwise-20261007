package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"orbitlink/internal/audit"
	stationclock "orbitlink/internal/clock"
	passsvc "orbitlink/internal/pass"
	"orbitlink/internal/receiver"
	"orbitlink/internal/rf"
	"orbitlink/internal/satellite"
	"orbitlink/internal/weather"
)

func TestOperationsPagesAndAPIsUseRuntimeState(t *testing.T) {
	runtime := newTestRuntime(t)
	router, err := NewRouter(runtime)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(router)
	defer server.Close()
	for _, target := range []string{"/passes", "/antennas", "/rf-chains", "/recordings", "/healthz", "/api/passes", "/api/antennas", "/api/rf-chains", "/api/recordings"} {
		response, err := server.Client().Get(server.URL + target)
		if err != nil {
			t.Fatalf("GET %s: %v", target, err)
		}
		if response.StatusCode != http.StatusOK {
			t.Fatalf("GET %s returned %d", target, response.StatusCode)
		}
		_ = response.Body.Close()
	}
}

func TestPassRevisionAcquisitionAndRecordingFlow(t *testing.T) {
	runtime := newTestRuntime(t)
	value := runtime.Passes.List()[0]
	if _, err := runtime.RF.Apply(rf.Plan{PassID: value.ID, ChainID: "RF-01", CenterHz: 2_245_000_000, DopplerHz: 12_000, Polarization: rf.RightCircular}); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.RF.Apply(rf.Plan{PassID: value.ID, ChainID: "RF-02", CenterHz: 2_245_000_000, DopplerHz: 12_050, Polarization: rf.RightCircular}); err != nil {
		t.Fatal(err)
	}
	attempt, err := runtime.Attempts.Begin(value.ID, "RF-01")
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Passes.BeginAcquisition(value.ID, attempt.ID); err != nil {
		t.Fatal(err)
	}
	results := []receiver.AcquisitionResult{
		{PassID: value.ID, AttemptID: attempt.ID, ChainID: "RF-01", Locked: true, Synced: true, Epoch: 7},
		{PassID: value.ID, AttemptID: attempt.ID, ChainID: "RF-02", Locked: true, Synced: true, Epoch: 7},
	}
	decision, err := runtime.Passes.AcceptDiversity(value.ID, results)
	if err != nil || !decision.Ready {
		t.Fatalf("diversity did not converge: %#v %v", decision, err)
	}
	active, found := runtime.Recorder.ActiveForPass(value.ID)
	if !found {
		t.Fatal("tracking did not start a recorder")
	}
	session, err := runtime.NewDecoderSession(value.ID, active.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.OnLock(attempt.ID); err != nil {
		t.Fatal(err)
	}
	if written, err := session.Feed(attempt.ID, make([]byte, 128)); err != nil || written != 2 {
		t.Fatalf("decoder feed wrote %d frames: %v", written, err)
	}
	if _, err := runtime.Recorder.Drain(context.Background(), active.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Recorder.Seal(active.ID, "integration complete"); err != nil {
		t.Fatal(err)
	}
}

func TestEphemerisClockAndWindSafetyFlow(t *testing.T) {
	runtime := newTestRuntime(t)
	value := runtime.Passes.List()[0]
	previous, _ := runtime.Ephemerides.Current(value.SatelliteID)
	if _, err := runtime.Ephemerides.Import(satellite.Ephemeris{SatelliteID: value.SatelliteID, Revision: previous.Revision + 1, Epoch: time.Now().UTC(), Line1: "revised orbital element one", Line2: "revised orbital element two"}); err != nil {
		t.Fatal(err)
	}
	commands := runtime.Commands.List(value.ID)
	if len(commands) == 0 || commands[len(commands)-1].Revision != previous.Revision+1 {
		t.Fatal("revised pointing commands were not queued")
	}
	if _, err := runtime.Clock.Apply(stationclock.Sample{ObservedAt: time.Now().UTC(), Offset: 2 * time.Second, Source: "gps", Quality: "locked"}); err != nil {
		t.Fatal(err)
	}
	if len(runtime.Clock.Corrections()) != 1 {
		t.Fatal("clock correction was not persisted")
	}
	if err := runtime.RF.EnableTransmit("RF-01"); err != nil {
		t.Fatal(err)
	}
	result, err := runtime.Weather.Handle(context.Background(), weather.WindSample{StationID: "station", GustMetersPerSecond: 25, ObservedAt: time.Now().UTC()}, value.ID, value.AntennaID, "RF-01")
	if err != nil || !result.InhibitConfirmed || !result.Stowed {
		t.Fatalf("wind safety did not converge: %#v %v", result, err)
	}
}

func TestRouterRejectsOverlappingReservation(t *testing.T) {
	runtime := newTestRuntime(t)
	first := runtime.Passes.List()[0]
	second, err := runtime.Passes.Create(passsvc.CreateRequest{SatelliteID: "SAT-C07", AntennaID: first.AntennaID, RFChains: []string{"RF-03"}, RequiredReceiverChains: []string{"RF-03"}, AOS: first.Window.AOS.Add(time.Minute), LOS: first.Window.LOS.Add(time.Minute), Revision: 1, OwnerStation: "north"})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.WindowRecompute.Apply(second.ID, second.Window); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Reservations.ReservePass(second.ID, second.AntennaID); err == nil {
		t.Fatal("overlapping reservation unexpectedly succeeded")
	}
}

func TestAuditQueryFiltersCursorAndStability(t *testing.T) {
	runtime := newTestRuntime(t)
	router, err := NewRouter(runtime)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(router)
	defer server.Close()

	passID := runtime.Passes.List()[0].ID

	// The pass filter matches events owned by or referencing the pass.
	filtered := fetchAuditPage(t, server, "/api/audit?pass="+url.QueryEscape(passID))
	if len(filtered.Items) == 0 {
		t.Fatal("expected audit events for the seeded pass")
	}
	for _, item := range filtered.Items {
		if item.Subject != passID && item.Fields["pass_id"] != passID {
			t.Fatalf("event %s (%s.%s) is not related to pass %s", item.ID, item.Component, item.Action, passID)
		}
	}
	if len(filtered.Sources) == 0 {
		t.Fatal("expected event sources in the audit response")
	}

	// Severity and time-range filters are accepted and narrow the result.
	warnings := fetchAuditPage(t, server, "/api/audit?min_severity=warning")
	for _, item := range warnings.Items {
		if item.Severity != audit.Warning && item.Severity != audit.Critical {
			t.Fatalf("min_severity=warning returned %s event", item.Severity)
		}
	}
	until := time.Now().UTC()
	since := until.Add(-time.Hour)
	ranged := fetchAuditPage(t, server, fmt.Sprintf("/api/audit?since=%s&until=%s", url.QueryEscape(since.Format(time.RFC3339)), url.QueryEscape(until.Format(time.RFC3339))))
	for _, item := range ranged.Items {
		if item.At.Before(since) || item.At.After(until) {
			t.Fatalf("event %s at %s outside [%s, %s]", item.ID, item.At, since, until)
		}
	}

	// Pages already read stay identical while new events are recorded.
	first := fetchAuditPage(t, server, "/api/audit?limit=2")
	if len(first.Items) != 2 || first.NextCursor == "" {
		t.Fatalf("first page = %d items, cursor %q; want 2 items and a cursor", len(first.Items), first.NextCursor)
	}
	for range 3 {
		if _, err := runtime.Audit.Record(audit.Event{Component: "test", Action: "written"}); err != nil {
			t.Fatal(err)
		}
	}
	replayed := fetchAuditPage(t, server, "/api/audit?limit=2")
	for i := range first.Items {
		if replayed.Items[i].ID != first.Items[i].ID {
			t.Fatalf("first page shifted after new writes: %v", first.Items)
		}
	}

	// The cursor continues where the first page stopped, without repeats.
	second := fetchAuditPage(t, server, "/api/audit?limit=2&cursor="+url.QueryEscape(first.NextCursor))
	if len(second.Items) == 0 {
		t.Fatal("expected a second page of audit events")
	}
	for _, item := range second.Items {
		if item.Seq <= first.Items[len(first.Items)-1].Seq {
			t.Fatalf("second page returned seq %d already covered by the first page", item.Seq)
		}
	}

	// Invalid parameters are rejected.
	for _, target := range []string{"/api/audit?severity=bogus", "/api/audit?min_severity=bogus", "/api/audit?since=not-a-time", "/api/audit?cursor=not-a-cursor", "/api/audit?limit=-1"} {
		response, err := server.Client().Get(server.URL + target)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("GET %s returned %d, want 422", target, response.StatusCode)
		}
		_ = response.Body.Close()
	}
}

func fetchAuditPage(t *testing.T, server *httptest.Server, target string) audit.Page {
	t.Helper()
	response, err := server.Client().Get(server.URL + target)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET %s returned %d", target, response.StatusCode)
	}
	var page audit.Page
	decodeBody(t, response, &page)
	return page
}

func newTestRuntime(t *testing.T) *Runtime {
	t.Helper()
	runtime, err := NewRuntime(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func decodeBody(t *testing.T, response *http.Response, value any) {
	t.Helper()
	defer response.Body.Close()
	if err := json.NewDecoder(response.Body).Decode(value); err != nil {
		t.Fatal(err)
	}
}

func requestJSON(t *testing.T, client *http.Client, method, target, payload string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(method, target, strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
