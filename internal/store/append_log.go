package store

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Event struct {
	ID        string         `json:"id"`
	Stream    string         `json:"stream"`
	Kind      string         `json:"kind"`
	At        time.Time      `json:"at"`
	Seq       uint64         `json:"seq,omitempty"`
	Severity  string         `json:"severity,omitempty"`
	Subject   string         `json:"subject,omitempty"`
	Fields    map[string]any `json:"fields,omitempty"`
	Operation string         `json:"operation,omitempty"`
}

// AppendLog serializes each event stream and fsyncs accepted control events.
type AppendLog struct {
	paths Paths
	mu    sync.Mutex
}

func NewAppendLog(paths Paths) *AppendLog {
	return &AppendLog{paths: paths}
}

func (l *AppendLog) Append(event Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	path := l.paths.Events(event.Stream)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create event directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open event stream: %w", err)
	}
	encoded, err := json.Marshal(event)
	if err == nil {
		_, err = file.Write(append(encoded, '\n'))
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return fmt.Errorf("append event: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close event stream: %w", closeErr)
	}
	return nil
}

func (l *AppendLog) Read(stream string, limit int) ([]Event, error) {
	events, skipped, err := l.ReadAll(stream)
	if err != nil {
		return nil, err
	}
	if skipped > 0 {
		return nil, fmt.Errorf("decode event: %d corrupt line(s) in stream %q", skipped, stream)
	}
	if limit > 0 && len(events) > limit {
		events = events[len(events)-limit:]
	}
	return events, nil
}

// ReadAll reads every event in the stream. Undecodable lines are skipped and
// counted so callers can detect gaps instead of losing the whole stream.
func (l *AppendLog) ReadAll(stream string) (events []Event, skipped int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	file, err := os.Open(l.paths.Events(stream))
	if os.IsNotExist(err) {
		return []Event{}, 0, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("open event stream: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var event Event
		if err := json.Unmarshal(line, &event); err != nil {
			skipped++
			continue
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, skipped, fmt.Errorf("scan events: %w", err)
	}
	return events, skipped, nil
}
