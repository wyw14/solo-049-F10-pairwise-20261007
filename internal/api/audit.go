package api

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"orbitlink/internal/audit"
)

// listAudit serves the stable cursor query over the audit trail. Supported
// filters: component, subject, pass, operation, severity, min_severity,
// since, until (RFC 3339), plus limit and cursor for pagination.
func (r *Runtime) listAudit(writer http.ResponseWriter, request *http.Request) {
	values := request.URL.Query()
	query := audit.Query{
		Component: values.Get("component"),
		Subject:   values.Get("subject"),
		PassID:    values.Get("pass"),
		Operation: values.Get("operation"),
	}
	if raw := values.Get("severity"); raw != "" {
		severity := audit.Severity(raw)
		if _, ok := audit.Rank(severity); !ok {
			writeError(writer, fmt.Errorf("unknown severity %q", raw))
			return
		}
		query.Severity = severity
	}
	if raw := values.Get("min_severity"); raw != "" {
		severity := audit.Severity(raw)
		if _, ok := audit.Rank(severity); !ok {
			writeError(writer, fmt.Errorf("unknown min_severity %q", raw))
			return
		}
		query.MinSeverity = severity
	}
	if raw := values.Get("since"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(writer, fmt.Errorf("invalid since timestamp: %w", err))
			return
		}
		query.Since = parsed
	}
	if raw := values.Get("until"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(writer, fmt.Errorf("invalid until timestamp: %w", err))
			return
		}
		query.Until = parsed
	}
	if raw := values.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			writeError(writer, fmt.Errorf("invalid limit %q", raw))
			return
		}
		query.Limit = parsed
	}
	cursor, err := audit.ParseCursor(values.Get("cursor"))
	if err != nil {
		writeError(writer, err)
		return
	}
	query.After = cursor
	writeJSON(writer, http.StatusOK, r.Audit.Query(query))
}
