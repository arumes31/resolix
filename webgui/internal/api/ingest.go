package api

import (
	"bytes"
	"compress/gzip"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/arumes31/resolix/webgui/internal/config"
	apperr "github.com/arumes31/resolix/webgui/internal/errors"
	"github.com/arumes31/resolix/webgui/internal/models"
)

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Enforce Authentication
	if s.cfg.IngestSecret != "" {
		auth := r.Header.Get("Authorization")
		expected := "Bearer " + s.cfg.IngestSecret
		if subtle.ConstantTimeCompare([]byte(auth), []byte(expected)) != 1 {
			http.Error(w, apperr.NewErrAuthFailed("invalid ingest secret", nil).Error(), http.StatusUnauthorized)
			return
		}
	}

	body, err := readRequestBody(w, r, s.cfg.MaxRequestSize)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, apperr.NewErrParseFailed("bad request", err).Error(), http.StatusBadRequest)
		}
		return
	}

	// New format: a top-level JSON array of QueryEvent (structured events
	// from dnsserver-based agents). Legacy format: an object with raw dnsmasq
	// log lines parsed via internal/parser.
	if bytes.HasPrefix(bytes.TrimSpace(body), []byte("[")) {
		s.handleIngestEvents(w, r, body)
		return
	}

	var payload struct {
		Node   string             `json:"node"`
		Line   string             `json:"line"`
		Batch  []string           `json:"batch"`
		Health map[string]float64 `json:"health,omitempty"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, apperr.NewErrParseFailed("payload too large or bad request", err).Error(), http.StatusBadRequest)
		return
	}
	identity := requestNodeIdentity(r, payload.Node)
	if payload.Node != "" && s.store.IsNodeTombstoned(identity) {
		http.Error(w, "node is decommissioned", http.StatusGone)
		return
	}

	// 3. Strict Input Validation
	if len(payload.Batch) > 100 {
		http.Error(w, "Batch too large (max 100)", http.StatusRequestEntityTooLarge)
		return
	}
	if !s.establishIngestNodeStatus(w, r, identity, payload.Node) {
		return
	}

	processLine := func(line string) {
		if len(line) > 1024 { // Cap max bytes per line
			return
		}
		ev := s.parser.ParseLogBytes([]byte(line), payload.Node)
		if ev != nil {
			s.BroadcastEvent(*ev)
		}
	}

	if payload.Line != "" {
		processLine(payload.Line)
	}
	for _, l := range payload.Batch {
		processLine(l)
	}
	if len(payload.Health) > 0 {
		s.store.SetUpstreamHealth(identity, payload.Health)
	}

	w.WriteHeader(http.StatusNoContent)
}

func readRequestBody(w http.ResponseWriter, r *http.Request, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = config.DefaultMaxRequestSize
	}
	compressed := http.MaxBytesReader(w, r.Body, maxBytes)
	var reader io.Reader = compressed
	var gzReader *gzip.Reader
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Content-Encoding")), "gzip") {
		var err error
		gzReader, err = gzip.NewReader(compressed)
		if err != nil {
			return nil, fmt.Errorf("gzip reader: %w", err)
		}
		defer func() { _ = gzReader.Close() }()
		reader = gzReader
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, &http.MaxBytesError{Limit: maxBytes}
	}
	return data, nil
}

// handleIngestEvents processes the new ingest format: a top-level JSON array
// of models.QueryEvent produced by dnsserver-based agents. Node status is
// updated from the X-Node-* headers as with legacy payloads.
func (s *Server) handleIngestEvents(w http.ResponseWriter, r *http.Request, body []byte) {
	var events []models.QueryEvent
	if err := json.Unmarshal(body, &events); err != nil {
		http.Error(w, apperr.NewErrParseFailed("invalid events payload", err).Error(), http.StatusBadRequest)
		return
	}
	if len(events) > 100 {
		http.Error(w, "Batch too large (max 100)", http.StatusRequestEntityTooLarge)
		return
	}

	node := ""
	if len(events) > 0 {
		node = events[0].Node
		for i := 1; i < len(events); i++ {
			if events[i].Node != node {
				http.Error(w, "events must belong to one node", http.StatusBadRequest)
				return
			}
		}
	}
	identity := requestNodeIdentity(r, node)
	if node != "" && s.store.IsNodeTombstoned(identity) {
		http.Error(w, "node is decommissioned", http.StatusGone)
		return
	}
	if !s.establishIngestNodeStatus(w, r, identity, node) {
		return
	}
	now := time.Now()
	maxUnixTime := now.Add(maxIngestFutureSkew).Unix()
	for i := range events {
		if events[i].UnixTime <= 0 || events[i].UnixTime > maxUnixTime {
			events[i].UnixTime = now.Unix()
		}
		events[i] = s.store.AddEvent(events[i])
		s.BroadcastEvent(events[i])
	}

	w.WriteHeader(http.StatusNoContent)
}
