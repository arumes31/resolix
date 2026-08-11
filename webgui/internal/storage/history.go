package storage

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/arumes31/resolix/webgui/internal/db"
	"github.com/arumes31/resolix/webgui/internal/models"
)

const (
	// MaxHistoryPageSize bounds database work and response size for history requests.
	MaxHistoryPageSize = 500
	defaultHistoryPage = 100
)

// ErrInvalidHistoryFilter identifies client-supplied history query errors.
var ErrInvalidHistoryFilter = errors.New("invalid history filter")

// HistoryFilter selects a keyset-paginated page from persisted query history.
// Cursor is the exclusive upper SQLite row ID; zero starts at the newest row.
type HistoryFilter struct {
	Cursor   int64
	Limit    int
	Domain   string
	ClientIP string
	Type     string
	Status   string
}

// HistoryPage is a newest-first page from persisted query history.
type HistoryPage struct {
	Events     []models.QueryEvent `json:"events"`
	NextCursor string              `json:"next_cursor,omitempty"`
	HasMore    bool                `json:"has_more"`
}

// QueryHistory returns persisted events using keyset pagination and database-
// side filters. Every value remains a SQL parameter; only fixed clauses are
// appended to the statement.
func (s *Store) QueryHistory(ctx context.Context, filter HistoryFilter) (HistoryPage, error) {
	if ctx == nil {
		return HistoryPage{}, errors.New("history query context is required")
	}
	if err := normalizeHistoryFilter(&filter); err != nil {
		return HistoryPage{}, err
	}
	query, args := buildHistoryQuery(filter)

	s.dbMu.RLock()
	defer s.dbMu.RUnlock()
	if s.closed || s.db == nil {
		return HistoryPage{}, errors.New("history database is not available")
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		s.recordDBError(err)
		return HistoryPage{}, fmt.Errorf("query persisted history: %w", err)
	}
	defer func() { _ = rows.Close() }()

	events := make([]models.QueryEvent, 0, filter.Limit+1)
	for rows.Next() {
		var (
			id           int64
			blocked      int
			latencyAlert int
			cacheTTL     int64
			event        models.QueryEvent
		)
		if err := rows.Scan(
			&id, &event.UnixTime, &event.Node, &event.ClientIP, &event.Domain,
			&event.Type, &event.Upstream, &event.Latency, &event.DNSSEC,
			&event.ClientHostname, &blocked, &event.ResponseCode, &latencyAlert,
			&event.MatchedRule, &event.BlockReason, &event.CacheStatus,
			&cacheTTL, &event.NegativeSOA,
		); err != nil {
			return HistoryPage{}, fmt.Errorf("scan persisted history: %w", err)
		}
		if cacheTTL < 0 || cacheTTL > int64(^uint32(0)) {
			return HistoryPage{}, fmt.Errorf("scan persisted history: invalid cache TTL %d", cacheTTL)
		}
		event.ID = strconv.FormatInt(id, 10)
		event.CacheTTL = uint32(cacheTTL)
		event.Blocked = blocked != 0
		event.LatencyAlert = latencyAlert != 0
		event.Alias = s.cfg.GetClientAlias(event.ClientIP)
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		s.recordDBError(err)
		return HistoryPage{}, fmt.Errorf("iterate persisted history: %w", err)
	}

	page := HistoryPage{Events: events}
	if len(events) > filter.Limit {
		page.HasMore = true
		page.Events = events[:filter.Limit]
		page.NextCursor = page.Events[len(page.Events)-1].ID
	}
	return page, nil
}

func normalizeHistoryFilter(filter *HistoryFilter) error {
	if filter.Cursor < 0 {
		return fmt.Errorf("%w: cursor must not be negative", ErrInvalidHistoryFilter)
	}
	if filter.Limit == 0 {
		filter.Limit = defaultHistoryPage
	}
	if filter.Limit < 1 || filter.Limit > MaxHistoryPageSize {
		return fmt.Errorf("%w: limit must be between 1 and %d", ErrInvalidHistoryFilter, MaxHistoryPageSize)
	}
	filter.Domain = strings.TrimSpace(strings.ToLower(filter.Domain))
	filter.ClientIP = strings.TrimSpace(filter.ClientIP)
	filter.Type = strings.ToUpper(strings.TrimSpace(filter.Type))
	filter.Status = strings.ToUpper(strings.TrimSpace(filter.Status))
	if len(filter.Domain) > 253 {
		return fmt.Errorf("%w: domain is too long", ErrInvalidHistoryFilter)
	}
	if len(filter.ClientIP) > 128 {
		return fmt.Errorf("%w: client is too long", ErrInvalidHistoryFilter)
	}
	if filter.Type != "" && !validHistoryToken(filter.Type, 16) {
		return fmt.Errorf("%w: type is invalid", ErrInvalidHistoryFilter)
	}
	if filter.Status != "" && !validHistoryToken(filter.Status, 32) {
		return fmt.Errorf("%w: status is invalid", ErrInvalidHistoryFilter)
	}
	return nil
}

func buildHistoryQuery(filter HistoryFilter) (string, []any) {
	var query strings.Builder
	query.WriteString(`SELECT id, unix_time, node, client_ip, domain, type, upstream,
		latency, dnssec, client_hostname, blocked, response_code, latency_alert,
		matched_rule, block_reason, cache_status, cache_ttl, negative_soa
		FROM queries WHERE 1 = 1`)
	args := make([]any, 0, 7)
	if filter.Cursor > 0 {
		query.WriteString(" AND id < ?")
		args = append(args, filter.Cursor)
	}
	if filter.Domain != "" {
		query.WriteString(" AND domain = ?")
		args = append(args, filter.Domain)
	}
	if filter.ClientIP != "" {
		query.WriteString(" AND client_ip = ?")
		args = append(args, filter.ClientIP)
	}
	if filter.Type != "" {
		query.WriteString(" AND type = ?")
		args = append(args, filter.Type)
	}
	switch filter.Status {
	case "":
	case "ALLOWED":
		query.WriteString(" AND blocked = 0")
	case "BLOCKED":
		query.WriteString(" AND blocked = 1")
	case "CACHE":
		query.WriteString(" AND (" + db.CacheHitSQLExpression + ")")
	case "ERROR":
		query.WriteString(" AND response_code NOT IN ('', 'NOERROR')")
	default:
		query.WriteString(" AND response_code = ?")
		args = append(args, filter.Status)
	}
	query.WriteString(" ORDER BY id DESC LIMIT ?")
	args = append(args, filter.Limit+1)
	return query.String(), args
}

func validHistoryToken(value string, maxLength int) bool {
	if value == "" || len(value) > maxLength {
		return false
	}
	for _, r := range value {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' {
			return false
		}
	}
	return true
}
