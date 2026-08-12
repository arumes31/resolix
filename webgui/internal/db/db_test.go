package db

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/glebarez/go-sqlite"
)

func TestIsCacheHitStatus(t *testing.T) {
	for _, status := range []string{"fresh", "stale", "prefetched", "negative", "servfail"} {
		if !IsCacheHitStatus(status) {
			t.Errorf("IsCacheHitStatus(%q) = false", status)
		}
	}
	for _, status := range []string{"", "miss", "coalesced", "FRESH"} {
		if IsCacheHitStatus(status) {
			t.Errorf("IsCacheHitStatus(%q) = true", status)
		}
	}
}

// TestInitDBMigratesOldSchema creates a queries table with the original
// column set and verifies InitDB adds all later columns while keeping inserts
// and reads working.
func TestInitDBMigratesOldSchema(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "old.db")

	// Create an original-schema DB with none of the later optional columns.
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.Exec(`CREATE TABLE queries (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		unix_time INTEGER NOT NULL,
		node TEXT NOT NULL,
		client_ip TEXT NOT NULL,
		domain TEXT NOT NULL,
		type TEXT NOT NULL,
		upstream TEXT,
		latency REAL
	);`)
	if err != nil {
		t.Fatalf("create old schema: %v", err)
	}
	_, err = raw.Exec(`INSERT INTO queries (unix_time, node, client_ip, domain, type) VALUES (1, 'n1', '1.1.1.1', 'old.example.com', 'A')`)
	if err != nil {
		t.Fatalf("seed old row: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	// Open through InitDB: migrations must add the new columns.
	db, err := InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	defer func() { _ = db.Close() }()

	cols := make(map[string]bool)
	rows, err := db.Query("SELECT name FROM pragma_table_info('queries')")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		cols[name] = true
	}
	for _, want := range []string{
		"matched_rule", "block_reason", "dnssec", "blocked",
		"cache_status", "cache_ttl", "negative_soa",
	} {
		if !cols[want] {
			t.Errorf("column %q missing after migration", want)
		}
	}
	for _, want := range []string{
		"idx_queries_blocked",
		"idx_queries_response_code",
		"idx_queries_history_time_id",
		"idx_queries_type_time_id",
		"idx_queries_cache_status_id",
	} {
		var name string
		if err := db.QueryRow("SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?", want).Scan(&name); err != nil {
			t.Errorf("index %q missing after migration: %v", want, err)
		}
	}

	// Old rows remain readable; new cache metadata uses zero values.
	var domain, matchedRule, blockReason, cacheStatus, negativeSOA string
	var cacheTTL int64
	err = db.QueryRow(`SELECT domain, matched_rule, block_reason,
		cache_status, cache_ttl, negative_soa FROM queries WHERE id = 1`).Scan(
		&domain, &matchedRule, &blockReason, &cacheStatus, &cacheTTL, &negativeSOA,
	)
	if err != nil {
		t.Fatalf("read migrated row: %v", err)
	}
	if domain != "old.example.com" || matchedRule != "" || blockReason != "" ||
		cacheStatus != "" || cacheTTL != 0 || negativeSOA != "" {
		t.Errorf("migrated row has unexpected values: domain=%q rule=%q reason=%q cache=%q/%d/%q",
			domain, matchedRule, blockReason, cacheStatus, cacheTTL, negativeSOA)
	}
	var aggregateCount int
	if err := db.QueryRow("SELECT total FROM query_hourly_totals WHERE hour = 0").Scan(&aggregateCount); err != nil {
		t.Fatalf("read backfilled hourly total: %v", err)
	}
	if aggregateCount != 1 {
		t.Fatalf("backfilled hourly total = %d, want 1", aggregateCount)
	}

	// Inserts with the new column set (as storage.go now issues) must work.
	_, err = db.Exec(`INSERT INTO queries (unix_time, node, client_ip, domain, type,
		upstream, latency, dnssec, response_code, client_hostname, blocked,
		latency_alert, matched_rule, block_reason, cache_status, cache_ttl, negative_soa)
		VALUES (2, 'n1', '2.2.2.2', 'blocked.example.com', 'A', 'Filtered', NULL, '',
		'NXDOMAIN', '', 1, 0, '||blocked.example.com^', 'FilteredByBlocklist',
		'negative', 30, 'example.com.')`)
	if err != nil {
		t.Fatalf("insert with new columns: %v", err)
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM queries").Scan(&count); err != nil || count != 2 {
		t.Errorf("row count = %d, err = %v, want 2", count, err)
	}
}
