package db

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/glebarez/go-sqlite"
)

// TestInitDBMigratesOldSchema creates a queries table with the pre-filter
// (Step 1) column set and verifies InitDB adds matched_rule/block_reason
// while keeping inserts and reads working.
func TestInitDBMigratesOldSchema(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "old.db")

	// Create an old-schema DB (no matched_rule/block_reason columns).
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
		latency REAL,
		dnssec TEXT DEFAULT '',
		client_hostname TEXT DEFAULT '',
		blocked INTEGER DEFAULT 0,
		response_code TEXT DEFAULT '',
		latency_alert INTEGER DEFAULT 0
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
	for _, want := range []string{"matched_rule", "block_reason", "dnssec", "blocked"} {
		if !cols[want] {
			t.Errorf("column %q missing after migration", want)
		}
	}

	// Old rows remain readable; new columns default to ''.
	var domain, matchedRule, blockReason string
	err = db.QueryRow("SELECT domain, matched_rule, block_reason FROM queries WHERE id = 1").Scan(&domain, &matchedRule, &blockReason)
	if err != nil {
		t.Fatalf("read migrated row: %v", err)
	}
	if domain != "old.example.com" || matchedRule != "" || blockReason != "" {
		t.Errorf("migrated row = (%q, %q, %q)", domain, matchedRule, blockReason)
	}

	// Inserts with the new column set (as storage.go now issues) must work.
	_, err = db.Exec(`INSERT INTO queries (unix_time, node, client_ip, domain, type, upstream, latency, dnssec, response_code, client_hostname, blocked, latency_alert, matched_rule, block_reason)
		VALUES (2, 'n1', '2.2.2.2', 'blocked.example.com', 'A', 'Filtered', NULL, '', 'NXDOMAIN', '', 1, 0, '||blocked.example.com^', 'FilteredByBlocklist')`)
	if err != nil {
		t.Fatalf("insert with new columns: %v", err)
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM queries").Scan(&count); err != nil || count != 2 {
		t.Errorf("row count = %d, err = %v, want 2", count, err)
	}
}
