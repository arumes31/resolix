package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"

	_ "github.com/glebarez/go-sqlite"
)

// InitDB initializes the SQLite database at the given full path.
// The directory containing the database file is created if it does not exist.
func InitDB(fullDBPath string) (*sql.DB, error) {
	// Ensure the directory exists before opening the database
	dbDir := filepath.Dir(fullDBPath)
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory %s: %w", dbDir, err)
	}

	// Open SQLite db (modernc sqlite syntax)
	db, err := sql.Open("sqlite", fullDBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	var success bool
	defer func() {
		if !success {
			_ = db.Close()
		}
	}()

	// Ensure only a single writer connection to avoid WAL writer contention
	db.SetMaxOpenConns(1)

	// Optimize SQLite for high concurrency and write throughput.
	// PRAGMA execution order:
	// 1. journal_mode=WAL — allows concurrent readers while a write is happening
	// 2. synchronous=NORMAL — safe with WAL; reduces disk write frequency
	// 3. busy_timeout=5000 — wait up to 5s to acquire a lock instead of immediate "database is locked"
	// 4. cache_size=-4000 — 4MB RAM for database page cache (negative = KiB units)
	// 5. foreign_keys=ON — enforce foreign key constraints
	_, err = db.Exec(`
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA busy_timeout=5000;
PRAGMA cache_size=-4000;
PRAGMA foreign_keys=ON;
`)
	if err != nil {
		return nil, fmt.Errorf("failed to set pragmas: %w", err)
	}

	// Create table and indexes
	schema := `
CREATE TABLE IF NOT EXISTS queries (
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
);
CREATE INDEX IF NOT EXISTS idx_queries_unix_time ON queries(unix_time);
CREATE INDEX IF NOT EXISTS idx_queries_domain_time ON queries(domain, unix_time);
CREATE INDEX IF NOT EXISTS idx_queries_client_time ON queries(client_ip, unix_time);
CREATE INDEX IF NOT EXISTS idx_queries_node ON queries(node);
CREATE INDEX IF NOT EXISTS idx_queries_node_time ON queries(node, unix_time);
CREATE INDEX IF NOT EXISTS idx_queries_blocked ON queries(blocked);
CREATE INDEX IF NOT EXISTS idx_queries_response_code ON queries(response_code);
`
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	// Migrate: add new columns if they don't exist (for existing databases)
	migrations := []struct {
		col string
		def string
	}{
		{"dnssec", "TEXT DEFAULT ''"},
		{"client_hostname", "TEXT DEFAULT ''"},
		{"blocked", "INTEGER DEFAULT 0"},
		{"response_code", "TEXT DEFAULT ''"},
		{"latency_alert", "INTEGER DEFAULT 0"},
	}
	for _, m := range migrations {
		// Check if column exists
		var colName string
		err := db.QueryRow("SELECT name FROM pragma_table_info('queries') WHERE name = ?", m.col).Scan(&colName)
		if err == sql.ErrNoRows {
			// Column doesn't exist, add it
			alterSQL := fmt.Sprintf("ALTER TABLE queries ADD COLUMN %s %s", m.col, m.def)
			if _, err := db.Exec(alterSQL); err != nil {
				log.Printf("[WARN] Migration: failed to add column %s: %v", m.col, err)
				return nil, fmt.Errorf("migration: add column %s: %w", m.col, err)
			} else {
				log.Printf("[INFO] Migration: added column %s to queries table", m.col)
			}
		} else if err != nil {
			log.Printf("[WARN] Migration: failed to inspect column %s: %v", m.col, err)
			return nil, fmt.Errorf("migration: inspect column %s: %w", m.col, err)
		}
	}

	log.Printf("[INFO] SQLite database initialized at %s", fullDBPath)
	success = true
	return db, nil
}
