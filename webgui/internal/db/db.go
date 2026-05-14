package db

import (
	"database/sql"
	"fmt"
	"log"
	"path/filepath"

	_ "github.com/glebarez/go-sqlite"
)

// InitDB initializes the SQLite database in the given directory.
func InitDB(historyDir string) (*sql.DB, error) {
	dbPath := filepath.Join(historyDir, "dns.db")

	// Open SQLite db (modernc sqlite syntax)
	db, err := sql.Open("sqlite", dbPath)
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

	// Optimize SQLite for high concurrency and write throughput
	// WAL mode allows concurrent readers while a write is happening.
	_, err = db.Exec(`
		PRAGMA journal_mode=WAL;
		PRAGMA synchronous=NORMAL;
		PRAGMA busy_timeout=5000;
		PRAGMA cache_size=-64000;
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
		latency REAL
	);
	CREATE INDEX IF NOT EXISTS idx_queries_time ON queries(unix_time);
	CREATE INDEX IF NOT EXISTS idx_queries_domain ON queries(domain);
	CREATE INDEX IF NOT EXISTS idx_queries_client_ip ON queries(client_ip);
	CREATE INDEX IF NOT EXISTS idx_queries_node_time ON queries(node, unix_time);
	`
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	log.Printf("SQLite database initialized at %s", dbPath)
	success = true
	return db, nil
}
