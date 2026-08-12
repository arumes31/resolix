package db

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"

	_ "github.com/glebarez/go-sqlite"
)

// CacheHitSQLExpression is the canonical SQLite predicate for a response
// actually served from cache. Coalesced misses share an upstream request but
// are not cache hits; legacy rows are recognized by their System Cache label.
const CacheHitSQLExpression = `(lower(trim(cache_status)) IN ('fresh','stale','prefetched','negative','servfail') OR (trim(cache_status) = '' AND upstream LIKE 'System Cache%'))`

// IsCacheHitStatus reports whether a normalized cache state means the answer
// was served from cache rather than merely sharing an in-flight miss.
func IsCacheHitStatus(status string) bool {
	switch status {
	case "fresh", "stale", "prefetched", "negative", "servfail":
		return true
	default:
		return false
	}
}

// InitDB initializes the SQLite database at the given full path.
// The directory containing the database file is created if it does not exist.
func InitDB(fullDBPath string) (*sql.DB, error) {
	newDatabase := false
	if info, err := os.Stat(fullDBPath); os.IsNotExist(err) || (err == nil && info.Size() == 0) {
		newDatabase = true
	}
	// Ensure the directory exists before opening the database
	dbDir := filepath.Dir(fullDBPath)
	if err := os.MkdirAll(dbDir, 0750); err != nil {
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
	if newDatabase {
		// Enabling incremental auto-vacuum requires VACUUM, which is safe here
		// because a newly created database contains no application data. Existing
		// databases are never subjected to this blocking migration automatically.
		if _, err := db.Exec("PRAGMA auto_vacuum=INCREMENTAL; VACUUM;"); err != nil {
			return nil, fmt.Errorf("enable incremental auto-vacuum for new database: %w", err)
		}
	}

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

	// Create the table before migrations. Indexes are created after migrations
	// because existing databases may not have all indexed columns yet.
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
	latency_alert INTEGER DEFAULT 0,
	matched_rule TEXT DEFAULT '',
	block_reason TEXT DEFAULT '',
	cache_status TEXT DEFAULT '',
	cache_ttl INTEGER DEFAULT 0,
	negative_soa TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS storage_metadata (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS node_tombstones (
	node_id TEXT PRIMARY KEY,
	node_name TEXT NOT NULL,
	decommissioned_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS query_hourly_totals (
	hour INTEGER PRIMARY KEY,
	total INTEGER NOT NULL,
	cache_hits INTEGER NOT NULL,
	replies INTEGER NOT NULL,
	blocked INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS query_hourly_domains (
	hour INTEGER NOT NULL,
	domain TEXT NOT NULL,
	count INTEGER NOT NULL,
	PRIMARY KEY (hour, domain)
);
CREATE TABLE IF NOT EXISTS query_hourly_clients (
	hour INTEGER NOT NULL,
	client_ip TEXT NOT NULL,
	count INTEGER NOT NULL,
	PRIMARY KEY (hour, client_ip)
);
CREATE TABLE IF NOT EXISTS query_hourly_types (
	hour INTEGER NOT NULL,
	type TEXT NOT NULL,
	count INTEGER NOT NULL,
	PRIMARY KEY (hour, type)
);
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
		{"matched_rule", "TEXT DEFAULT ''"},
		{"block_reason", "TEXT DEFAULT ''"},
		{"cache_status", "TEXT DEFAULT ''"},
		{"cache_ttl", "INTEGER DEFAULT 0"},
		{"negative_soa", "TEXT DEFAULT ''"},
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

	indexes := `
CREATE INDEX IF NOT EXISTS idx_queries_unix_time ON queries(unix_time);
CREATE INDEX IF NOT EXISTS idx_queries_domain_time ON queries(domain, unix_time);
CREATE INDEX IF NOT EXISTS idx_queries_client_time ON queries(client_ip, unix_time);
CREATE INDEX IF NOT EXISTS idx_queries_node ON queries(node);
CREATE INDEX IF NOT EXISTS idx_queries_node_time ON queries(node, unix_time);
CREATE INDEX IF NOT EXISTS idx_queries_blocked ON queries(blocked);
CREATE INDEX IF NOT EXISTS idx_queries_response_code ON queries(response_code);
CREATE INDEX IF NOT EXISTS idx_queries_history_time_id ON queries(unix_time DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_queries_domain_time_id ON queries(domain, unix_time DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_queries_client_time_id ON queries(client_ip, unix_time DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_queries_type_time_id ON queries(type, unix_time DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_queries_blocked_time_id ON queries(blocked, unix_time DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_queries_response_time_id ON queries(response_code, unix_time DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_queries_domain_id ON queries(domain, id DESC);
CREATE INDEX IF NOT EXISTS idx_queries_client_id ON queries(client_ip, id DESC);
CREATE INDEX IF NOT EXISTS idx_queries_type_id ON queries(type, id DESC);
CREATE INDEX IF NOT EXISTS idx_queries_blocked_id ON queries(blocked, id DESC);
CREATE INDEX IF NOT EXISTS idx_queries_response_id ON queries(response_code, id DESC);
CREATE INDEX IF NOT EXISTS idx_queries_cache_status_id ON queries(cache_status, id DESC);
CREATE INDEX IF NOT EXISTS idx_query_hourly_domains_count ON query_hourly_domains(hour, count DESC, domain);
CREATE INDEX IF NOT EXISTS idx_query_hourly_clients_count ON query_hourly_clients(hour, count DESC, client_ip);
`
	if _, err := db.Exec(indexes); err != nil {
		return nil, fmt.Errorf("failed to create indexes: %w", err)
	}
	if err := backfillHourlyAggregates(db); err != nil {
		return nil, fmt.Errorf("backfill hourly aggregates: %w", err)
	}

	log.Printf("[INFO] SQLite database initialized at %s", fullDBPath)
	success = true
	return db, nil
}

// backfillHourlyAggregates performs an additive, one-time migration for
// databases created before incremental hourly aggregates existed. The marker
// and all aggregate rows commit together, so an interrupted migration is safe
// to retry on the next start.
func backfillHourlyAggregates(database *sql.DB) error {
	const migrationKey = "hourly_aggregates_v1"
	var marker string
	err := database.QueryRow("SELECT value FROM storage_metadata WHERE key = ?", migrationKey).Scan(&marker)
	if err == nil {
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}

	tx, err := database.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	statements := []string{
		fmt.Sprintf(`INSERT INTO query_hourly_totals (hour, total, cache_hits, replies, blocked)
		 SELECT (unix_time / 3600) * 3600, COUNT(*),
		        COALESCE(SUM(CASE WHEN %s THEN 1 ELSE 0 END), 0),
		        COALESCE(SUM(CASE WHEN upstream != '' THEN 1 ELSE 0 END), 0),
		        COALESCE(SUM(blocked), 0)
		 FROM queries GROUP BY (unix_time / 3600) * 3600`, CacheHitSQLExpression),
		`INSERT INTO query_hourly_domains (hour, domain, count)
		 SELECT (unix_time / 3600) * 3600, domain, COUNT(*)
		 FROM queries GROUP BY (unix_time / 3600) * 3600, domain`,
		`INSERT INTO query_hourly_clients (hour, client_ip, count)
		 SELECT (unix_time / 3600) * 3600, client_ip, COUNT(*)
		 FROM queries GROUP BY (unix_time / 3600) * 3600, client_ip`,
		`INSERT INTO query_hourly_types (hour, type, count)
		 SELECT (unix_time / 3600) * 3600, type, COUNT(*)
		 FROM queries GROUP BY (unix_time / 3600) * 3600, type`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(
		"INSERT INTO storage_metadata (key, value) VALUES (?, ?)",
		migrationKey,
		"complete",
	); err != nil {
		return err
	}
	return tx.Commit()
}
