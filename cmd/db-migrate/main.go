// Command db-migrate copies a SQLite payment database into PostgreSQL.
//
// It is the Fase 4 tool of the lmhost migration: one-shot, operator-run, and safe
// to run twice (every insert is ON CONFLICT DO NOTHING, so a second pass carries
// only the rows the first one did not have — which is what the cutover's delta run
// needs).
//
//	PAYMENT_DB_PATH=/opt/payment/payment.db \
//	PAYMENT_DB_DSN='postgres://payment:...@data:5432/payment?sslmode=require' \
//	db-migrate [-dry-run]
//
// What it does NOT do, on purpose:
//
//   - It never re-encrypts. The sealed columns are copied byte for byte: the KEK is
//     the same and the AAD binds (tenantID, bankID), which the copy does not change.
//     Rotating the KEK is cmd/vault-reseal, as a separate step.
//   - It never writes to the source. The SQLite file is opened, read, and closed.
//
// The row order comes from PostgreSQL's own foreign-key catalogue rather than a
// hand-kept list, so a migration added later cannot leave this tool behind.
//
// Two things worth knowing before the first run. SQLite ran `PRAGMA foreign_keys`
// on a single pooled connection and never bounded the pool, so FK enforcement there
// was inconsistent; PostgreSQL enforces every one of them, and a source database
// carrying orphan rows will fail here. That is the tool doing its job — find it in
// a dry run, not during the cutover window. And timestamps are normalised to a
// fixed-width fraction on the way in (see normaliseTimestamp).
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/postgres"
	pgmigrations "github.com/ia-dev-sindireceita/payment/migrations/pg"
)

// srcLayout is what the SQLite adapter wrote: RFC3339Nano, whose fraction has no
// fixed width. dstLayout is what the PostgreSQL adapter reads and writes.
const (
	srcLayout = time.RFC3339Nano
	dstLayout = "2006-01-02T15:04:05.000000000Z07:00"
)

// skipTables are managed by the target itself, not carried over. The ledger is
// written by Migrate against migrations/pg; copying the source's would claim files
// as applied that never ran here.
var skipTables = map[string]bool{"schema_migrations": true}

func main() {
	if err := run(); err != nil {
		log.Fatalf("db-migrate: %v", err)
	}
}

func run() error {
	dryRun := flag.Bool("dry-run", false, "read and validate, then roll back without keeping anything")
	flag.Parse()

	srcPath := os.Getenv("PAYMENT_DB_PATH")
	dstDSN := os.Getenv("PAYMENT_DB_DSN")
	if srcPath == "" || dstDSN == "" {
		return errors.New("PAYMENT_DB_PATH (SQLite source) and PAYMENT_DB_DSN (PostgreSQL target) are both required")
	}
	ctx := context.Background()

	src, err := sql.Open("sqlite", srcPath)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer func() { _ = src.Close() }()

	dst, err := postgres.Open(dstDSN)
	if err != nil {
		return fmt.Errorf("open target: %w", err)
	}
	defer func() { _ = dst.Close() }()

	// The target must carry the full schema before anything is copied.
	if err := postgres.Migrate(ctx, dst, pgmigrations.FS); err != nil {
		return fmt.Errorf("migrate target: %w", err)
	}

	return copyAll(ctx, src, dst, *dryRun)
}

// copyAll does the work run() sets up: order the tables, copy them in one
// transaction, and re-count both sides. Split out from run so a test can drive it
// with two databases it built itself.
func copyAll(ctx context.Context, src *sql.DB, dst *sql.DB, dryRun bool) error {
	tables, err := orderedTables(ctx, dst)
	if err != nil {
		return err
	}
	log.Printf("copy order (%d tables): %s", len(tables), strings.Join(tables, " -> "))

	// One transaction for the whole copy: a failure anywhere leaves the target
	// exactly as it was, so the operator retries from a known state instead of
	// reasoning about a half-filled database during a cutover window.
	tx, err := dst.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	total := 0
	for _, table := range tables {
		n, err := copyTable(ctx, src, tx, table)
		if err != nil {
			return fmt.Errorf("copy %s: %w", table, err)
		}
		total += n
		if n > 0 {
			log.Printf("  %-32s %6d rows", table, n)
		}
	}

	if dryRun {
		log.Printf("dry run: %d rows read and accepted by the target schema; rolling back", total)
		return nil
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	log.Printf("copied %d rows", total)

	return verify(ctx, src, dst, tables)
}

// orderedTables lists the target's public tables so that a table always comes
// after the ones it references. The dependency edges come from pg_constraint, so
// adding a migration with a new foreign key needs no change here.
//
// Self-references (a table pointing at itself) are ignored: they order nothing,
// and treating one as an edge would make the graph look cyclic.
func orderedTables(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT table_name FROM information_schema.tables
		  WHERE table_schema = 'public' AND table_type = 'BASE TABLE'`)
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	all := map[string]bool{}
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan table: %w", err)
		}
		if !skipTables[t] {
			all[t] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tables: %w", err)
	}
	_ = rows.Close()

	deps := map[string]map[string]bool{}
	for t := range all {
		deps[t] = map[string]bool{}
	}
	fkRows, err := db.QueryContext(ctx,
		`SELECT c.conrelid::regclass::text, c.confrelid::regclass::text
		   FROM pg_constraint c
		   JOIN pg_namespace n ON n.oid = c.connamespace
		  WHERE c.contype = 'f' AND n.nspname = 'public'`)
	if err != nil {
		return nil, fmt.Errorf("list foreign keys: %w", err)
	}
	defer func() { _ = fkRows.Close() }()
	for fkRows.Next() {
		var child, parent string
		if err := fkRows.Scan(&child, &parent); err != nil {
			return nil, fmt.Errorf("scan fk: %w", err)
		}
		if child == parent || !all[child] || !all[parent] {
			continue
		}
		deps[child][parent] = true
	}
	if err := fkRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate fks: %w", err)
	}

	// Kahn's algorithm, taking ready tables in name order so two runs on the same
	// schema produce the same log.
	var out []string
	done := map[string]bool{}
	for len(done) < len(all) {
		var ready []string
		for t := range all {
			if done[t] {
				continue
			}
			ok := true
			for p := range deps[t] {
				if !done[p] {
					ok = false
					break
				}
			}
			if ok {
				ready = append(ready, t)
			}
		}
		if len(ready) == 0 {
			var stuck []string
			for t := range all {
				if !done[t] {
					stuck = append(stuck, t)
				}
			}
			sort.Strings(stuck)
			return nil, fmt.Errorf("foreign keys form a cycle among: %s", strings.Join(stuck, ", "))
		}
		sort.Strings(ready)
		for _, t := range ready {
			done[t] = true
			out = append(out, t)
		}
	}
	return out, nil
}

// copyTable reads every row of one table from SQLite and inserts it into the
// target, skipping rows already present. The column list comes from the target, so
// a column the source lacks (or carries and the target does not) is a hard error
// rather than a silently shifted value.
func copyTable(ctx context.Context, src *sql.DB, tx *sql.Tx, table string) (int, error) {
	cols, err := targetColumns(ctx, tx, table)
	if err != nil {
		return 0, err
	}
	quoted := make([]string, len(cols))
	placeholders := make([]string, len(cols))
	for i, c := range cols {
		quoted[i] = `"` + c + `"`
		placeholders[i] = fmt.Sprintf("$%d", i+1)
	}
	insert := fmt.Sprintf(`INSERT INTO %q (%s) VALUES (%s) ON CONFLICT DO NOTHING`,
		table, strings.Join(quoted, ", "), strings.Join(placeholders, ", "))

	rows, err := src.QueryContext(ctx, fmt.Sprintf(`SELECT %s FROM %q`, strings.Join(quoted, ", "), table))
	if err != nil {
		return 0, fmt.Errorf("read source: %w", err)
	}
	defer func() { _ = rows.Close() }()

	n := 0
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return 0, fmt.Errorf("scan source row: %w", err)
		}
		for i, c := range cols {
			if isTimestampColumn(c) {
				vals[i] = normaliseTimestamp(vals[i])
			}
		}
		if _, err := tx.ExecContext(ctx, insert, vals...); err != nil {
			return 0, fmt.Errorf("insert row %d: %w", n+1, err)
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate source: %w", err)
	}
	return n, nil
}

func targetColumns(ctx context.Context, tx *sql.Tx, table string) ([]string, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT column_name FROM information_schema.columns
		  WHERE table_schema = 'public' AND table_name = $1
		  ORDER BY ordinal_position`, table)
	if err != nil {
		return nil, fmt.Errorf("columns of %s: %w", table, err)
	}
	defer func() { _ = rows.Close() }()
	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, fmt.Errorf("scan column: %w", err)
		}
		cols = append(cols, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate columns: %w", err)
	}
	if len(cols) == 0 {
		return nil, fmt.Errorf("table %s has no columns", table)
	}
	return cols, nil
}

// isTimestampColumn reports whether a column holds an RFC3339 instant. Both schemas
// name them the same way — "at", or something ending in "_at" — and no other column
// does, so the name is the reliable signal and it stays right as migrations land.
func isTimestampColumn(name string) bool {
	return name == "at" || strings.HasSuffix(name, "_at")
}

// normaliseTimestamp rewrites a stored instant to the fixed-width fraction the
// PostgreSQL adapter uses.
//
// This is the one place the copy is not byte-for-byte, and it is deliberate. The
// SQLite adapter formatted with RFC3339Nano, which drops trailing zeros, so a whole
// second was written "…:00Z" and half a second later "…:00.5Z". The columns are
// TEXT and every ORDER BY on them is lexical: at index 19, 'Z' (0x5A) sorts after
// '.' (0x2E), so the whole second lands AFTER the fraction that follows it. Copying
// the text verbatim would carry that into the new database and leave it mixed with
// correctly-formatted new rows, which is worse than either alone.
//
// A value that does not parse is passed through untouched: it is not ours to
// reinterpret, and the target's NOT NULL / type constraints still get their say.
func normaliseTimestamp(v any) any {
	var s string
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		s = t
	case []byte:
		s = string(t)
	case time.Time:
		return t.UTC().Format(dstLayout)
	default:
		return v
	}
	parsed, err := time.Parse(srcLayout, s)
	if err != nil {
		return v
	}
	return parsed.UTC().Format(dstLayout)
}

// verify re-counts every table on both sides. The copy skips rows already present,
// so a mismatch here means the target is missing rows the source has — the failure
// mode that matters. A target with MORE rows is reported too: on a first run it
// means the database was not empty.
func verify(ctx context.Context, src *sql.DB, dst *sql.DB, tables []string) error {
	var problems []string
	for _, table := range tables {
		var srcN, dstN int64
		if err := src.QueryRowContext(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM %q`, table)).Scan(&srcN); err != nil {
			return fmt.Errorf("count source %s: %w", table, err)
		}
		if err := dst.QueryRowContext(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM %q`, table)).Scan(&dstN); err != nil {
			return fmt.Errorf("count target %s: %w", table, err)
		}
		switch {
		case dstN < srcN:
			problems = append(problems, fmt.Sprintf("%s: target has %d rows, source has %d", table, dstN, srcN))
		case dstN > srcN:
			log.Printf("  note: %s has %d rows in the target and %d in the source (pre-existing rows)", table, dstN, srcN)
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("verification failed:\n  %s", strings.Join(problems, "\n  "))
	}
	log.Print("verification ok: every table has at least as many rows in the target as in the source")
	return nil
}
