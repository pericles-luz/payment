// Package pgmigrations embeds the PostgreSQL flavour of the migration files.
//
// The files here are GENERATED from ../*.sql by scripts/gen-pg-migrations.py and
// must not be edited by hand. Only two things differ from the SQLite originals,
// because the DDL was deliberately written portable from the start:
//
//   - BLOB -> BYTEA, for the five AES-256-GCM sealed columns.
//   - "<name>_cents INTEGER" -> BIGINT. This one is not cosmetic: in Postgres
//     INTEGER is int32, which caps a money column at ~R$ 21,4 million in cents,
//     while the Go side reads and writes int64. A literal port of the SQLite DDL
//     would narrow every amount silently.
//
// The 0/1 boolean columns (tenants.active, accounts.active, account_keys.active,
// account_outbound_webhook.enabled) stay INTEGER on purpose: Postgres accepts
// them as-is, and turning them into BOOLEAN would break every `var active int`
// scan and the boolToInt helper for no gain.
//
// When you add a migration, add it to ../ and re-run the generator.
package pgmigrations

import "embed"

// FS holds the ordered .sql migration files for PostgreSQL.
//
//go:embed *.sql
var FS embed.FS
