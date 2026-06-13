// Package migrations embeds the SQL migration files so binaries can apply them
// without a separate file dependency. Migrations are written to be portable to
// Postgres later (see README); divergences are documented inline.
package migrations

import "embed"

// FS holds the ordered .sql migration files.
//
//go:embed *.sql
var FS embed.FS
