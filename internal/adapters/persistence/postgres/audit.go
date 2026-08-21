package postgres

import (
	"context"
	"fmt"

	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// This file is the persistent, append-only implementation of ports.AuditLog.
//
// ATOMICITY (the architecture decision, SIN-66025): the append must commit (or
// roll back) together with the operation that triggered it. AuditLog is bundled
// into ports.Repository, so Append below runs on the SAME dbtx handle (r.q) as
// the triggering write — exactly like SaveTenant. When a use-case appends through
// the Repository handed to WithinTx, the audit INSERT and the action share one
// transaction; when it appends through the standalone Deps.Audit port (the *Store,
// whose embedded repo.q is the *sql.DB pool), the INSERT autocommits on its own.
// Either way the trail is durable and survives a restart.
//
// APPEND-ONLY: the only statement this adapter ever issues against audit_log is an
// INSERT. There is no UPDATE or DELETE anywhere in application code — immutability
// is a property of the code surface, not just a convention. The Entry type carries
// no secret by construction, so no column here can leak one (threat C1/C4).

// Compile-time checks that the persistence adapter satisfies the audit port both
// on the pool (*Store) and inside a transaction (repo).
var (
	_ ports.AuditLog = (*Store)(nil)
	_ ports.AuditLog = repo{}
)

// Append durably records one audit entry (append-only INSERT). It runs on the
// adapter's current handle: the transaction when this repo came from WithinTx, the
// connection pool otherwise. It never persists a secret — Entry exposes only
// who/what/tenant/when plus, for a settlement mismatch, the txid and the
// expected/received cents, and for a credential.set the non-secret bank slug
// (bank_id, SIN-66044) — never the credential secret or client id (threat C1/C4).
// It also stamps the audited tenant's owning account (account_id, SIN-69127), a
// public 'acct-<tenant_id>' attribution id, so the trail completes the
// account→tenant rollup; a self-account resolves to NULL (NULL-safe). Finally it
// records the non-secret origin label (admin | self-serve, SIN-69196/migration
// 0010) so the trail distinguishes an admin write from a tenant self-rotation.
func (r repo) Append(ctx context.Context, e audit.Entry) error {
	_, err := r.q.ExecContext(ctx,
		`INSERT INTO audit_log (id, operator_id, action, tenant_id, at, tx_id, expected_cents, received_cents, bank_id, account_id, origin)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		e.ID(), e.OperatorID(), string(e.Action()), e.TenantID(), e.At().Format(tsLayout),
		e.TxID(), e.ExpectedCents(), e.ReceivedCents(), e.BankID(), nullIfEmpty(e.AccountID()), e.Origin())
	if err != nil {
		return fmt.Errorf("append audit entry: %w", err)
	}
	return nil
}
