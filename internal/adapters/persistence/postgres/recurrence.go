package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ia-dev-sindireceita/payment/internal/domain/recurrence"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// This file is the persistent implementation of the PIX Automático recurrence
// ports (SIN-66037): pix_rec for the recurring-debit mandate and pix_cobr for each
// charge instance of its cycle. Like the rest of this adapter, SQL is parameterised
// and every read is tenant-scoped (threat P1). Save is an upsert so a reconciled
// status transition (Rec.Transition / CobR.Transition) is persisted by re-saving
// the aggregate, keeping only its current state — the transition HISTORY lives in
// the append-only audit_log (recurrence.* actions), not here.
//
// Because these methods live on repo (the dbtx-backed type), a transition's save
// and its audit append run on the SAME handle when invoked through WithinTx —
// committing atomically (the unit-of-work seam, SIN-66025).

var (
	_ ports.RecRepository  = (*Store)(nil)
	_ ports.RecRepository  = repo{}
	_ ports.CobRRepository = (*Store)(nil)
	_ ports.CobRRepository = repo{}
)

// SaveRec inserts or updates a mandate, keyed by (tenant_id, id_rec). The
// immutable identity/registration columns are written on insert and the mutable
// state (status, updated_at) on conflict, mirroring SavePayment.
func (r repo) SaveRec(ctx context.Context, rec *recurrence.Rec) error {
	_, err := r.q.ExecContext(ctx,
		`INSERT INTO pix_rec (id_rec, tenant_id, bank_id, contrato, devedor_doc, devedor_nome,
		    data_inicial, periodicidade, valor_cents, status, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		 ON CONFLICT(tenant_id, id_rec) DO UPDATE SET
		    status = excluded.status, updated_at = excluded.updated_at`,
		rec.IDRec(), rec.TenantID(), rec.BankID(), rec.Contrato(),
		rec.Devedor().Doc(), rec.Devedor().Nome(), rec.DataInicial(),
		string(rec.Periodicidade()), rec.ValorCents(), string(rec.Status()),
		rec.CreatedAt().Format(tsLayout), rec.UpdatedAt().Format(tsLayout))
	if err != nil {
		return fmt.Errorf("save rec: %w", err)
	}
	return nil
}

// FindRecByID returns a tenant-scoped mandate or shared.ErrNotFound.
func (r repo) FindRecByID(ctx context.Context, tenantID, idRec string) (*recurrence.Rec, error) {
	row := r.q.QueryRowContext(ctx,
		`SELECT id_rec, tenant_id, bank_id, contrato, devedor_doc, devedor_nome,
		    data_inicial, periodicidade, valor_cents, status, created_at, updated_at
		 FROM pix_rec WHERE tenant_id = $1 AND id_rec = $2`, tenantID, idRec)
	var gotIDRec, gotTenant, bankID, contrato, doc, nome, dataInicial, periodicidade, status, createdAt, updatedAt string
	var valorCents int64
	if err := row.Scan(&gotIDRec, &gotTenant, &bankID, &contrato, &doc, &nome,
		&dataInicial, &periodicidade, &valorCents, &status, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("scan rec: %w", err)
	}
	devedor, err := recurrence.NewDevedor(doc, nome)
	if err != nil {
		return nil, fmt.Errorf("rehydrate devedor: %w", err)
	}
	return recurrence.RehydrateRec(gotIDRec, gotTenant, bankID, contrato, devedor,
		dataInicial, recurrence.RecPeriodicidade(periodicidade), valorCents,
		recurrence.RecStatus(status), parseTime(createdAt), parseTime(updatedAt)), nil
}

// SaveCobR inserts or updates a charge instance, keyed by (tenant_id, tx_id).
func (r repo) SaveCobR(ctx context.Context, c *recurrence.CobR) error {
	_, err := r.q.ExecContext(ctx,
		`INSERT INTO pix_cobr (tx_id, id_rec, tenant_id, vencimento, valor_cents, status, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT(tenant_id, tx_id) DO UPDATE SET
		    status = excluded.status, updated_at = excluded.updated_at`,
		c.TxID(), c.IDRec(), c.TenantID(), c.Vencimento(), c.ValorCents(),
		string(c.Status()), c.CreatedAt().Format(tsLayout), c.UpdatedAt().Format(tsLayout))
	if err != nil {
		return fmt.Errorf("save cobr: %w", err)
	}
	return nil
}

// FindCobRByTxID returns a tenant-scoped charge instance or shared.ErrNotFound.
func (r repo) FindCobRByTxID(ctx context.Context, tenantID, txID string) (*recurrence.CobR, error) {
	row := r.q.QueryRowContext(ctx,
		`SELECT tx_id, id_rec, tenant_id, vencimento, valor_cents, status, created_at, updated_at
		 FROM pix_cobr WHERE tenant_id = $1 AND tx_id = $2`, tenantID, txID)
	c, err := scanCobR(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("scan cobr: %w", err)
	}
	return c, nil
}

// ListCobRByRec returns a mandate's charge instances, due-date ascending (tx_id as
// a deterministic tie-break). Tenant-scoped (threat P1).
func (s *Store) ListCobRByRec(ctx context.Context, tenantID, idRec string) ([]*recurrence.CobR, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT tx_id, id_rec, tenant_id, vencimento, valor_cents, status, created_at, updated_at
		 FROM pix_cobr WHERE tenant_id = $1 AND id_rec = $2 ORDER BY vencimento ASC, tx_id ASC`,
		tenantID, idRec)
	if err != nil {
		return nil, fmt.Errorf("query cobr: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*recurrence.CobR
	for rows.Next() {
		c, err := scanCobR(rows)
		if err != nil {
			return nil, fmt.Errorf("scan cobr: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cobr: %w", err)
	}
	return out, nil
}

// scanner is the row-scanning surface shared by QueryRow and Query iteration.
type scanner interface {
	Scan(dest ...any) error
}

func scanCobR(s scanner) (*recurrence.CobR, error) {
	var txID, idRec, tenantID, vencimento, status, createdAt, updatedAt string
	var valorCents int64
	if err := s.Scan(&txID, &idRec, &tenantID, &vencimento, &valorCents, &status, &createdAt, &updatedAt); err != nil {
		return nil, err
	}
	return recurrence.RehydrateCobR(txID, idRec, tenantID, vencimento, valorCents,
		recurrence.CobRStatus(status), parseTime(createdAt), parseTime(updatedAt)), nil
}
