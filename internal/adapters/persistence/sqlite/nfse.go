package sqlite

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/nfse"
	"github.com/ia-dev-sindireceita/payment/internal/nfse/custody"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// This file persists the NFS-e emitter state (migration 0020): emission records
// (nfse_emissions), the DPS numbering (nfse_dps_sequences) and the PUBLIC side
// of the A1 certificates (nfse_a1_certs). The private keys never reach this
// database — they are non-exportable keys behind custody.FiscalSigner.

var (
	_ ports.NFSeEmissionRepository = repo{}
	_ ports.NFSeStore              = (*Store)(nil)
	_ custody.CertStore            = (*NFSeCertStore)(nil)
	_ custody.CertLister           = (*NFSeCertStore)(nil)
)

const nfseEmissionColumns = `id, tenant_id, idempotency_key, emitter_cnpj, competencia_year, competencia_month, competencia_day,
	service_value_cents, series, number, tomador_doc, tomador_nome, status, chave_acesso, nfse_number,
	dps_id, rejection_code, rejection_message, nfse_xml, created_at`

// SaveNFSeEmission upserts an emission keyed by id. The DANFSe cache column is
// never touched here. A clash on the (tenant, idempotency key) index with a
// different id is shared.ErrConflict.
func (r repo) SaveNFSeEmission(ctx context.Context, e nfse.Emission) error {
	now := time.Now().UTC().Format(tsLayout)
	_, err := r.q.ExecContext(ctx,
		`INSERT INTO nfse_emissions (`+nfseEmissionColumns+`, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		    series = excluded.series, number = excluded.number,
		    tomador_doc = excluded.tomador_doc, tomador_nome = excluded.tomador_nome,
		    status = excluded.status, chave_acesso = excluded.chave_acesso,
		    nfse_number = excluded.nfse_number, dps_id = excluded.dps_id,
		    rejection_code = excluded.rejection_code, rejection_message = excluded.rejection_message,
		    nfse_xml = excluded.nfse_xml, updated_at = excluded.updated_at`,
		nfseEmissionArgs(e, now)...)
	if err != nil {
		if isUniqueViolation(err) {
			return shared.ErrConflict
		}
		return fmt.Errorf("save nfse emission: %w", err)
	}
	return nil
}

func nfseEmissionArgs(e nfse.Emission, now string) []any {
	var xml any
	if len(e.XML) > 0 {
		xml = e.XML
	}
	return []any{e.ID, e.TenantID, e.IdempotencyKey, e.EmitterCNPJ, e.Competencia.Year, e.Competencia.Month, e.Competencia.Day,
		e.ServiceValueCents, e.Series, e.Number, e.TomadorDocument, e.TomadorName, string(e.Status),
		e.ChaveAcesso, e.NFSeNumber, e.DPSID, e.RejectionCode, e.RejectionMessage, xml,
		e.CreatedAt.UTC().Format(tsLayout), now}
}

// FindNFSeEmission returns a tenant-scoped emission or shared.ErrNotFound.
func (r repo) FindNFSeEmission(ctx context.Context, tenantID, id string) (nfse.Emission, error) {
	return scanNFSeEmission(r.q.QueryRowContext(ctx,
		`SELECT `+nfseEmissionColumns+` FROM nfse_emissions WHERE tenant_id = ? AND id = ?`, tenantID, id))
}

// FindNFSeEmissionByIdempotencyKey returns the emission holding (tenant, key).
func (s *Store) FindNFSeEmissionByIdempotencyKey(ctx context.Context, tenantID, key string) (nfse.Emission, error) {
	if key == "" {
		return nfse.Emission{}, shared.ErrNotFound
	}
	return scanNFSeEmission(s.db.QueryRowContext(ctx,
		`SELECT `+nfseEmissionColumns+` FROM nfse_emissions WHERE tenant_id = ? AND idempotency_key = ?`, tenantID, key))
}

func scanNFSeEmission(row *sql.Row) (nfse.Emission, error) {
	var e nfse.Emission
	var status, createdAt string
	var xml []byte
	if err := row.Scan(&e.ID, &e.TenantID, &e.IdempotencyKey, &e.EmitterCNPJ, &e.Competencia.Year,
		&e.Competencia.Month, &e.Competencia.Day, &e.ServiceValueCents, &e.Series, &e.Number, &e.TomadorDocument, &e.TomadorName,
		&status, &e.ChaveAcesso, &e.NFSeNumber, &e.DPSID, &e.RejectionCode, &e.RejectionMessage, &xml,
		&createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nfse.Emission{}, shared.ErrNotFound
		}
		return nfse.Emission{}, fmt.Errorf("scan nfse emission: %w", err)
	}
	e.Status = nfse.Status(status)
	e.CreatedAt = parseTime(createdAt)
	if len(xml) > 0 {
		e.XML = xml
	}
	return e, nil
}

// ReserveNFSeEmission claims (tenant, idempotency key) for p; see
// ports.NFSeStore. It runs in one transaction: insert-if-free, otherwise
// inspect the holder and, when it is a stale pending row, replace it.
func (s *Store) ReserveNFSeEmission(ctx context.Context, p nfse.Emission, staleBefore time.Time) (nfse.Emission, bool, error) {
	if p.IdempotencyKey == "" {
		return nfse.Emission{}, false, nfse.ErrEmptyIdempotencyKey
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nfse.Emission{}, false, fmt.Errorf("begin reserve tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	insert := func() (bool, error) {
		res, err := tx.ExecContext(ctx,
			`INSERT INTO nfse_emissions (`+nfseEmissionColumns+`, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT (tenant_id, idempotency_key) WHERE idempotency_key <> '' DO NOTHING`,
			nfseEmissionArgs(p, time.Now().UTC().Format(tsLayout))...)
		if err != nil {
			return false, fmt.Errorf("reserve nfse emission: %w", err)
		}
		n, err := res.RowsAffected()
		return n == 1, err
	}
	ok, err := insert()
	if err != nil {
		return nfse.Emission{}, false, err
	}
	if ok {
		return nfse.Emission{}, true, tx.Commit()
	}
	prior, err := scanNFSeEmission(tx.QueryRowContext(ctx,
		`SELECT `+nfseEmissionColumns+` FROM nfse_emissions WHERE tenant_id = ? AND idempotency_key = ?`,
		p.TenantID, p.IdempotencyKey))
	if err != nil {
		return nfse.Emission{}, false, err
	}
	if prior.Status != nfse.StatusPending {
		return prior, false, nil
	}
	if !prior.CreatedAt.Before(staleBefore) {
		return nfse.Emission{}, false, nfse.ErrEmissionInFlight
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM nfse_emissions WHERE id = ? AND status = 'pending'`, prior.ID); err != nil {
		return nfse.Emission{}, false, fmt.Errorf("take over nfse reservation: %w", err)
	}
	if ok, err = insert(); err != nil {
		return nfse.Emission{}, false, err
	}
	if !ok {
		return nfse.Emission{}, false, nfse.ErrEmissionInFlight
	}
	return prior, true, tx.Commit()
}

// ReleaseNFSeEmission drops a pending reservation; a finished row is kept.
func (s *Store) ReleaseNFSeEmission(ctx context.Context, tenantID, key, id string) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM nfse_emissions WHERE tenant_id = ? AND idempotency_key = ? AND id = ? AND status = 'pending'`,
		tenantID, key, id); err != nil {
		return fmt.Errorf("release nfse reservation: %w", err)
	}
	return nil
}

// NextDPSNumber increments the (CNPJ, série) sequence atomically.
func (s *Store) NextDPSNumber(ctx context.Context, emitterCNPJ, series string) (int64, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx,
		`INSERT INTO nfse_dps_sequences (emitter_cnpj, series, last_number) VALUES (?, ?, 1)
		 ON CONFLICT (emitter_cnpj, series) DO UPDATE SET last_number = nfse_dps_sequences.last_number + 1
		 RETURNING last_number`, emitterCNPJ, series).Scan(&n); err != nil {
		return 0, fmt.Errorf("next dps number: %w", err)
	}
	return n, nil
}

// SaveNFSeDANFSe caches the PDF on a tenant-owned emission.
func (s *Store) SaveNFSeDANFSe(ctx context.Context, tenantID, id string, pdf []byte) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE nfse_emissions SET danfse_pdf = ? WHERE tenant_id = ? AND id = ?`, pdf, tenantID, id)
	if err != nil {
		return fmt.Errorf("save danfse: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return shared.ErrNotFound
	}
	return nil
}

// FindNFSeDANFSe returns the cached PDF or shared.ErrNotFound.
func (s *Store) FindNFSeDANFSe(ctx context.Context, tenantID, id string) ([]byte, error) {
	var pdf []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT danfse_pdf FROM nfse_emissions WHERE tenant_id = ? AND id = ?`, tenantID, id).Scan(&pdf)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && len(pdf) == 0) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find danfse: %w", err)
	}
	return pdf, nil
}

// NFSeCertStore is the durable custody.CertStore: the public chain and the
// non-secret metadata of each company's A1 certificate.
type NFSeCertStore struct{ db *sql.DB }

// NFSeCerts returns the certificate store backed by this database.
func (s *Store) NFSeCerts() *NFSeCertStore { return &NFSeCertStore{db: s.db} }

// PutA1 upserts companyID's certificate (one active certificate per company).
func (c *NFSeCertStore) PutA1(ctx context.Context, companyID string, chain []*x509.Certificate, meta custody.A1Meta) error {
	if companyID == "" {
		return custody.ErrEmptyCompanyID
	}
	pemStr, err := custody.EncodeChainPEM(chain)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(tsLayout)
	if _, err := c.db.ExecContext(ctx,
		`INSERT INTO nfse_a1_certs (company_id, serial, subject, not_after, cnpj_hash, chain_pem, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (company_id) DO UPDATE SET serial = excluded.serial, subject = excluded.subject,
		    not_after = excluded.not_after, cnpj_hash = excluded.cnpj_hash, chain_pem = excluded.chain_pem,
		    updated_at = excluded.updated_at`,
		companyID, meta.Serial, meta.Subject, meta.NotAfter.UTC().Format(tsLayout), meta.CNPJHash, pemStr, now, now); err != nil {
		return fmt.Errorf("put a1: %w", err)
	}
	return nil
}

// Get returns companyID's chain and metadata, or custody.ErrCertNotFound.
func (c *NFSeCertStore) Get(ctx context.Context, companyID string) ([]*x509.Certificate, custody.A1Meta, error) {
	if companyID == "" {
		return nil, custody.A1Meta{}, custody.ErrEmptyCompanyID
	}
	var meta custody.A1Meta
	var notAfter, pemStr string
	err := c.db.QueryRowContext(ctx,
		`SELECT serial, subject, not_after, cnpj_hash, chain_pem FROM nfse_a1_certs WHERE company_id = ?`, companyID).
		Scan(&meta.Serial, &meta.Subject, &notAfter, &meta.CNPJHash, &pemStr)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, custody.A1Meta{}, custody.ErrCertNotFound
	}
	if err != nil {
		return nil, custody.A1Meta{}, fmt.Errorf("get a1: %w", err)
	}
	chain, err := custody.DecodeChainPEM(pemStr)
	if err != nil {
		return nil, custody.A1Meta{}, err
	}
	meta.NotAfter = parseTime(notAfter)
	return chain, meta, nil
}

// Delete removes companyID's certificate metadata (idempotent).
func (c *NFSeCertStore) Delete(ctx context.Context, companyID string) error {
	if companyID == "" {
		return custody.ErrEmptyCompanyID
	}
	if _, err := c.db.ExecContext(ctx, `DELETE FROM nfse_a1_certs WHERE company_id = ?`, companyID); err != nil {
		return fmt.Errorf("delete a1: %w", err)
	}
	return nil
}

// ListMeta lists every certificate's metadata for the expiry sweep.
func (c *NFSeCertStore) ListMeta(ctx context.Context) ([]custody.CertMeta, error) {
	rows, err := c.db.QueryContext(ctx,
		`SELECT company_id, serial, subject, not_after, cnpj_hash FROM nfse_a1_certs ORDER BY not_after`)
	if err != nil {
		return nil, fmt.Errorf("list a1: %w", err)
	}
	defer rows.Close()
	var out []custody.CertMeta
	for rows.Next() {
		var cm custody.CertMeta
		var notAfter string
		if err := rows.Scan(&cm.CompanyID, &cm.Meta.Serial, &cm.Meta.Subject, &notAfter, &cm.Meta.CNPJHash); err != nil {
			return nil, fmt.Errorf("scan a1: %w", err)
		}
		cm.Meta.NotAfter = parseTime(notAfter)
		out = append(out, cm)
	}
	return out, rows.Err()
}
