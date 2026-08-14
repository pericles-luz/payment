package app

import (
	"context"

	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// directRepo composes the individual repository ports wired in Deps into a single
// ports.Repository. It is used by the autocommit fallback unit of work, where a
// transactional UoW was not supplied.
type directRepo struct {
	ports.PaymentRepository
	ports.TenantRepository
	ports.PricingRepository
	ports.LedgerRepository
	ports.ProcessedEventStore
	ports.RecRepository
	ports.CobRRepository
	ports.AuditLog
	ports.PIIAccessRecorder
}

// autocommitUoW runs fn against the repositories directly, with no surrounding
// transaction: every write autocommits on its own. This is the fallback when
// Deps.UoW is nil — it preserves the pre-transactional behaviour for unit tests
// that inject per-port fakes. Production wiring supplies a real transactional
// UnitOfWork (the SQLite adapter) so multi-write use-cases are all-or-nothing.
type autocommitUoW struct{ repo ports.Repository }

func (u autocommitUoW) WithinTx(ctx context.Context, fn func(ports.Repository) error) error {
	return fn(u.repo)
}

// resolveUoW returns the configured transactional UnitOfWork, or an autocommit
// fallback composed from the individual ports in d.
func resolveUoW(d Deps) ports.UnitOfWork {
	if d.UoW != nil {
		return d.UoW
	}
	a := d.Audit
	if a == nil {
		// Keep the autocommit fallback panic-free when a use-case appends audit
		// through the unit of work but no audit log was wired (unit tests with
		// per-port fakes); production wires a real one (footgun guarded elsewhere).
		a = noopAudit{}
	}
	pii := d.PIIAccess
	if pii == nil {
		// Same footgun-guard for the PII access recorder: a use-case that mediates a
		// PII read through the unit of work must not panic when no recorder was wired
		// (unit tests with per-port fakes). Production wires a real append-only one.
		pii = noopPIIAccess{}
	}
	return autocommitUoW{repo: directRepo{
		PaymentRepository:   d.Payments,
		TenantRepository:    d.Tenants,
		PricingRepository:   d.Pricing,
		LedgerRepository:    d.Ledger,
		ProcessedEventStore: d.Processed,
		RecRepository:       d.Recs,
		CobRRepository:      d.CobRs,
		AuditLog:            a,
		PIIAccessRecorder:   pii,
	}}
}
