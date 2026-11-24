package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/nfse"
	"github.com/ia-dev-sindireceita/payment/internal/nfse/a1import"
	"github.com/ia-dev-sindireceita/payment/internal/nfse/custody"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// NFSeEmitEndpoint is the billing-ledger endpoint of an authorised NFS-e. While
// no price is configured for a tenant it is free (resolvePriceOrFree), but every
// authorised emission still writes a ledger entry, so it is counted in the
// console's Consumo and Faturas.
const NFSeEmitEndpoint = "nfse.emit"

// DefaultNFSeSeries is the DPS série used when the client informs none.
const DefaultNFSeSeries = "1"

// NFSeTransport is the ADN adapter: it transmits the DPS and downloads the
// DANFSe (internal/nfse/adn implements it).
type NFSeTransport interface {
	nfse.Transmitter
	GetDANFSe(ctx context.Context, companyID, chaveAcesso string) ([]byte, error)
}

// NFSeCertImporter imports an A1 (PKCS#12) certificate into custody
// (internal/nfse/a1import implements it).
type NFSeCertImporter interface {
	Import(ctx context.Context, tenantID string, pfx []byte, password, expectedCNPJ string) (a1import.Result, error)
	Certificate(ctx context.Context, tenantID, cnpj string) (custody.A1Meta, error)
}

// NFSeDeps are the NFS-e specific ports.
type NFSeDeps struct {
	Store    ports.NFSeStore
	Certs    custody.CertStore
	Signer   custody.FiscalSigner
	ADN      NFSeTransport
	Importer NFSeCertImporter
	// Environment is the ADN tpAmb; zero means homologação (produção restrita).
	Environment nfse.Environment
}

// NFSeService emits NFS-e (padrão nacional) for the authenticated tenant. The
// emitter certificate is custodied per (tenant, CNPJ); the DPS numbering is the
// gateway's (several products emit for the same CNPJ); an authorised emission
// and its ledger entry commit in one transaction.
type NFSeService struct {
	tenants ports.TenantRepository
	pricing ports.PricingRepository
	clock   ports.Clock
	ids     ports.IDProvider
	uow     ports.UnitOfWork
	audit   ports.AuditLog
	nd      NFSeDeps
}

// NewNFSeService wires the NFS-e use-case.
func NewNFSeService(d Deps, nd NFSeDeps) *NFSeService {
	if nd.Environment == 0 {
		nd.Environment = nfse.EnvHomologacao
	}
	return &NFSeService{
		tenants: d.Tenants,
		pricing: d.Pricing,
		clock:   d.Clock,
		ids:     d.IDs,
		uow:     resolveUoW(d),
		audit:   d.Audit,
		nd:      nd,
	}
}

// EmitNFSeInput is the validated boundary input of an emission. TenantID and
// AccountID come from the authenticated credential, never from the body.
type EmitNFSeInput struct {
	TenantID       string
	AccountID      string
	IdempotencyKey string

	EmitterCNPJ             string
	Series                  string
	Competencia             nfse.Competencia
	MunicipalityCode        string
	EmitterMunicipalityCode string
	ServiceCode             string
	Description             string
	ValueCents              int64
	Regime                  nfse.SimplesNacional
	SimplesTaxRateBps       int
	Tomador                 *nfse.Tomador
	MunicipalServiceCode    string
	NBSCode                 string
}

// Emit transmits a DPS and returns the stored emission. Idempotent on
// (tenant, Idempotency-Key): a replay returns the first result and is not
// counted again. An ADN rejection returns the rejected record together with a
// *nfse.BusinessError.
func (s *NFSeService) Emit(ctx context.Context, in EmitNFSeInput) (nfse.Emission, error) {
	t, err := s.tenants.FindTenantByID(ctx, in.TenantID)
	if err != nil {
		return nfse.Emission{}, fmt.Errorf("resolve tenant: %w", err)
	}
	if !t.Active() {
		return nfse.Emission{}, shared.NewValidationError("tenant", "tenant is not active")
	}
	if in.IdempotencyKey == "" {
		return nfse.Emission{}, shared.NewValidationError("idempotency_key", "idempotency key is required")
	}
	price, err := resolvePriceOrFree(ctx, s.pricing, in.TenantID, NFSeEmitEndpoint)
	if err != nil {
		return nfse.Emission{}, err
	}
	comp := in.Competencia
	if comp == (nfse.Competencia{}) {
		// Default: the emission date, as the portal nacional does.
		comp = nfse.CompetenciaOn(s.clock.Now())
	}
	series := in.Series
	if series == "" {
		series = DefaultNFSeSeries
	}

	store := &billedNFSeStore{svc: s, tenantID: in.TenantID, accountID: in.AccountID, priceCents: price.PriceCents()}
	emitter := nfse.NewEmitter(s.nd.Certs, s.nd.Signer, s.nd.ADN, store,
		nfse.WithEnvironment(s.nd.Environment),
		nfse.WithSequencer(s.nd.Store),
		nfse.WithClock(s.clock.Now),
	)
	return emitter.Emit(ctx, nfse.EmitCommand{
		CompanyID:               custody.CompanyIDFor(in.TenantID, in.EmitterCNPJ),
		TenantID:                in.TenantID,
		IdempotencyKey:          in.IdempotencyKey,
		EmitterCNPJ:             in.EmitterCNPJ,
		Series:                  series,
		Competencia:             comp,
		MunicipalityCode:        in.MunicipalityCode,
		Description:             in.Description,
		ServiceValueCents:       in.ValueCents,
		ServiceCode:             in.ServiceCode,
		Regime:                  in.Regime,
		SimplesTaxRateBps:       in.SimplesTaxRateBps,
		EmitterMunicipalityCode: in.EmitterMunicipalityCode,
		Tomador:                 in.Tomador,
		MunicipalServiceCode:    in.MunicipalServiceCode,
		NBSCode:                 in.NBSCode,
	})
}

// Get returns a tenant-scoped emission (shared.ErrNotFound for another
// tenant's id, without disclosing it exists).
func (s *NFSeService) Get(ctx context.Context, tenantID, id string) (nfse.Emission, error) {
	return s.nd.Store.FindNFSeEmission(ctx, tenantID, id)
}

// DANFSe returns the official PDF of an authorised emission: from the local
// cache, else downloaded from the ADN and cached. nfse.ErrDANFSeUnavailable
// when the emission is not authorised or the ADN has no PDF for it.
func (s *NFSeService) DANFSe(ctx context.Context, tenantID, id string) ([]byte, error) {
	em, err := s.Get(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if em.Status != nfse.StatusAuthorized || em.ChaveAcesso == "" {
		return nil, nfse.ErrDANFSeUnavailable
	}
	pdf, err := s.nd.Store.FindNFSeDANFSe(ctx, tenantID, id)
	if err == nil {
		return pdf, nil
	}
	if !errors.Is(err, shared.ErrNotFound) {
		return nil, err
	}
	pdf, err = s.nd.ADN.GetDANFSe(ctx, custody.CompanyIDFor(tenantID, em.EmitterCNPJ), em.ChaveAcesso)
	if err != nil {
		return nil, err
	}
	if cerr := s.nd.Store.SaveNFSeDANFSe(ctx, tenantID, id, pdf); cerr != nil {
		// The PDF is served anyway; the next request downloads it again.
		slog.WarnContext(ctx, "nfse.danfse_cache_failed", slog.String("tenant_id", tenantID),
			slog.String("emission_id", id), slog.String("error", cerr.Error()))
	}
	return pdf, nil
}

// ImportCertificate custodies the tenant's A1 certificate for cnpj and
// records it in the audit trail (who/which tenant/when; never key material).
// The tenant must exist: the admin route takes it from the path.
func (s *NFSeService) ImportCertificate(ctx context.Context, tenantID string, pfx []byte, password, cnpj string) (a1import.Result, error) {
	if s.nd.Importer == nil {
		return a1import.Result{}, ErrNFSeCertImportUnavailable
	}
	if _, err := s.tenants.FindTenantByID(ctx, tenantID); err != nil {
		return a1import.Result{}, fmt.Errorf("resolve tenant: %w", err)
	}
	res, err := s.nd.Importer.Import(ctx, tenantID, pfx, password, cnpj)
	if err != nil {
		return a1import.Result{}, err
	}
	if s.audit != nil {
		e, aerr := audit.NewEntry(s.ids.NewID(), OperatorIDFromContext(ctx), audit.ActionSetNFSeCertificate, tenantID, s.clock.Now())
		if aerr == nil {
			aerr = s.audit.Append(ctx, e)
		}
		if aerr != nil {
			// The certificate is already in custody; a lost audit record is
			// logged loudly rather than reported as a failed import.
			slog.ErrorContext(ctx, "nfse.certificate_audit_failed", slog.String("tenant_id", tenantID),
				slog.String("error", aerr.Error()))
		}
	}
	return res, nil
}

// Certificate returns the metadata of the tenant's certificate for cnpj.
func (s *NFSeService) Certificate(ctx context.Context, tenantID, cnpj string) (custody.A1Meta, error) {
	if s.nd.Importer == nil {
		return custody.A1Meta{}, ErrNFSeCertImportUnavailable
	}
	return s.nd.Importer.Certificate(ctx, tenantID, cnpj)
}

// ErrNFSeCertImportUnavailable is returned when no key custody is configured.
var ErrNFSeCertImportUnavailable = errors.New("nfse: certificate import is not configured")

// billedNFSeStore adapts ports.NFSeStore to nfse.Store for ONE emission
// request, and is where counting happens: the save that first marks an
// emission authorised appends its "nfse.emit" ledger entry in the same
// transaction. A replay or re-save of an already authorised record is never
// counted twice.
type billedNFSeStore struct {
	svc        *NFSeService
	tenantID   string
	accountID  string
	priceCents int64
}

var _ nfse.Store = (*billedNFSeStore)(nil)

func (b *billedNFSeStore) Reserve(ctx context.Context, p nfse.Emission, staleBefore time.Time) (nfse.Emission, bool, error) {
	return b.svc.nd.Store.ReserveNFSeEmission(ctx, p, staleBefore)
}

func (b *billedNFSeStore) Release(ctx context.Context, tenantID, key, id string) error {
	return b.svc.nd.Store.ReleaseNFSeEmission(ctx, tenantID, key, id)
}

func (b *billedNFSeStore) GetByID(ctx context.Context, tenantID, id string) (nfse.Emission, error) {
	return mapNFSeNotFound(b.svc.nd.Store.FindNFSeEmission(ctx, tenantID, id))
}

func (b *billedNFSeStore) GetByIdempotencyKey(ctx context.Context, tenantID, key string) (nfse.Emission, error) {
	return mapNFSeNotFound(b.svc.nd.Store.FindNFSeEmissionByIdempotencyKey(ctx, tenantID, key))
}

func (b *billedNFSeStore) Save(ctx context.Context, e nfse.Emission) error {
	return b.svc.uow.WithinTx(ctx, func(r ports.Repository) error {
		prev, err := r.FindNFSeEmission(ctx, e.TenantID, e.ID)
		if err != nil && !errors.Is(err, shared.ErrNotFound) {
			return fmt.Errorf("reload nfse emission: %w", err)
		}
		alreadyCounted := err == nil && prev.Status == nfse.StatusAuthorized
		if err := r.SaveNFSeEmission(ctx, e); err != nil {
			return fmt.Errorf("save nfse emission: %w", err)
		}
		if e.Status != nfse.StatusAuthorized || alreadyCounted {
			return nil
		}
		entry, err := billing.NewLedgerEntry(b.svc.ids.NewID(), b.tenantID, NFSeEmitEndpoint, e.ID,
			b.priceCents, b.svc.clock.Now(), billing.WithAccount(b.accountID))
		if err != nil {
			return err
		}
		if err := r.AppendLedgerEntry(ctx, entry); err != nil {
			return fmt.Errorf("append ledger: %w", err)
		}
		return nil
	})
}

func mapNFSeNotFound(e nfse.Emission, err error) (nfse.Emission, error) {
	if errors.Is(err, shared.ErrNotFound) {
		return nfse.Emission{}, nfse.ErrNotFound
	}
	return e, err
}
