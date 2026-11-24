package app_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	persistence "github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/nfse"
	"github.com/ia-dev-sindireceita/payment/internal/nfse/a1import"
	"github.com/ia-dev-sindireceita/payment/internal/nfse/custody"
)

const (
	nfseCNPJ    = "67188163000110" // LHMOST
	nfseTomador = "57151944000187" // Syndeotech
)

var nfseNow = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

// fakeADN scripts the ADN: Transmit answers receipt/err, GetDANFSe pdf/pdfErr.
type fakeADN struct {
	mu        sync.Mutex
	calls     int
	pdfCalls  int
	receipt   nfse.Receipt
	err       error
	pdf       []byte
	pdfErr    error
	lastChave string
}

func (f *fakeADN) Transmit(_ context.Context, _ string, _ []byte) (nfse.Receipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.receipt, f.err
}

func (f *fakeADN) GetDANFSe(_ context.Context, _ string, chave string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pdfCalls++
	f.lastChave = chave
	return f.pdf, f.pdfErr
}

type nfseHarness struct {
	store  *persistence.Store
	svc    *app.NFSeService
	admin  *app.AdminService
	adn    *fakeADN
	tenant string
	deps   app.Deps
	nd     app.NFSeDeps
}

// newNFSeHarness wires the NFS-e service over the in-memory store with a
// local test signer holding an A1 for nfseCNPJ under the created tenant.
func newNFSeHarness(t *testing.T) *nfseHarness {
	t.Helper()
	h := newHarness(t)
	h.deps.Clock = fixedClock{t: nfseNow}
	h.deps.Audit = h.store
	admin := app.NewAdminService(h.deps)
	tn, err := admin.CreateTenant(context.Background(), "LHMOST")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	signer := custody.NewLocalTestSigner(custody.WithClock(func() time.Time { return nfseNow }))
	companyID := custody.CompanyIDFor(tn.ID(), nfseCNPJ)
	chain, meta, err := signer.Provision(companyID, nfseCNPJ, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if err := h.store.NFSeCerts().PutA1(context.Background(), companyID, chain, meta); err != nil {
		t.Fatalf("put a1: %v", err)
	}
	fa := &fakeADN{receipt: nfse.Receipt{ChaveAcesso: "35261167188163000110000000000000001123456789012345", NFSeNumber: "17", XML: []byte("<NFSe/>")}}
	nd := app.NFSeDeps{Store: h.store, Certs: h.store.NFSeCerts(), Signer: signer, ADN: fa}
	return &nfseHarness{
		store: h.store, svc: app.NewNFSeService(h.deps, nd), admin: admin, adn: fa,
		tenant: tn.ID(), deps: h.deps, nd: nd,
	}
}

func (h *nfseHarness) input(key string) app.EmitNFSeInput {
	return app.EmitNFSeInput{
		TenantID:          h.tenant,
		AccountID:         "acct-lhmost",
		IdempotencyKey:    key,
		EmitterCNPJ:       nfseCNPJ,
		Competencia:       nfse.Competencia{Year: 2026, Month: 10},
		MunicipalityCode:  "3550308",
		ServiceCode:       "010501",
		Description:       "Licenciamento do catálogo — outubro/2026",
		ValueCents:        269000,
		Regime:            nfse.SimplesMEEPP,
		SimplesTaxRateBps: 600,
		Tomador:           &nfse.Tomador{Document: nfseTomador, Name: "SYNDEOTECH ASSESSORIA E CONSULTORIA LTDA"},
	}
}

func (h *nfseHarness) ledger(t *testing.T) []string {
	t.Helper()
	entries, err := h.store.ListLedgerEntries(context.Background(), h.tenant)
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	var refs []string
	for _, e := range entries {
		if e.Endpoint() == app.NFSeEmitEndpoint {
			refs = append(refs, e.Reference())
		}
	}
	return refs
}

func TestNFSeEmitCountsAuthorisedEmissionForFree(t *testing.T) {
	t.Parallel()
	h := newNFSeHarness(t)
	em, err := h.svc.Emit(context.Background(), h.input("invoice:2026-0010"))
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if em.Status != nfse.StatusAuthorized || em.Number != "1" || em.Series != app.DefaultNFSeSeries {
		t.Fatalf("emission = %+v", em)
	}
	if em.Competencia != (nfse.Competencia{Year: 2026, Month: 10}) {
		t.Errorf("explicit competência changed: %+v", em.Competencia)
	}
	if em.TomadorDocument != nfseTomador || string(em.XML) != "<NFSe/>" {
		t.Errorf("tomador/xml not kept: %+v", em)
	}
	entries, _ := h.store.ListLedgerEntries(context.Background(), h.tenant)
	if len(entries) != 1 {
		t.Fatalf("ledger entries = %d, want 1", len(entries))
	}
	e := entries[0]
	if e.Endpoint() != app.NFSeEmitEndpoint || e.PriceCents() != 0 || e.Reference() != em.ID || e.AccountID() != "acct-lhmost" {
		t.Errorf("ledger entry = %s/%d/%s/%s", e.Endpoint(), e.PriceCents(), e.Reference(), e.AccountID())
	}
	got, err := h.svc.Get(context.Background(), h.tenant, em.ID)
	if err != nil || got.ChaveAcesso != em.ChaveAcesso {
		t.Fatalf("get = %+v, %v", got, err)
	}
}

func TestNFSeEmitReplayIsNotCountedTwice(t *testing.T) {
	t.Parallel()
	h := newNFSeHarness(t)
	first, err := h.svc.Emit(context.Background(), h.input("k1"))
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	again, err := h.svc.Emit(context.Background(), h.input("k1"))
	if err != nil || again.ID != first.ID {
		t.Fatalf("replay = %+v, %v", again, err)
	}
	if h.adn.calls != 1 {
		t.Errorf("ADN calls = %d, want 1", h.adn.calls)
	}
	if refs := h.ledger(t); len(refs) != 1 {
		t.Errorf("ledger = %v, want one entry", refs)
	}
	second, err := h.svc.Emit(context.Background(), h.input("k2"))
	if err != nil {
		t.Fatalf("second emit: %v", err)
	}
	if second.Number != "2" {
		t.Errorf("second number = %s, want 2", second.Number)
	}
	if refs := h.ledger(t); len(refs) != 2 {
		t.Errorf("ledger = %v, want two entries", refs)
	}
}

func TestNFSeEmitUsesConfiguredPrice(t *testing.T) {
	t.Parallel()
	h := newNFSeHarness(t)
	if _, err := h.admin.SetEndpointPrice(context.Background(), h.tenant, app.NFSeEmitEndpoint, 15); err != nil {
		t.Fatalf("price: %v", err)
	}
	if _, err := h.svc.Emit(context.Background(), h.input("k1")); err != nil {
		t.Fatalf("emit: %v", err)
	}
	entries, _ := h.store.ListLedgerEntries(context.Background(), h.tenant)
	if len(entries) != 1 || entries[0].PriceCents() != 15 {
		t.Fatalf("entries = %v", entries)
	}
}

func TestNFSeEmitRejectionIsNotCounted(t *testing.T) {
	t.Parallel()
	h := newNFSeHarness(t)
	h.adn.err = &nfse.BusinessError{HTTPStatus: 400, Items: []nfse.BusinessErrorItem{{Code: "E0014", Message: "DPS duplicada"}}}
	em, err := h.svc.Emit(context.Background(), h.input("k1"))
	if _, ok := nfse.AsBusinessError(err); !ok {
		t.Fatalf("err = %v, want BusinessError", err)
	}
	if em.Status != nfse.StatusRejected || em.RejectionCode != "E0014" {
		t.Errorf("emission = %+v", em)
	}
	if refs := h.ledger(t); len(refs) != 0 {
		t.Errorf("rejection counted: %v", refs)
	}
	if got, err := h.svc.Get(context.Background(), h.tenant, em.ID); err != nil || got.Status != nfse.StatusRejected {
		t.Errorf("rejected record not readable: %+v %v", got, err)
	}
}

func TestNFSeEmitTransportFailureReleasesKey(t *testing.T) {
	t.Parallel()
	h := newNFSeHarness(t)
	h.adn.err = &nfse.TransportError{Op: "do", Err: errors.New("timeout")}
	if _, err := h.svc.Emit(context.Background(), h.input("k1")); err == nil {
		t.Fatal("want transport error")
	}
	h.adn.err = nil
	em, err := h.svc.Emit(context.Background(), h.input("k1"))
	if err != nil || em.Status != nfse.StatusAuthorized {
		t.Fatalf("retry = %+v, %v", em, err)
	}
	if refs := h.ledger(t); len(refs) != 1 {
		t.Errorf("ledger = %v", refs)
	}
}

func TestNFSeEmitGuards(t *testing.T) {
	t.Parallel()
	h := newNFSeHarness(t)
	in := h.input("")
	if _, err := h.svc.Emit(context.Background(), in); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("missing key: %v", err)
	}
	in = h.input("k")
	in.TenantID = "missing"
	if _, err := h.svc.Emit(context.Background(), in); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("unknown tenant: %v", err)
	}
	in = h.input("k")
	in.EmitterCNPJ = nfseTomador // no certificate for this CNPJ
	if _, err := h.svc.Emit(context.Background(), in); !errors.Is(err, nfse.ErrNoCertificate) {
		t.Errorf("no cert: %v", err)
	}
	tn, _ := h.store.FindTenantByID(context.Background(), h.tenant)
	tn.Deactivate()
	_ = h.store.SaveTenant(context.Background(), tn)
	if _, err := h.svc.Emit(context.Background(), h.input("k")); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("inactive tenant: %v", err)
	}
}

func TestNFSeGetIsTenantScoped(t *testing.T) {
	t.Parallel()
	h := newNFSeHarness(t)
	em, err := h.svc.Emit(context.Background(), h.input("k1"))
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	other, _ := h.admin.CreateTenant(context.Background(), "Outra")
	if _, err := h.svc.Get(context.Background(), other.ID(), em.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	if _, err := h.svc.DANFSe(context.Background(), other.ID(), em.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant pdf: %v", err)
	}
}

func TestNFSeDANFSeIsFetchedOnceAndCached(t *testing.T) {
	t.Parallel()
	h := newNFSeHarness(t)
	h.adn.pdf = []byte("%PDF-1.7 danfse")
	em, err := h.svc.Emit(context.Background(), h.input("k1"))
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	for i := 0; i < 2; i++ {
		pdf, err := h.svc.DANFSe(context.Background(), h.tenant, em.ID)
		if err != nil || string(pdf) != "%PDF-1.7 danfse" {
			t.Fatalf("pdf = %q, %v", pdf, err)
		}
	}
	if h.adn.pdfCalls != 1 || h.adn.lastChave != em.ChaveAcesso {
		t.Errorf("ADN pdf calls = %d chave = %s", h.adn.pdfCalls, h.adn.lastChave)
	}
}

func TestNFSeDANFSeUnavailable(t *testing.T) {
	t.Parallel()
	h := newNFSeHarness(t)
	h.adn.err = &nfse.BusinessError{HTTPStatus: 400}
	rej, _ := h.svc.Emit(context.Background(), h.input("k1"))
	if _, err := h.svc.DANFSe(context.Background(), h.tenant, rej.ID); !errors.Is(err, nfse.ErrDANFSeUnavailable) {
		t.Errorf("rejected pdf: %v", err)
	}
	h.adn.err = nil
	h.adn.pdfErr = &nfse.TransportError{Op: "do", Err: errors.New("down")}
	ok, _ := h.svc.Emit(context.Background(), h.input("k2"))
	var te *nfse.TransportError
	if _, err := h.svc.DANFSe(context.Background(), h.tenant, ok.ID); !errors.As(err, &te) {
		t.Errorf("transport pdf: %v", err)
	}
}

type fakeImporter struct {
	err  error
	got  string
	meta custody.A1Meta
}

func (f *fakeImporter) Import(_ context.Context, tenantID string, _ []byte, _, cnpj string) (a1import.Result, error) {
	f.got = tenantID + "/" + cnpj
	if f.err != nil {
		return a1import.Result{}, f.err
	}
	return a1import.Result{CompanyID: custody.CompanyIDFor(tenantID, cnpj), CNPJ: cnpj, Meta: f.meta}, nil
}

func (f *fakeImporter) Certificate(_ context.Context, _, _ string) (custody.A1Meta, error) {
	if f.err != nil {
		return custody.A1Meta{}, f.err
	}
	return f.meta, nil
}

func TestNFSeImportCertificateAudits(t *testing.T) {
	t.Parallel()
	h := newNFSeHarness(t)
	imp := &fakeImporter{meta: custody.A1Meta{Serial: "abc"}}
	h.nd.Importer = imp
	svc := app.NewNFSeService(h.deps, h.nd)
	res, err := svc.ImportCertificate(context.Background(), h.tenant, []byte("pfx"), "pw", nfseCNPJ)
	if err != nil || res.Meta.Serial != "abc" {
		t.Fatalf("import = %+v, %v", res, err)
	}
	found := false
	for _, e := range h.store.AuditEntries() {
		if e.Action() == audit.ActionSetNFSeCertificate && e.TenantID() == h.tenant {
			found = true
		}
	}
	if !found {
		t.Error("certificate import not audited")
	}
	if meta, err := svc.Certificate(context.Background(), h.tenant, nfseCNPJ); err != nil || meta.Serial != "abc" {
		t.Errorf("certificate = %+v, %v", meta, err)
	}
	if _, err := svc.ImportCertificate(context.Background(), "missing", nil, "", nfseCNPJ); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("unknown tenant: %v", err)
	}
	imp.err = a1import.ErrWrongPassword
	if _, err := svc.ImportCertificate(context.Background(), h.tenant, nil, "", nfseCNPJ); !errors.Is(err, a1import.ErrWrongPassword) {
		t.Errorf("import error: %v", err)
	}
}

func TestNFSeCertificateUnavailableWithoutImporter(t *testing.T) {
	t.Parallel()
	h := newNFSeHarness(t)
	if _, err := h.svc.ImportCertificate(context.Background(), h.tenant, nil, "", nfseCNPJ); !errors.Is(err, app.ErrNFSeCertImportUnavailable) {
		t.Errorf("import: %v", err)
	}
	if _, err := h.svc.Certificate(context.Background(), h.tenant, nfseCNPJ); !errors.Is(err, app.ErrNFSeCertImportUnavailable) {
		t.Errorf("certificate: %v", err)
	}
}

func TestNFSeEmitDefaultsCompetenciaToEmissionDate(t *testing.T) {
	t.Parallel()
	h := newNFSeHarness(t)
	in := h.input("k-today")
	in.Competencia = nfse.Competencia{}
	em, err := h.svc.Emit(context.Background(), in)
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if want := nfse.CompetenciaOn(nfseNow); em.Competencia != want {
		t.Fatalf("competencia = %+v, want %+v", em.Competencia, want)
	}
}
