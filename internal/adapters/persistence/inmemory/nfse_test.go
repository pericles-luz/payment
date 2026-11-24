package inmemory_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/persistence/inmemory"
	"github.com/ia-dev-sindireceita/payment/internal/domain/billing"
	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/nfse"
	"github.com/ia-dev-sindireceita/payment/internal/nfse/custody"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

var nfseT0 = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

func nfsePending(id, tenant, key string, at time.Time) nfse.Emission {
	return nfse.Emission{
		ID: id, TenantID: tenant, IdempotencyKey: key, EmitterCNPJ: "67188163000110",
		Competencia: nfse.Competencia{Year: 2026, Month: 11, Day: 5}, ServiceValueCents: 269000,
		Status: nfse.StatusPending, CreatedAt: at,
	}
}

func TestNFSeReserveSemantics(t *testing.T) {
	s := inmemory.NewStore()
	ctx := context.Background()
	stale := nfseT0.Add(-2 * time.Minute)

	if _, ok, err := s.ReserveNFSeEmission(ctx, nfsePending("e1", "tA", "", nfseT0), stale); ok || !errors.Is(err, nfse.ErrEmptyIdempotencyKey) {
		t.Fatalf("empty key: ok=%v err=%v", ok, err)
	}
	if _, ok, err := s.ReserveNFSeEmission(ctx, nfsePending("e1", "tA", "k", nfseT0), stale); !ok || err != nil {
		t.Fatalf("first reserve: ok=%v err=%v", ok, err)
	}
	// Same key, live pending → in flight.
	if _, _, err := s.ReserveNFSeEmission(ctx, nfsePending("e2", "tA", "k", nfseT0), stale); !errors.Is(err, nfse.ErrEmissionInFlight) {
		t.Fatalf("in flight: %v", err)
	}
	// Same key in another tenant is independent.
	if _, ok, err := s.ReserveNFSeEmission(ctx, nfsePending("e3", "tB", "k", nfseT0), stale); !ok || err != nil {
		t.Fatalf("other tenant: ok=%v err=%v", ok, err)
	}
	// Pin a number on the pending row, then take it over once stale.
	pinned := nfsePending("e1", "tA", "k", nfseT0)
	pinned.Series, pinned.Number = "1", "42"
	if err := s.SaveNFSeEmission(ctx, pinned); err != nil {
		t.Fatalf("pin: %v", err)
	}
	prior, ok, err := s.ReserveNFSeEmission(ctx, nfsePending("e4", "tA", "k", nfseT0.Add(3*time.Minute)), nfseT0.Add(time.Minute))
	if !ok || err != nil || prior.ID != "e1" || prior.Number != "42" {
		t.Fatalf("takeover: prior=%+v ok=%v err=%v", prior, ok, err)
	}
	if _, err := s.FindNFSeEmission(ctx, "tA", "e1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("stale row survived: %v", err)
	}
	// Finish e4 and replay.
	done := nfsePending("e4", "tA", "k", nfseT0)
	done.Status, done.ChaveAcesso, done.XML = nfse.StatusAuthorized, "chave", []byte("<NFSe/>")
	done.TomadorDocument, done.TomadorName = "57151944000187", "Syndeotech"
	if err := s.SaveNFSeEmission(ctx, done); err != nil {
		t.Fatalf("save: %v", err)
	}
	prior, ok, err = s.ReserveNFSeEmission(ctx, nfsePending("e5", "tA", "k", nfseT0), stale)
	if ok || err != nil || prior.ID != "e4" || prior.Status != nfse.StatusAuthorized || string(prior.XML) != "<NFSe/>" || prior.TomadorName != "Syndeotech" {
		t.Fatalf("replay: prior=%+v ok=%v err=%v", prior, ok, err)
	}
	byKey, err := s.FindNFSeEmissionByIdempotencyKey(ctx, "tA", "k")
	// created_at is the reservation's (an upsert never rewrites it).
	if byKey.Competencia.Day != 5 {
		t.Fatalf("competencia day lost: %+v", byKey.Competencia)
	}
	if err != nil || byKey.ID != "e4" || !byKey.CreatedAt.Equal(nfseT0.Add(3*time.Minute)) {
		t.Fatalf("by key: %+v %v", byKey, err)
	}
	if _, err := s.FindNFSeEmissionByIdempotencyKey(ctx, "tA", ""); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("empty key lookup: %v", err)
	}
	// Release never drops a finished row.
	if err := s.ReleaseNFSeEmission(ctx, "tA", "k", "e4"); err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, err := s.FindNFSeEmission(ctx, "tA", "e4"); err != nil {
		t.Fatalf("finished row released: %v", err)
	}
	// Release drops a pending one.
	if err := s.ReleaseNFSeEmission(ctx, "tB", "k", "e3"); err != nil {
		t.Fatalf("release pending: %v", err)
	}
	if _, err := s.FindNFSeEmission(ctx, "tB", "e3"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("pending row not released: %v", err)
	}
}

func TestNFSeSaveConflictAndScope(t *testing.T) {
	s := inmemory.NewStore()
	ctx := context.Background()
	if err := s.SaveNFSeEmission(ctx, nfsePending("e1", "tA", "k", nfseT0)); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := s.SaveNFSeEmission(ctx, nfsePending("e2", "tA", "k", nfseT0)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("conflict: %v", err)
	}
	if _, err := s.FindNFSeEmission(ctx, "tB", "e1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant read: %v", err)
	}
}

func TestNFSeNextDPSNumberIsAtomic(t *testing.T) {
	s := inmemory.NewStore()
	ctx := context.Background()
	const n = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[int64]bool{}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := s.NextDPSNumber(ctx, "67188163000110", "1")
			if err != nil {
				t.Errorf("next: %v", err)
				return
			}
			mu.Lock()
			seen[v] = true
			mu.Unlock()
		}()
	}
	wg.Wait()
	for i := int64(1); i <= n; i++ {
		if !seen[i] {
			t.Fatalf("missing number %d in %v", i, seen)
		}
	}
	if v, _ := s.NextDPSNumber(ctx, "67188163000110", "2"); v != 1 {
		t.Errorf("other series starts at %d", v)
	}
}

func TestNFSeDANFSeCache(t *testing.T) {
	s := inmemory.NewStore()
	ctx := context.Background()
	if err := s.SaveNFSeDANFSe(ctx, "tA", "e1", []byte("%PDF")); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("pdf for missing emission: %v", err)
	}
	if err := s.SaveNFSeEmission(ctx, nfsePending("e1", "tA", "k", nfseT0)); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := s.FindNFSeDANFSe(ctx, "tA", "e1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("empty cache: %v", err)
	}
	if err := s.SaveNFSeDANFSe(ctx, "tA", "e1", []byte("%PDF-1")); err != nil {
		t.Fatalf("cache: %v", err)
	}
	if pdf, err := s.FindNFSeDANFSe(ctx, "tA", "e1"); err != nil || string(pdf) != "%PDF-1" {
		t.Fatalf("cached = %q %v", pdf, err)
	}
	if _, err := s.FindNFSeDANFSe(ctx, "tB", "e1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant pdf: %v", err)
	}
	// A later save of the emission keeps the cached PDF.
	if err := s.SaveNFSeEmission(ctx, nfsePending("e1", "tA", "k", nfseT0)); err != nil {
		t.Fatalf("resave: %v", err)
	}
	if pdf, _ := s.FindNFSeDANFSe(ctx, "tA", "e1"); string(pdf) != "%PDF-1" {
		t.Fatalf("cache lost on save: %q", pdf)
	}
}

func TestNFSeEmissionRollsBackWithLedger(t *testing.T) {
	s := inmemory.NewStore()
	ctx := context.Background()
	tn, _ := tenant.New("tA", "A", nfseT0)
	if err := s.SaveTenant(ctx, tn); err != nil {
		t.Fatalf("tenant: %v", err)
	}
	boom := errors.New("boom")
	err := s.WithinTx(ctx, func(r ports.Repository) error {
		if err := r.SaveNFSeEmission(ctx, nfsePending("e1", "tA", "k", nfseT0)); err != nil {
			return err
		}
		e, err := billing.NewLedgerEntry("l1", "tA", "nfse.emit", "e1", 0, nfseT0)
		if err != nil {
			return err
		}
		if err := r.AppendLedgerEntry(ctx, e); err != nil {
			return err
		}
		if _, err := r.FindNFSeEmission(ctx, "tA", "e1"); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("tx: %v", err)
	}
	if _, err := s.FindNFSeEmission(ctx, "tA", "e1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("emission survived rollback: %v", err)
	}
}

func TestNFSeCertStoreRoundTrip(t *testing.T) {
	s := inmemory.NewStore()
	ctx := context.Background()
	certs := s.NFSeCerts()
	signer := custody.NewLocalTestSigner(custody.WithClock(func() time.Time { return nfseT0 }))
	chain, meta, err := signer.Provision("tA_67188163000110", "67188163000110", 24*time.Hour)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if _, _, err := certs.Get(ctx, "tA_67188163000110"); !errors.Is(err, custody.ErrCertNotFound) {
		t.Fatalf("missing cert: %v", err)
	}
	if err := certs.PutA1(ctx, "", chain, meta); !errors.Is(err, custody.ErrEmptyCompanyID) {
		t.Fatalf("empty company: %v", err)
	}
	if err := certs.PutA1(ctx, "tA_67188163000110", chain, meta); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := certs.PutA1(ctx, "tA_67188163000110", chain, meta); err != nil {
		t.Fatalf("re-put: %v", err)
	}
	gotChain, gotMeta, err := certs.Get(ctx, "tA_67188163000110")
	if err != nil || len(gotChain) != len(chain) || gotMeta.Serial != meta.Serial ||
		gotMeta.CNPJHash != meta.CNPJHash || !gotMeta.NotAfter.Equal(meta.NotAfter.UTC()) {
		t.Fatalf("get = %v %+v %v (want %+v)", len(gotChain), gotMeta, err, meta)
	}
	list, err := certs.ListMeta(ctx)
	if err != nil || len(list) != 1 || list[0].CompanyID != "tA_67188163000110" {
		t.Fatalf("list = %+v %v", list, err)
	}
	if err := certs.Delete(ctx, "tA_67188163000110"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, _, err := certs.Get(ctx, "tA_67188163000110"); !errors.Is(err, custody.ErrCertNotFound) {
		t.Fatalf("deleted cert: %v", err)
	}
	if _, _, err := certs.Get(ctx, ""); !errors.Is(err, custody.ErrEmptyCompanyID) {
		t.Fatalf("get empty: %v", err)
	}
	if err := certs.Delete(ctx, ""); !errors.Is(err, custody.ErrEmptyCompanyID) {
		t.Fatalf("delete empty: %v", err)
	}
}
