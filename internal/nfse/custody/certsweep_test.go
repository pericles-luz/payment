package custody

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// recorder captures ExpiryObserver callbacks for assertions. It is safe for the
// concurrent Run test (the sweep goroutine and the test goroutine both touch it).
type recorder struct {
	mu   sync.Mutex
	obs  []expiryObservation
	seen int
}

func (r *recorder) observe(companyID, serial string, days int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.obs = append(r.obs, expiryObservation{companyID, serial, days})
	r.seen++
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.seen
}

func (r *recorder) snapshot() []expiryObservation {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]expiryObservation, len(r.obs))
	copy(out, r.obs)
	return out
}

// errLister is a CertLister that always fails, to drive the sweep error path.
type errLister struct {
	mu    sync.Mutex
	err   error
	calls int
}

func (e *errLister) ListMeta(context.Context) ([]CertMeta, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls++
	return nil, e.err
}

func (e *errLister) callCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls
}

// putMeta stores a tenant with a caller-chosen serial + notAfter so day counts
// are fully deterministic (the chain itself is irrelevant to the sweep, which
// reads metadata only). It uses a real leaf for the chain so PutA1's validation
// passes exactly as in production.
func putMeta(t *testing.T, s *MemoryCertStore, companyID, serial string, notAfter time.Time) {
	t.Helper()
	chain, _ := provisionLeaf(t, companyID, "11222333000181", time.Hour)
	meta := A1Meta{Serial: serial, NotAfter: notAfter}
	if err := s.PutA1(context.Background(), companyID, chain, meta); err != nil {
		t.Fatalf("put %s: %v", companyID, err)
	}
}

// TestExpirySweepPublishesForIdleTenant is the SIN-67762 regression: WITHOUT any
// sign / mTLS call, a single sweep tick still publishes the gauge for a
// provisioned-but-idle tenant. It fails before this change (no sweep existed, so
// an idle tenant's a1_cert_expiry_days was never refreshed) and passes after.
func TestExpirySweepPublishesForIdleTenant(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	store := NewMemoryCertStore()
	putMeta(t, store, "co-idle", "deadbeef", base.Add(20*24*time.Hour)) // 20 days out

	var rec recorder
	sweep, err := NewExpirySweep(ExpirySweepConfig{
		Store:    store,
		Observer: rec.observe,
		Now:      func() time.Time { return base },
	})
	if err != nil {
		t.Fatalf("new sweep: %v", err)
	}

	// No SignDigest / ClientCertificate has been called anywhere — the only path
	// that touches the gauge is this sweep.
	n, err := sweep.sweepOnce(ctx)
	if err != nil {
		t.Fatalf("sweepOnce: %v", err)
	}
	if n != 1 {
		t.Fatalf("swept %d tenants, want 1", n)
	}
	got := rec.snapshot()
	if len(got) != 1 {
		t.Fatalf("observer fired %d times, want 1", len(got))
	}
	if got[0].companyID != "co-idle" || got[0].serial != "deadbeef" || got[0].days != 20 {
		t.Errorf("observation = %+v, want {co-idle deadbeef 20}", got[0])
	}
}

// TestExpirySweepMixedTenants proves one tick refreshes EVERY tenant, including
// an already-expired one whose negative gauge is what fires NFSeA1CertExpired.
func TestExpirySweepMixedTenants(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	store := NewMemoryCertStore()
	putMeta(t, store, "co-healthy", "aa11", base.Add(45*24*time.Hour)) // 45 days
	putMeta(t, store, "co-warning", "bb22", base.Add(7*24*time.Hour))  // D-7
	putMeta(t, store, "co-expired", "cc33", base.Add(-3*24*time.Hour)) // 3 days past

	var rec recorder
	sweep, err := NewExpirySweep(ExpirySweepConfig{
		Store: store, Observer: rec.observe, Now: func() time.Time { return base },
	})
	if err != nil {
		t.Fatalf("new sweep: %v", err)
	}
	n, err := sweep.sweepOnce(ctx)
	if err != nil || n != 3 {
		t.Fatalf("sweepOnce n=%d err=%v, want 3,nil", n, err)
	}

	want := map[string]int{"co-healthy": 45, "co-warning": 7, "co-expired": -3}
	for _, o := range rec.snapshot() {
		w, ok := want[o.companyID]
		if !ok {
			t.Errorf("unexpected tenant observed: %q", o.companyID)
			continue
		}
		if o.days != w {
			t.Errorf("%s observed days = %d, want %d", o.companyID, o.days, w)
		}
		delete(want, o.companyID)
	}
	if len(want) != 0 {
		t.Errorf("tenants not observed by the sweep: %v", want)
	}
}

// TestExpirySweepRunImmediateAndStop proves Run performs an immediate sweep (so
// the gauge appears without waiting a full interval) and returns promptly once
// its context is cancelled — the clean shutdown seam the closer relies on.
func TestExpirySweepRunImmediateAndStop(t *testing.T) {
	base := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	store := NewMemoryCertStore()
	putMeta(t, store, "co-1", "aa11", base.Add(10*24*time.Hour))

	var rec recorder
	sweep, err := NewExpirySweep(ExpirySweepConfig{
		Store: store, Observer: rec.observe,
		Interval: 10 * time.Millisecond,
		Now:      func() time.Time { return base },
	})
	if err != nil {
		t.Fatalf("new sweep: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sweep.Run(ctx); close(done) }()

	// Wait for at least two sweeps: the immediate one (count 1) plus one ticker
	// firing (count 2), so both the immediate-sweep and the ticker branch of Run
	// are exercised.
	deadline := time.Now().Add(2 * time.Second)
	for rec.count() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("Run produced only %d sweeps, want >=2 (immediate + tick)", rec.count())
		}
		time.Sleep(time.Millisecond)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}

// TestExpirySweepListErrorContinues proves a ListMeta failure is surfaced via
// OnError and returned from sweepOnce (no observer call, no panic) — a transient
// store outage must not crash the sweep.
func TestExpirySweepListErrorContinues(t *testing.T) {
	sentinel := errors.New("store down")
	lister := &errLister{err: sentinel}

	var onErr error
	var observed int
	sweep, err := NewExpirySweep(ExpirySweepConfig{
		Store:    lister,
		Observer: func(string, string, int) { observed++ },
		OnError:  func(e error) { onErr = e },
	})
	if err != nil {
		t.Fatalf("new sweep: %v", err)
	}
	n, err := sweep.sweepOnce(context.Background())
	if n != 0 {
		t.Errorf("swept %d on error, want 0", n)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("sweepOnce err = %v, want sentinel", err)
	}
	if !errors.Is(onErr, sentinel) {
		t.Errorf("OnError got %v, want sentinel", onErr)
	}
	if observed != 0 {
		t.Errorf("observer fired %d times on error, want 0", observed)
	}
	if lister.callCount() != 1 {
		t.Errorf("ListMeta called %d times, want 1", lister.callCount())
	}
}

func TestNewExpirySweepValidation(t *testing.T) {
	if _, err := NewExpirySweep(ExpirySweepConfig{Observer: func(string, string, int) {}}); err == nil {
		t.Error("nil store should fail")
	}
	if _, err := NewExpirySweep(ExpirySweepConfig{Store: NewMemoryCertStore()}); err == nil {
		t.Error("nil observer should fail")
	}
	// A non-positive interval falls back to the default rather than erroring.
	s, err := NewExpirySweep(ExpirySweepConfig{
		Store: NewMemoryCertStore(), Observer: func(string, string, int) {}, Interval: -1,
	})
	if err != nil {
		t.Fatalf("valid config errored: %v", err)
	}
	if s.interval != defaultExpirySweepInterval {
		t.Errorf("interval = %v, want default %v", s.interval, defaultExpirySweepInterval)
	}
}

// TestMemoryCertStoreListMeta covers the in-memory CertLister directly: it
// enumerates all tenants' metadata and nothing for an empty store.
func TestMemoryCertStoreListMeta(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryCertStore()
	if metas, err := store.ListMeta(ctx); err != nil || len(metas) != 0 {
		t.Fatalf("empty ListMeta = %v, %v; want [],nil", metas, err)
	}
	now := time.Now()
	putMeta(t, store, "co-1", "aa11", now.Add(time.Hour))
	putMeta(t, store, "co-2", "bb22", now.Add(2*time.Hour))

	metas, err := store.ListMeta(ctx)
	if err != nil {
		t.Fatalf("ListMeta: %v", err)
	}
	if len(metas) != 2 {
		t.Fatalf("ListMeta returned %d, want 2", len(metas))
	}
	byID := map[string]string{}
	for _, m := range metas {
		byID[m.CompanyID] = m.Meta.Serial
	}
	if byID["co-1"] != "aa11" || byID["co-2"] != "bb22" {
		t.Errorf("ListMeta serials = %v, want co-1:aa11 co-2:bb22", byID)
	}
}
