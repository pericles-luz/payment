package custody

import (
	"context"
	"errors"
	"time"
)

// ExpiryObserver receives a tenant certificate's remaining validity in whole
// days (negative once past notAfter). It is the seam behind the
// a1_cert_expiry_days gauge (SIN-67760): both the sign / mTLS path
// (VaultTransitSigner.observeExpiry) and the proactive sweep (ExpirySweep)
// publish through the SAME callback, so an idle tenant and an active one share
// one metric definition and converge to the same value.
type ExpiryObserver func(companyID, serial string, expiryDays int)

// CertMeta pairs a tenant id with its stored, non-secret A1 metadata. It is the
// unit CertLister.ListMeta enumerates for the expiry sweep — public material
// only (serial + notAfter), never the chain and never key material.
type CertMeta struct {
	CompanyID string
	Meta      A1Meta
}

// CertLister is the OPTIONAL CertStore capability the proactive expiry sweep
// needs: enumerate every custodied tenant's metadata so a1_cert_expiry_days can
// be refreshed for IDLE tenants too — ones that never hit the sign / mTLS path,
// so observeExpiry never runs for them. It is kept OFF the mandatory CertStore
// port (mirroring pdfstore.PresignedGetter) so a store that cannot cheaply
// enumerate simply opts the sweep out via a failed type assertion; the
// production adapters (pgcertstore.Store, MemoryCertStore) implement it.
type CertLister interface {
	// ListMeta returns the non-secret metadata for every custodied tenant. It
	// reads only public metadata (no chain, no key material) to keep the sweep
	// cheap and its cardinality bounded by the tenant count.
	ListMeta(ctx context.Context) ([]CertMeta, error)
}

// defaultExpirySweepInterval is the tick period used when ExpirySweepConfig
// leaves Interval unset. One hour keeps the store load negligible (a single
// ListMeta query per hour) while ensuring even a permanently-idle tenant's gauge
// is refreshed long before it can silently cross a D-30/15/7/1 threshold.
const defaultExpirySweepInterval = time.Hour

// ExpirySweep periodically republishes a1_cert_expiry_days for EVERY custodied
// tenant, independent of NFS-e traffic. Without it the gauge for an IDLE tenant
// — one that never hits the sign / mTLS path, so observeExpiry never fires — is
// never refreshed, and its certificate can pass notAfter with no D-30/15/7/1
// alert ever firing. That is the exact silent-expiry threat AC #7 guards
// against; the sign-path observer alone only covers ACTIVE tenants (SIN-67762,
// follow-up to SIN-67760).
//
// Each tick is one ListMeta read plus one observer call per tenant, so load is a
// single store query per interval and cardinality stays bounded by the tenant
// count. It is safe to run alongside the sign-path observer: both converge the
// gauge to the same value for a given (company_id, serial).
type ExpirySweep struct {
	store    CertLister
	observe  ExpiryObserver
	interval time.Duration
	now      func() time.Time
	onError  func(error)
}

// ExpirySweepConfig configures NewExpirySweep.
type ExpirySweepConfig struct {
	// Store enumerates custodied tenants. Required.
	Store CertLister
	// Observer publishes each tenant's remaining validity. Required — it is the
	// same callback the signer uses, so the sweep and the sign path back one
	// metric.
	Observer ExpiryObserver
	// Interval between sweeps. Zero or negative uses defaultExpirySweepInterval.
	Interval time.Duration
	// Now overrides the clock (test hook). Defaults to time.Now.
	Now func() time.Time
	// OnError, when set, receives a sweep-level (ListMeta) error. It must not
	// block; the sweep loop keeps running so a transient store outage does not
	// permanently silence the gauge.
	OnError func(error)
}

// NewExpirySweep builds the sweep, failing fast when the store or observer is
// missing — both are required for the gauge to be refreshed at all.
func NewExpirySweep(cfg ExpirySweepConfig) (*ExpirySweep, error) {
	if cfg.Store == nil {
		return nil, errors.New("custody: expiry sweep requires a CertLister store")
	}
	if cfg.Observer == nil {
		return nil, errors.New("custody: expiry sweep requires an observer")
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = defaultExpirySweepInterval
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &ExpirySweep{
		store:    cfg.Store,
		observe:  cfg.Observer,
		interval: interval,
		now:      now,
		onError:  cfg.OnError,
	}, nil
}

// sweepOnce reads every custodied tenant and republishes its gauge. It returns
// the number of tenants observed; a ListMeta error is surfaced via OnError and
// returned so Run/tests can react without the loop stopping. All tenants in one
// sweep read the same clock instant so their gauges stay mutually consistent.
func (s *ExpirySweep) sweepOnce(ctx context.Context) (int, error) {
	metas, err := s.store.ListMeta(ctx)
	if err != nil {
		if s.onError != nil {
			s.onError(err)
		}
		return 0, err
	}
	now := s.now()
	for _, m := range metas {
		s.observe(m.CompanyID, m.Meta.Serial, m.Meta.ExpiresInDays(now))
	}
	return len(metas), nil
}

// Run performs an immediate sweep, then repeats every interval until ctx is
// cancelled. It BLOCKS; callers launch it in a goroutine and cancel ctx to stop
// it (a clean shutdown seam). An error from any single sweep does not stop the
// loop — a transient store outage must not permanently silence the gauge.
func (s *ExpirySweep) Run(ctx context.Context) {
	_, _ = s.sweepOnce(ctx)
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = s.sweepOnce(ctx)
		}
	}
}
