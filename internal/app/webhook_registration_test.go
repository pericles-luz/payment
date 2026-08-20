package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/domain/tenant"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// --- test doubles -----------------------------------------------------------

// fakeCredStore is a ports.CredentialStore whose GetBankCredential returns a fixed
// credential/error. It records the (tenant, bank) it was asked for.
type fakeCredStore struct {
	cred    ports.BankCredential
	err     error
	calls   int
	lastKey [2]string
}

func (f *fakeCredStore) GetBankCredential(_ context.Context, tenantID, bankID string) (ports.BankCredential, error) {
	f.calls++
	f.lastKey = [2]string{tenantID, bankID}
	return f.cred, f.err
}

// fakeRegistrar is a ports.PixWebhookRegistrar recording every PUT/GET and returning
// scripted results. getResults is consumed in order so a single test can model
// "NotFound then registered". A missing script entry falls back to getDefault.
type fakeRegistrar struct {
	mu sync.Mutex

	registerErr    error
	registered     []string // callback URLs PUT, in order
	registerTenant []string

	getResults []ports.WebhookRegistration
	getErrs    []error
	getDefault ports.WebhookRegistration
	getDefErr  error
	getCalls   int
}

func (f *fakeRegistrar) RegisterWebhook(_ context.Context, tenantID, _ /*pixKey*/, webhookURL string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.registerErr != nil {
		return f.registerErr
	}
	f.registered = append(f.registered, webhookURL)
	f.registerTenant = append(f.registerTenant, tenantID)
	// A successful PUT means a subsequent GET should read the URL back — append it as
	// the next scripted GET result so confirm-by-GET sees what we just registered
	// (unless the test scripted its own GET sequence entirely).
	return nil
}

func (f *fakeRegistrar) GetWebhook(_ context.Context, _ /*tenantID*/, _ /*pixKey*/ string) (ports.WebhookRegistration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.getCalls
	f.getCalls++
	if i < len(f.getResults) || i < len(f.getErrs) {
		var reg ports.WebhookRegistration
		var err error
		if i < len(f.getResults) {
			reg = f.getResults[i]
		}
		if i < len(f.getErrs) {
			err = f.getErrs[i]
		}
		return reg, err
	}
	return f.getDefault, f.getDefErr
}

// fakeMinter is a webhookRefMinter returning a fixed ref (or error) and counting mints.
type fakeMinter struct {
	ref   string
	err   error
	mints int
}

func (f *fakeMinter) MintWebhookRef(_ context.Context, _ string) (string, error) {
	f.mints++
	return f.ref, f.err
}

const testBaseURL = "https://payment.example.test"

func newBufLogger() (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), buf
}

func completeCred() ports.BankCredential {
	return ports.BankCredential{TenantID: "t1", BankID: ports.BankIDC6, ClientID: "cid", CreditorKey: "recebedor@example.com"}
}

// --- tests ------------------------------------------------------------------

// TestTryRegisterHappyPath: cred+key complete, C6 has no webhook (NotFound), so the
// service mints ONE ref, PUTs the callback, and confirms by GET.
func TestTryRegisterHappyPath(t *testing.T) {
	t.Parallel()
	creds := &fakeCredStore{cred: completeCred()}
	minter := &fakeMinter{ref: strings.Repeat("A", 43)}
	reg := &fakeRegistrar{
		// GET #1: idempotency probe → NotFound (register). GET #2: confirm → the URL we PUT.
		getResults: []ports.WebhookRegistration{{}, {WebhookURL: testBaseURL + webhookCallbackPathPrefix + minter.ref}},
		getErrs:    []error{shared.ErrNotFound, nil},
	}
	logger, buf := newBufLogger()
	s := NewWebhookRegistrationService(creds, reg, minter, testBaseURL, logger)

	s.TryRegister(context.Background(), "t1")

	if minter.mints != 1 {
		t.Fatalf("mints = %d, want 1", minter.mints)
	}
	if len(reg.registered) != 1 {
		t.Fatalf("registered %d URLs, want 1", len(reg.registered))
	}
	want := testBaseURL + webhookCallbackPathPrefix + minter.ref
	if reg.registered[0] != want {
		t.Fatalf("registered URL = %q, want %q", reg.registered[0], want)
	}
	if creds.lastKey != [2]string{"t1", ports.BankIDC6} {
		t.Fatalf("resolved credential for %v, want {t1 c6}", creds.lastKey)
	}
	if !strings.Contains(buf.String(), "registered and confirmed") {
		t.Fatalf("expected success log, got: %s", buf.String())
	}
	assertNoSecretLeak(t, buf.String(), minter.ref)
}

// TestTryRegisterAlreadyRegistered: C6 already holds a callback under our origin, so
// the service skips WITHOUT minting or PUTting (idempotency gate).
func TestTryRegisterAlreadyRegistered(t *testing.T) {
	t.Parallel()
	creds := &fakeCredStore{cred: completeCred()}
	minter := &fakeMinter{ref: strings.Repeat("B", 43)}
	reg := &fakeRegistrar{getDefault: ports.WebhookRegistration{WebhookURL: testBaseURL + webhookCallbackPathPrefix + "existingref0000000000000000000000000000000"}}
	logger, buf := newBufLogger()
	s := NewWebhookRegistrationService(creds, reg, minter, testBaseURL, logger)

	s.TryRegister(context.Background(), "t1")

	if minter.mints != 0 {
		t.Fatalf("mints = %d, want 0 (already registered)", minter.mints)
	}
	if len(reg.registered) != 0 {
		t.Fatalf("registered %d URLs, want 0", len(reg.registered))
	}
	assertNoSecretLeak(t, buf.String(), "existingref0000000000000000000000000000000")
}

// TestTryRegisterIdempotentUnderRetry: a second call after a successful first sees the
// webhook already registered and does NOT mint again (steady state = one ref).
func TestTryRegisterIdempotentUnderRetry(t *testing.T) {
	t.Parallel()
	creds := &fakeCredStore{cred: completeCred()}
	minter := &fakeMinter{ref: strings.Repeat("C", 43)}
	url := testBaseURL + webhookCallbackPathPrefix + minter.ref
	reg := &fakeRegistrar{
		// First call: GET NotFound (probe) → PUT → GET url (confirm). Second call: GET url
		// (probe, already-registered) → stop.
		getResults: []ports.WebhookRegistration{{}, {WebhookURL: url}, {WebhookURL: url}},
		getErrs:    []error{shared.ErrNotFound, nil, nil},
	}
	s := NewWebhookRegistrationService(creds, reg, minter, testBaseURL, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))

	s.TryRegister(context.Background(), "t1")
	s.TryRegister(context.Background(), "t1")

	if minter.mints != 1 {
		t.Fatalf("mints = %d, want 1 across two calls", minter.mints)
	}
	if len(reg.registered) != 1 {
		t.Fatalf("registered %d URLs, want 1 across two calls", len(reg.registered))
	}
}

// TestTryRegisterForeignURLReplaces: C6 holds a callback under a DIFFERENT origin →
// the service mints and (re)registers ours.
func TestTryRegisterForeignURLReplaces(t *testing.T) {
	t.Parallel()
	creds := &fakeCredStore{cred: completeCred()}
	minter := &fakeMinter{ref: strings.Repeat("D", 43)}
	url := testBaseURL + webhookCallbackPathPrefix + minter.ref
	reg := &fakeRegistrar{
		getResults: []ports.WebhookRegistration{{WebhookURL: "https://evil.example/webhooks/c6/x"}, {WebhookURL: url}},
		getErrs:    []error{nil, nil},
	}
	s := NewWebhookRegistrationService(creds, reg, minter, testBaseURL, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))

	s.TryRegister(context.Background(), "t1")

	if minter.mints != 1 || len(reg.registered) != 1 {
		t.Fatalf("mints=%d registered=%d, want 1/1 (foreign URL replaced)", minter.mints, len(reg.registered))
	}
}

// TestTryRegisterSkips covers every branch that must NOT mint or PUT.
func TestTryRegisterSkips(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		cred      ports.BankCredential
		credErr   error
		getErr    error // error returned by the idempotency-probe GET
		wantLog   string
		wantNoLog bool
	}{
		{name: "credential not found (not complete)", credErr: shared.ErrNotFound, wantNoLog: true},
		{name: "credential lookup infra error", credErr: errors.New("db down"), wantLog: "credential lookup failed"},
		{name: "empty creditor key (not complete)", cred: ports.BankCredential{ClientID: "cid"}, wantNoLog: true},
		{name: "ambiguous readback error", cred: completeCred(), getErr: errors.New("502 bad gateway"), wantLog: "readback failed"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			creds := &fakeCredStore{cred: tc.cred, err: tc.credErr}
			minter := &fakeMinter{ref: strings.Repeat("E", 43)}
			reg := &fakeRegistrar{getDefErr: tc.getErr}
			logger, buf := newBufLogger()
			s := NewWebhookRegistrationService(creds, reg, minter, testBaseURL, logger)

			s.TryRegister(context.Background(), "t1")

			if minter.mints != 0 {
				t.Fatalf("mints = %d, want 0", minter.mints)
			}
			if len(reg.registered) != 0 {
				t.Fatalf("registered %d, want 0", len(reg.registered))
			}
			if tc.wantNoLog && buf.Len() != 0 {
				t.Fatalf("expected no log, got: %s", buf.String())
			}
			if tc.wantLog != "" && !strings.Contains(buf.String(), tc.wantLog) {
				t.Fatalf("expected log %q, got: %s", tc.wantLog, buf.String())
			}
			// Never leak the (masked) key's full value.
			if strings.Contains(buf.String(), "recebedor@example.com") {
				t.Fatalf("log leaked the full PIX key: %s", buf.String())
			}
		})
	}
}

// TestTryRegisterBestEffortFailures proves a PSP-side failure NEVER panics/propagates
// and never logs the secret ref/URL. Each sub-case exercises a distinct failure stage.
func TestTryRegisterBestEffortFailures(t *testing.T) {
	t.Parallel()
	ref := strings.Repeat("F", 43)
	url := testBaseURL + webhookCallbackPathPrefix + ref
	cases := []struct {
		name    string
		minter  *fakeMinter
		reg     *fakeRegistrar
		wantLog string
	}{
		{
			name:    "mint fails",
			minter:  &fakeMinter{err: errors.New("csprng down")},
			reg:     &fakeRegistrar{getErrs: []error{shared.ErrNotFound}},
			wantLog: "mint ref failed",
		},
		{
			name:    "register fails",
			minter:  &fakeMinter{ref: ref},
			reg:     &fakeRegistrar{getErrs: []error{shared.ErrNotFound}, registerErr: errors.New("503")},
			wantLog: "register failed",
		},
		{
			name:    "confirm GET fails",
			minter:  &fakeMinter{ref: ref},
			reg:     &fakeRegistrar{getResults: []ports.WebhookRegistration{{}, {}}, getErrs: []error{shared.ErrNotFound, errors.New("timeout")}},
			wantLog: "confirm failed",
		},
		{
			name:    "confirm mismatch",
			minter:  &fakeMinter{ref: ref},
			reg:     &fakeRegistrar{getResults: []ports.WebhookRegistration{{}, {WebhookURL: testBaseURL + webhookCallbackPathPrefix + "otherref00000000000000000000000000000000000"}}, getErrs: []error{shared.ErrNotFound, nil}},
			wantLog: "confirmation mismatch",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			creds := &fakeCredStore{cred: completeCred()}
			logger, buf := newBufLogger()
			s := NewWebhookRegistrationService(creds, tc.reg, tc.minter, testBaseURL, logger)

			// Must not panic and returns nothing (best-effort).
			s.TryRegister(context.Background(), "t1")

			if !strings.Contains(buf.String(), tc.wantLog) {
				t.Fatalf("expected log %q, got: %s", tc.wantLog, buf.String())
			}
			assertNoSecretLeak(t, buf.String(), ref)
			// The full callback URL must never appear either.
			if strings.Contains(buf.String(), url) {
				t.Fatalf("log leaked the callback URL: %s", buf.String())
			}
		})
	}
}

// TestTryRegisterNotWired: any nil dependency (or blank base URL) makes TryRegister an
// inert no-op — no lookup, no mint, no PUT — so a stub/unwired deployment is safe.
func TestTryRegisterNotWired(t *testing.T) {
	t.Parallel()
	full := func() (*fakeCredStore, *fakeRegistrar, *fakeMinter) {
		return &fakeCredStore{cred: completeCred()}, &fakeRegistrar{getErrs: []error{shared.ErrNotFound}}, &fakeMinter{ref: strings.Repeat("G", 43)}
	}
	t.Run("nil registrar", func(t *testing.T) {
		creds, _, minter := full()
		s := NewWebhookRegistrationService(creds, nil, minter, testBaseURL, slog.Default())
		s.TryRegister(context.Background(), "t1")
		if creds.calls != 0 || minter.mints != 0 {
			t.Fatalf("expected inert no-op, got creds=%d mints=%d", creds.calls, minter.mints)
		}
	})
	t.Run("nil minter", func(t *testing.T) {
		creds, reg, _ := full()
		s := NewWebhookRegistrationService(creds, reg, nil, testBaseURL, slog.Default())
		s.TryRegister(context.Background(), "t1")
		if creds.calls != 0 {
			t.Fatalf("expected inert no-op, got creds=%d", creds.calls)
		}
	})
	t.Run("nil creds", func(t *testing.T) {
		_, reg, minter := full()
		s := NewWebhookRegistrationService(nil, reg, minter, testBaseURL, slog.Default())
		s.TryRegister(context.Background(), "t1")
		if minter.mints != 0 || reg.getCalls != 0 {
			t.Fatalf("expected inert no-op, got mints=%d getCalls=%d", minter.mints, reg.getCalls)
		}
	})
	t.Run("blank base url", func(t *testing.T) {
		creds, reg, minter := full()
		s := NewWebhookRegistrationService(creds, reg, minter, "   ", slog.Default())
		s.TryRegister(context.Background(), "t1")
		if creds.calls != 0 {
			t.Fatalf("expected inert no-op with blank base url, got creds=%d", creds.calls)
		}
	})
	t.Run("empty tenant id", func(t *testing.T) {
		creds, reg, minter := full()
		s := NewWebhookRegistrationService(creds, reg, minter, testBaseURL, slog.Default())
		s.TryRegister(context.Background(), "   ")
		if creds.calls != 0 {
			t.Fatalf("expected no-op for blank tenant, got creds=%d", creds.calls)
		}
	})
}

// TestNewWebhookRegistrationServiceNilLogger: a nil logger falls back to the default
// (no panic on use).
func TestNewWebhookRegistrationServiceNilLogger(t *testing.T) {
	t.Parallel()
	s := NewWebhookRegistrationService(&fakeCredStore{cred: completeCred()},
		&fakeRegistrar{getErrs: []error{shared.ErrNotFound}}, &fakeMinter{ref: strings.Repeat("H", 43)}, testBaseURL, nil)
	if s.logger == nil {
		t.Fatal("nil logger must fall back to a non-nil default")
	}
	// Must not panic.
	s.TryRegister(context.Background(), "t1")
}

// TestMaskPixKey covers the log-masking helper (first+last kept, short fully masked).
func TestMaskPixKey(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"":                "****",
		"ab":              "****",
		"abcd":            "****",
		"recebedor@x.com": "r***m",
		"12345678901":     "1***1",
	}
	for in, want := range cases {
		if got := maskPixKey(in); got != want {
			t.Fatalf("maskPixKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// assertNoSecretLeak fails if the captured log output contains the plaintext ref or a
// full /webhooks/c6/{ref} path — the capability secret must never be logged.
func assertNoSecretLeak(t *testing.T, logOutput, ref string) {
	t.Helper()
	if ref != "" && strings.Contains(logOutput, ref) {
		t.Fatalf("log leaked the plaintext ref %q: %s", ref, logOutput)
	}
	if strings.Contains(logOutput, webhookCallbackPathPrefix+ref) && ref != "" {
		t.Fatalf("log leaked the full callback path: %s", logOutput)
	}
}

// fakeTenantReader resolves a tenant with a scripted active flag, or an error.
type fakeTenantReader struct {
	active bool
	err    error
	calls  int
}

func (f *fakeTenantReader) FindTenantByID(_ context.Context, id string) (*tenant.Tenant, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	tn, err := tenant.New(id, "empresa "+id, time.Unix(0, 0).UTC())
	if err != nil {
		return nil, err
	}
	if !f.active {
		tn.Deactivate()
	}
	return tn, nil
}

// TestTryRegisterSkipsInactiveTenant: um tenant SUSPENSO não registra webhook.
//
// Suspender não remove a credencial, e a varredura enumera justamente por presença de
// credencial — então o suspenso continuava agindo. Quando ele e uma empresa ATIVA
// compartilham a chave PIX (foi o caso da empresa 27 em produção), o estrago é
// concreto: no C6 há uma URL só por chave, os dois se sobrescrevem a cada 60 segundos,
// e o aviso de pagamento da empresa ativa passa a chegar por um ref que não é dela e
// ser recusado. Cada rodada ainda gasta chamadas cobradas do PSP.
//
// O portão tem de barrar ANTES de qualquer chamada ao banco: nada de cunhar ref, nada
// de GET de sondagem, nada de PUT.
func TestTryRegisterSkipsInactiveTenant(t *testing.T) {
	t.Parallel()
	creds := &fakeCredStore{cred: completeCred()}
	minter := &fakeMinter{ref: strings.Repeat("A", 43)}
	reg := &fakeRegistrar{
		getResults: []ports.WebhookRegistration{{}, {WebhookURL: testBaseURL + webhookCallbackPathPrefix + strings.Repeat("A", 43)}},
		getErrs:    []error{shared.ErrNotFound, nil},
	}
	logger, buf := newBufLogger()
	tenants := &fakeTenantReader{active: false}

	s := NewWebhookRegistrationService(creds, reg, minter, testBaseURL, logger).WithTenants(tenants)
	s.TryRegister(context.Background(), "t-suspenso")

	if tenants.calls != 1 {
		t.Fatalf("o portão não consultou o tenant (calls=%d)", tenants.calls)
	}
	if minter.mints != 0 {
		t.Fatalf("tenant suspenso cunhou %d refs: cada cunhagem aposenta o ref anterior\ne mata os canais que ainda o usavam", minter.mints)
	}
	if len(reg.registered) != 0 || reg.getCalls != 0 {
		t.Fatalf("tenant suspenso falou com o C6: %d PUT, %d GET — é assim que ele\ndisputa a chave PIX de uma empresa ativa", len(reg.registered), reg.getCalls)
	}
	if creds.calls != 0 {
		t.Fatalf("credencial lida para um tenant suspenso (calls=%d)", creds.calls)
	}
	if strings.Contains(buf.String(), "registered and confirmed") {
		t.Fatalf("log diz que registrou um tenant suspenso: %s", buf.String())
	}
}

// TestTryRegisterActiveTenantStillRegisters: a contrapartida — o portão não pode
// estorvar quem está ativo.
func TestTryRegisterActiveTenantStillRegisters(t *testing.T) {
	t.Parallel()
	creds := &fakeCredStore{cred: completeCred()}
	minter := &fakeMinter{ref: strings.Repeat("B", 43)}
	reg := &fakeRegistrar{
		getResults: []ports.WebhookRegistration{{}, {WebhookURL: testBaseURL + webhookCallbackPathPrefix + strings.Repeat("B", 43)}},
		getErrs:    []error{shared.ErrNotFound, nil},
	}
	logger, buf := newBufLogger()

	s := NewWebhookRegistrationService(creds, reg, minter, testBaseURL, logger).
		WithTenants(&fakeTenantReader{active: true})
	s.TryRegister(context.Background(), "t-ativo")

	if len(reg.registered) != 1 {
		t.Fatalf("tenant ativo registrou %d URLs, want 1", len(reg.registered))
	}
	if !strings.Contains(buf.String(), "registered and confirmed") {
		t.Fatalf("esperava log de sucesso, veio: %s", buf.String())
	}
}

// TestTryRegisterSkipsWhenTenantUnresolvable: falha fechado. Um erro de infraestrutura
// ao ler o tenant não autoriza registrar em nome dele — a varredura tenta de novo em 60
// segundos, então adiar não custa nada e agir por engano custa a chave de outra empresa.
func TestTryRegisterSkipsWhenTenantUnresolvable(t *testing.T) {
	t.Parallel()
	creds := &fakeCredStore{cred: completeCred()}
	minter := &fakeMinter{ref: strings.Repeat("C", 43)}
	reg := &fakeRegistrar{}
	logger, buf := newBufLogger()

	s := NewWebhookRegistrationService(creds, reg, minter, testBaseURL, logger).
		WithTenants(&fakeTenantReader{err: errors.New("database is locked")})
	s.TryRegister(context.Background(), "t-indeterminado")

	if minter.mints != 0 || len(reg.registered) != 0 {
		t.Fatalf("registrou com o tenant indeterminado: %d mints, %d PUT", minter.mints, len(reg.registered))
	}
	if !strings.Contains(buf.String(), "tenant lookup failed") {
		t.Fatalf("a falha de leitura tem de aparecer no log, veio: %s", buf.String())
	}
}
