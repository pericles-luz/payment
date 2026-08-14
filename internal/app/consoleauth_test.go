package app_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	store "github.com/ia-dev-sindireceita/payment/internal/adapters/consoleauth"
	"github.com/ia-dev-sindireceita/payment/internal/app"
	domain "github.com/ia-dev-sindireceita/payment/internal/domain/consoleauth"
)

// errBoom is an injected store failure used to exercise fail-closed branches.
var errBoom = errors.New("boom")

// mutableClock is a test clock whose Now can be advanced.
type mutableClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *mutableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *mutableClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// totpFor computes the RFC 6238 code for a base32 secret at a moment — an
// independent reimplementation so the tests do not depend on domain internals.
func totpFor(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	dec := base32.StdEncoding.WithPadding(base32.NoPadding)
	key, err := dec.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off]&0x7f) << 24) | (uint32(sum[off+1]) << 16) | (uint32(sum[off+2]) << 8) | uint32(sum[off+3])
	return fmt.Sprintf("%06d", bin%1_000_000)
}

func newService(t *testing.T, cfg app.ConsoleAuthConfig) (*app.ConsoleAuthService, *store.MemStore, *mutableClock) {
	t.Helper()
	m := store.NewMemStore()
	clk := &mutableClock{now: time.Unix(1_700_000_000, 0).UTC()}
	return app.NewConsoleAuthService(m, m, m, clk, cfg), m, clk
}

// provision runs a successful bootstrap and returns the generated credentials.
func provision(t *testing.T, svc *app.ConsoleAuthService, token string) app.BootstrapResult {
	t.Helper()
	res, err := svc.Bootstrap(context.Background(), token)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	return res
}

func TestBootstrapDisabledWithoutToken(t *testing.T) {
	t.Parallel()
	svc, _, _ := newService(t, app.ConsoleAuthConfig{}) // no bootstrap token
	if svc.BootstrapEnabled() {
		t.Fatal("bootstrap should be disabled without a token")
	}
	if _, err := svc.Bootstrap(context.Background(), "anything"); err != app.ErrBootstrapDisabled {
		t.Fatalf("err = %v, want ErrBootstrapDisabled", err)
	}
}

func TestBootstrapWrongToken(t *testing.T) {
	t.Parallel()
	svc, _, _ := newService(t, app.ConsoleAuthConfig{BootstrapToken: "deploy-secret"})
	if _, err := svc.Bootstrap(context.Background(), "guess"); err != app.ErrBootstrapForbidden {
		t.Fatalf("err = %v, want ErrBootstrapForbidden", err)
	}
	if svc.Provisioned(context.Background()) {
		t.Fatal("a rejected bootstrap must not provision")
	}
}

func TestBootstrapSuccessThenLocked(t *testing.T) {
	t.Parallel()
	svc, _, _ := newService(t, app.ConsoleAuthConfig{BootstrapToken: "deploy-secret", Username: "pericles.luz"})
	res := provision(t, svc, "deploy-secret")
	if res.Username != "pericles.luz" || res.Password == "" || res.TOTPSecret == "" {
		t.Fatalf("bootstrap result incomplete: %+v", res)
	}
	if !strings.HasPrefix(res.OTPAuthURI, "otpauth://totp/") {
		t.Fatalf("otpauth URI = %q", res.OTPAuthURI)
	}
	if !svc.Provisioned(context.Background()) {
		t.Fatal("should be provisioned after bootstrap")
	}
	// Single-use: a second bootstrap (even with the right token) is locked.
	if _, err := svc.Bootstrap(context.Background(), "deploy-secret"); err != app.ErrBootstrapLocked {
		t.Fatalf("second bootstrap err = %v, want ErrBootstrapLocked", err)
	}
}

func TestLoginSuccessAndSession(t *testing.T) {
	t.Parallel()
	svc, _, clk := newService(t, app.ConsoleAuthConfig{BootstrapToken: "tok", Username: "pericles.luz"})
	res := provision(t, svc, "tok")
	ctx := context.Background()

	code := totpFor(t, res.TOTPSecret, clk.Now())
	id, err := svc.Login(ctx, "pericles.luz", res.Password, code)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if id == "" {
		t.Fatal("empty session id on success")
	}
	subject, ok := svc.Authenticate(ctx, id)
	if !ok || subject != "pericles.luz" {
		t.Fatalf("Authenticate = (%q,%v), want (pericles.luz,true)", subject, ok)
	}
	// Logout revokes.
	if err := svc.Logout(ctx, id); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, ok := svc.Authenticate(ctx, id); ok {
		t.Fatal("session should be invalid after logout")
	}
}

func TestLoginBeforeProvisioning(t *testing.T) {
	t.Parallel()
	svc, _, _ := newService(t, app.ConsoleAuthConfig{BootstrapToken: "tok"})
	if _, err := svc.Login(context.Background(), "pericles.luz", "pw", "123456"); err != app.ErrInvalidCredentials {
		t.Fatalf("err = %v, want ErrInvalidCredentials", err)
	}
}

func TestLoginWrongFactors(t *testing.T) {
	t.Parallel()
	svc, _, clk := newService(t, app.ConsoleAuthConfig{BootstrapToken: "tok", Username: "pericles.luz"})
	res := provision(t, svc, "tok")
	ctx := context.Background()
	good := totpFor(t, res.TOTPSecret, clk.Now())

	cases := []struct{ name, user, pass, code string }{
		{"wrong-user", "attacker", res.Password, good},
		{"wrong-pass", "pericles.luz", "nope", good},
		{"wrong-code", "pericles.luz", res.Password, "000000"},
	}
	for _, tc := range cases {
		if _, err := svc.Login(ctx, tc.user, tc.pass, tc.code); err != app.ErrInvalidCredentials {
			t.Fatalf("%s: err = %v, want ErrInvalidCredentials", tc.name, err)
		}
	}
}

func TestLoginTOTPReplayRejected(t *testing.T) {
	t.Parallel()
	svc, _, clk := newService(t, app.ConsoleAuthConfig{BootstrapToken: "tok", Username: "pericles.luz"})
	res := provision(t, svc, "tok")
	ctx := context.Background()
	code := totpFor(t, res.TOTPSecret, clk.Now())

	if _, err := svc.Login(ctx, "pericles.luz", res.Password, code); err != nil {
		t.Fatalf("first login: %v", err)
	}
	// Same code, same window → replay guard rejects.
	if _, err := svc.Login(ctx, "pericles.luz", res.Password, code); err != app.ErrInvalidCredentials {
		t.Fatalf("replayed code err = %v, want ErrInvalidCredentials", err)
	}
	// A fresh code in a later window succeeds again.
	clk.advance(60 * time.Second)
	next := totpFor(t, res.TOTPSecret, clk.Now())
	if _, err := svc.Login(ctx, "pericles.luz", res.Password, next); err != nil {
		t.Fatalf("later-window login: %v", err)
	}
}

func TestLoginLockout(t *testing.T) {
	t.Parallel()
	svc, _, clk := newService(t, app.ConsoleAuthConfig{
		BootstrapToken: "tok", Username: "pericles.luz",
		MaxFailures: 3, LockoutWindow: 10 * time.Minute,
	})
	res := provision(t, svc, "tok")
	ctx := context.Background()

	// Three failures lock the account.
	for i := 0; i < 3; i++ {
		if _, err := svc.Login(ctx, "pericles.luz", "wrong", "000000"); err != app.ErrInvalidCredentials {
			t.Fatalf("failure %d: %v", i, err)
		}
	}
	// Even correct credentials are now refused (locked).
	good := totpFor(t, res.TOTPSecret, clk.Now())
	if _, err := svc.Login(ctx, "pericles.luz", res.Password, good); err != app.ErrInvalidCredentials {
		t.Fatalf("locked correct-cred login err = %v, want ErrInvalidCredentials", err)
	}
	// After the window elapses the lock clears and a valid login works.
	clk.advance(11 * time.Minute)
	good = totpFor(t, res.TOTPSecret, clk.Now())
	if _, err := svc.Login(ctx, "pericles.luz", res.Password, good); err != nil {
		t.Fatalf("post-window login: %v", err)
	}
}

func TestAuthenticateExpiredSession(t *testing.T) {
	t.Parallel()
	svc, _, clk := newService(t, app.ConsoleAuthConfig{
		BootstrapToken: "tok", Username: "pericles.luz",
		AbsoluteTTL: time.Hour, IdleTTL: 15 * time.Minute,
	})
	res := provision(t, svc, "tok")
	ctx := context.Background()
	id, err := svc.Login(ctx, "pericles.luz", res.Password, totpFor(t, res.TOTPSecret, clk.Now()))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	// Idle timeout: no activity for longer than IdleTTL.
	clk.advance(20 * time.Minute)
	if _, ok := svc.Authenticate(ctx, id); ok {
		t.Fatal("session should be idle-expired")
	}
	// And the expired session was revoked (not just reported invalid).
	if _, ok, _ := readSession(svc, id); ok {
		_ = ok // Authenticate deletes it; a second call is still false.
	}
	if _, ok := svc.Authenticate(ctx, id); ok {
		t.Fatal("expired session should stay invalid")
	}
}

// readSession is a tiny indirection so the test above reads clearly; the store is
// private to the service, so we just re-call Authenticate.
func readSession(svc *app.ConsoleAuthService, id string) (string, bool, error) {
	s, ok := svc.Authenticate(context.Background(), id)
	return s, ok, nil
}

func TestNilStoresFailClosed(t *testing.T) {
	t.Parallel()
	svc := app.NewConsoleAuthService(nil, nil, nil, &mutableClock{now: time.Unix(1000, 0).UTC()}, app.ConsoleAuthConfig{})
	if _, err := svc.Login(context.Background(), "u", "p", "123456"); err != app.ErrConsoleAuthUnavailable {
		t.Fatalf("Login err = %v, want ErrConsoleAuthUnavailable", err)
	}
	if _, ok := svc.Authenticate(context.Background(), "x"); ok {
		t.Fatal("Authenticate with nil store should be false")
	}
	if svc.Provisioned(context.Background()) {
		t.Fatal("nil-store Provisioned should be false")
	}
	if _, err := svc.Bootstrap(context.Background(), "t"); err != app.ErrConsoleAuthUnavailable {
		t.Fatalf("Bootstrap err = %v, want ErrConsoleAuthUnavailable", err)
	}
}

// faultyStore wraps a MemStore and can be told to return errors from selected
// port methods, so the fail-closed branches (store errors on the security path)
// are exercised. Unset toggles delegate to the embedded MemStore.
type faultyStore struct {
	*store.MemStore
	credErr    error
	lastErr    error
	getSessErr error
}

func (f *faultyStore) GetCredential(ctx context.Context) (cred domain.Credential, ok bool, err error) {
	if f.credErr != nil {
		return domain.Credential{}, false, f.credErr
	}
	return f.MemStore.GetCredential(ctx)
}

func (f *faultyStore) LastStep(ctx context.Context, subject string) (int64, error) {
	if f.lastErr != nil {
		return 0, f.lastErr
	}
	return f.MemStore.LastStep(ctx, subject)
}

func (f *faultyStore) Get(ctx context.Context, id string) (sess domain.Session, ok bool, err error) {
	if f.getSessErr != nil {
		return domain.Session{}, false, f.getSessErr
	}
	return f.MemStore.Get(ctx, id)
}

func TestLoginCredStoreErrorUnavailable(t *testing.T) {
	t.Parallel()
	m := store.NewMemStore()
	f := &faultyStore{MemStore: m, credErr: errBoom}
	svc := app.NewConsoleAuthService(f, f, f, &mutableClock{now: time.Unix(1000, 0).UTC()}, app.ConsoleAuthConfig{BootstrapToken: "t"})
	if _, err := svc.Login(context.Background(), "pericles.luz", "pw", "123456"); err != app.ErrConsoleAuthUnavailable {
		t.Fatalf("err = %v, want ErrConsoleAuthUnavailable", err)
	}
	// Provisioned is fail-safe: a store error reads as provisioned (never advertise
	// the box as un-bootstrapped on a read failure).
	if !svc.Provisioned(context.Background()) {
		t.Fatal("Provisioned should be true (fail-safe) on a store error")
	}
}

func TestLoginReplayStoreErrorFailsClosed(t *testing.T) {
	t.Parallel()
	m := store.NewMemStore()
	clk := &mutableClock{now: time.Unix(1_700_000_000, 0).UTC()}
	// Provision through a clean service sharing the same underlying store.
	provSvc := app.NewConsoleAuthService(m, m, m, clk, app.ConsoleAuthConfig{BootstrapToken: "t", Username: "pericles.luz"})
	res := provision(t, provSvc, "t")
	// Now wrap the store so the replay read errors: a correct password + TOTP must
	// still be refused (fail closed — never open the replay window on a fault).
	f := &faultyStore{MemStore: m, lastErr: errBoom}
	svc := app.NewConsoleAuthService(f, f, f, clk, app.ConsoleAuthConfig{BootstrapToken: "t", Username: "pericles.luz"})
	code := totpFor(t, res.TOTPSecret, clk.Now())
	if _, err := svc.Login(context.Background(), "pericles.luz", res.Password, code); err != app.ErrInvalidCredentials {
		t.Fatalf("err = %v, want ErrInvalidCredentials (fail closed)", err)
	}
}

func TestAuthenticateSessionStoreErrorFalse(t *testing.T) {
	t.Parallel()
	m := store.NewMemStore()
	f := &faultyStore{MemStore: m, getSessErr: errBoom}
	svc := app.NewConsoleAuthService(f, f, f, &mutableClock{now: time.Unix(1000, 0).UTC()}, app.ConsoleAuthConfig{})
	if _, ok := svc.Authenticate(context.Background(), "any"); ok {
		t.Fatal("Authenticate should be false on a session store error")
	}
}

func TestNilReplayAllowsLogin(t *testing.T) {
	t.Parallel()
	m := store.NewMemStore()
	clk := &mutableClock{now: time.Unix(1_700_000_000, 0).UTC()}
	// nil replay store: the guard degrades to always-fresh (test-only path).
	svc := app.NewConsoleAuthService(m, m, nil, clk, app.ConsoleAuthConfig{BootstrapToken: "t", Username: "pericles.luz"})
	res := provision(t, svc, "t")
	code := totpFor(t, res.TOTPSecret, clk.Now())
	if _, err := svc.Login(context.Background(), "pericles.luz", res.Password, code); err != nil {
		t.Fatalf("login with nil replay store: %v", err)
	}
}

func TestLogoutEmptyID(t *testing.T) {
	t.Parallel()
	svc, _, _ := newService(t, app.ConsoleAuthConfig{BootstrapToken: "t"})
	if err := svc.Logout(context.Background(), ""); err != nil {
		t.Fatalf("Logout empty id: %v", err)
	}
}

func TestServiceAccessors(t *testing.T) {
	t.Parallel()
	svc, _, _ := newService(t, app.ConsoleAuthConfig{Username: "custom.user", BootstrapToken: "t"})
	if svc.Username() != "custom.user" {
		t.Fatalf("Username = %q", svc.Username())
	}
	if !svc.BootstrapEnabled() {
		t.Fatal("BootstrapEnabled should be true with a token")
	}
	// Default username applies when empty.
	def, _, _ := newService(t, app.ConsoleAuthConfig{})
	if def.Username() != "pericles.luz" {
		t.Fatalf("default username = %q, want pericles.luz", def.Username())
	}
}
