package c6

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// pixTestServer is a configurable C6 PIX + OAuth2 double backed by httptest TLS.
// It stores immediate charges by txid so idempotent re-submits can be asserted,
// and records the last request so tests can check method/headers/body without
// races.
type pixTestServer struct {
	*httptest.Server

	mu          sync.Mutex
	cobs        map[string]pixChargeResponseBody // keyed by txid (PUT target)
	putHits     int
	getHits     int
	lastMethod  string
	lastAuth    string
	lastIdemKey string
	lastReqBody pixChargeRequestBody

	// Overridable handlers; nil uses the happy-path default.
	putHandler http.HandlerFunc
	getHandler http.HandlerFunc
}

func newPixTestServer(t *testing.T) *pixTestServer {
	t.Helper()
	ts := &pixTestServer{cobs: make(map[string]pixChargeResponseBody)}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		user, _, _ := r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok-` + user + `","token_type":"Bearer","expires_in":3600}`))
	})
	mux.HandleFunc("/v1/pix/", func(w http.ResponseWriter, r *http.Request) {
		txid := strings.TrimPrefix(r.URL.Path, "/v1/pix/")
		ts.mu.Lock()
		ts.lastMethod = r.Method
		ts.lastAuth = r.Header.Get("Authorization")
		switch r.Method {
		case http.MethodPut:
			ts.putHits++
			ts.lastIdemKey = r.Header.Get("Idempotency-Key")
			_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&ts.lastReqBody)
			h := ts.putHandler
			ts.mu.Unlock()
			if h != nil {
				h(w, r)
				return
			}
			ts.mu.Lock()
			cob, ok := ts.cobs[txid]
			if !ok {
				cob = pixChargeResponseBody{
					TxID:          txid,
					Status:        "ATIVA",
					Calendario:    pixCalendario{Expiracao: ts.lastReqBody.Calendario.Expiracao},
					Loc:           pixLoc{Location: "pix.example.com/qr/v2/" + txid},
					PixCopiaECola: "000201..." + txid,
				}
				ts.cobs[txid] = cob
			}
			ts.mu.Unlock()
			writeJSON(w, http.StatusCreated, cob)
		case http.MethodGet:
			ts.getHits++
			h := ts.getHandler
			cob, ok := ts.cobs[txid]
			ts.mu.Unlock()
			if h != nil {
				h(w, r)
				return
			}
			if !ok {
				writeJSON(w, http.StatusNotFound, map[string]string{"code": "NOT_FOUND"})
				return
			}
			writeJSON(w, http.StatusOK, cob)
		default:
			ts.mu.Unlock()
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	ts.Server = httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (ts *pixTestServer) provider(t *testing.T, creds ports.CredentialStore, now func() time.Time) *Provider {
	t.Helper()
	p, err := New(Config{
		BaseURL:    ts.URL,
		TokenURL:   ts.URL + "/oauth/token",
		HTTPClient: ts.Client(),
		Now:        now,
	}, creds)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func fixedClock(ts time.Time) func() time.Time { return func() time.Time { return ts } }

func TestCreateImmediateChargeSuccess(t *testing.T) {
	t.Parallel()
	ts := newPixTestServer(t)
	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	p := ts.provider(t, oneTenant("t1", "client-1", "secret-1"), fixedClock(now))

	res, err := p.CreateImmediateCharge(context.Background(), "t1", ports.ChargeRequest{
		TenantID: "t1", PaymentID: "pay-1", IdempotencyKey: "idem-1", AmountCents: 1050, Currency: "BRL",
	}, 30*time.Minute)
	if err != nil {
		t.Fatalf("CreateImmediateCharge: %v", err)
	}

	if ts.lastMethod != http.MethodPut {
		t.Fatalf("expected PUT, got %s", ts.lastMethod)
	}
	if ts.lastAuth != "Bearer tok-client-1" {
		t.Fatalf("bearer token not attached: %q", ts.lastAuth)
	}
	if ts.lastIdemKey != "idem-1" {
		t.Fatalf("idempotency key not forwarded: %q", ts.lastIdemKey)
	}
	if ts.lastReqBody.Calendario.Expiracao != 1800 {
		t.Fatalf("expiracao: want 1800s, got %d", ts.lastReqBody.Calendario.Expiracao)
	}
	if ts.lastReqBody.Valor.Original != "10.50" {
		t.Fatalf("valor.original: want 10.50, got %q", ts.lastReqBody.Valor.Original)
	}

	wantTx := pixTxID(ports.ChargeRequest{IdempotencyKey: "idem-1"})
	if res.TxID != wantTx {
		t.Fatalf("txid: want %q, got %q", wantTx, res.TxID)
	}
	if res.Status != "ATIVA" {
		t.Fatalf("status: want ATIVA, got %q", res.Status)
	}
	if res.QRCodePayload == "" || res.QRCodeLocation == "" {
		t.Fatalf("QR material missing: %+v", res)
	}
	// No criacao on the create response => expiry is clock + window.
	if want := now.Add(30 * time.Minute); !res.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt: want %v, got %v", want, res.ExpiresAt)
	}
}

func TestCreateImmediateChargeDefaultExpiry(t *testing.T) {
	t.Parallel()
	ts := newPixTestServer(t)
	p := ts.provider(t, oneTenant("t1", "c", "s"), nil)

	if _, err := p.CreateImmediateCharge(context.Background(), "t1", ports.ChargeRequest{
		TenantID: "t1", PaymentID: "pay-1", AmountCents: 100, Currency: "BRL",
	}, 0); err != nil {
		t.Fatalf("CreateImmediateCharge: %v", err)
	}
	if ts.lastReqBody.Calendario.Expiracao != int64(defaultPixExpiry/time.Second) {
		t.Fatalf("default expiry not applied: %d", ts.lastReqBody.Calendario.Expiracao)
	}
	// No idempotency key => txid falls back to the PaymentID anchor.
	if ts.lastIdemKey != "pay-1" {
		t.Fatalf("idempotency key should fall back to payment id, got %q", ts.lastIdemKey)
	}
}

// TestCreateImmediateChargeIdempotentResubmit proves a re-submit with the same
// idempotency key resolves to the same charge and creates no duplicate at the PSP.
func TestCreateImmediateChargeIdempotentResubmit(t *testing.T) {
	t.Parallel()
	ts := newPixTestServer(t)
	p := ts.provider(t, oneTenant("t1", "c", "s"), nil)

	req := ports.ChargeRequest{TenantID: "t1", PaymentID: "pay-1", IdempotencyKey: "idem-1", AmountCents: 500, Currency: "BRL"}
	first, err := p.CreateImmediateCharge(context.Background(), "t1", req, time.Hour)
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	second, err := p.CreateImmediateCharge(context.Background(), "t1", req, time.Hour)
	if err != nil {
		t.Fatalf("second create: %v", err)
	}

	if first.TxID != second.TxID {
		t.Fatalf("re-submit changed txid: %q vs %q", first.TxID, second.TxID)
	}
	ts.mu.Lock()
	distinct := len(ts.cobs)
	hits := ts.putHits
	ts.mu.Unlock()
	if distinct != 1 {
		t.Fatalf("expected a single charge at the PSP, got %d", distinct)
	}
	if hits != 2 {
		t.Fatalf("expected 2 PUTs (both idempotent), got %d", hits)
	}
}

func TestGetImmediateChargeReconcile(t *testing.T) {
	t.Parallel()
	ts := newPixTestServer(t)
	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	criacao := now.Add(-10 * time.Minute)
	ts.cobs["tx-paid"] = pixChargeResponseBody{
		TxID:          "tx-paid",
		Status:        "CONCLUIDA",
		Calendario:    pixCalendario{Criacao: criacao.Format(time.RFC3339), Expiracao: 3600},
		Loc:           pixLoc{Location: "pix.example.com/qr/v2/tx-paid"},
		PixCopiaECola: "000201-paid",
	}
	p := ts.provider(t, oneTenant("t1", "c", "s"), fixedClock(now))

	res, err := p.GetImmediateCharge(context.Background(), "t1", "tx-paid")
	if err != nil {
		t.Fatalf("GetImmediateCharge: %v", err)
	}
	if res.Status != "CONCLUIDA" {
		t.Fatalf("status: want CONCLUIDA, got %q", res.Status)
	}
	// Expiry is anchored to the PSP creation time, not the local clock.
	if want := criacao.Add(time.Hour); !res.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt: want %v, got %v", want, res.ExpiresAt)
	}
	if ts.lastMethod != http.MethodGet {
		t.Fatalf("expected GET, got %s", ts.lastMethod)
	}
}

// TestGetImmediateChargeExpiredQR proves the reconciled charge exposes enough to
// detect an expired QR: ExpiresAt is in the past relative to the adapter clock.
func TestGetImmediateChargeExpiredQR(t *testing.T) {
	t.Parallel()
	ts := newPixTestServer(t)
	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	criacao := now.Add(-2 * time.Hour) // created 2h ago, 1h window => expired
	ts.cobs["tx-exp"] = pixChargeResponseBody{
		TxID:       "tx-exp",
		Status:     "REMOVIDA_PELO_PSP",
		Calendario: pixCalendario{Criacao: criacao.Format(time.RFC3339), Expiracao: 3600},
	}
	p := ts.provider(t, oneTenant("t1", "c", "s"), fixedClock(now))

	res, err := p.GetImmediateCharge(context.Background(), "t1", "tx-exp")
	if err != nil {
		t.Fatalf("GetImmediateCharge: %v", err)
	}
	if !now.After(res.ExpiresAt) {
		t.Fatalf("expected QR expired: now=%v expiresAt=%v", now, res.ExpiresAt)
	}
	if res.Status != "REMOVIDA_PELO_PSP" {
		t.Fatalf("status: want REMOVIDA_PELO_PSP, got %q", res.Status)
	}
}

func TestGetImmediateChargeNotFound(t *testing.T) {
	t.Parallel()
	ts := newPixTestServer(t)
	p := ts.provider(t, oneTenant("t1", "c", "s"), nil)
	if _, err := p.GetImmediateCharge(context.Background(), "t1", "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestCreateImmediateChargeErrorMapping(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		status int
		want   error
	}{
		{"validation", 422, shared.ErrValidation},
		{"conflict", 409, shared.ErrConflict},
		{"unavailable", 503, shared.ErrUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ts := newPixTestServer(t)
			ts.putHandler = func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, tc.status, map[string]string{"code": "X"})
			}
			p := ts.provider(t, oneTenant("t1", "c", "s"), nil)
			_, err := p.CreateImmediateCharge(context.Background(), "t1", ports.ChargeRequest{
				TenantID: "t1", PaymentID: "p", AmountCents: 1, Currency: "BRL",
			}, time.Hour)
			if !errors.Is(err, tc.want) {
				t.Fatalf("status %d: want %v, got %v", tc.status, tc.want, err)
			}
		})
	}
}

func TestCreateImmediateChargeMalformedBody(t *testing.T) {
	t.Parallel()
	ts := newPixTestServer(t)
	ts.putHandler = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`not-json`))
	}
	p := ts.provider(t, oneTenant("t1", "c", "s"), nil)
	if _, err := p.CreateImmediateCharge(context.Background(), "t1", ports.ChargeRequest{
		TenantID: "t1", PaymentID: "p", AmountCents: 1, Currency: "BRL",
	}, time.Hour); !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("malformed 2xx body should map to ErrUnavailable, got %v", err)
	}
}

func TestPixTokenUnauthorized(t *testing.T) {
	t.Parallel()
	ts := newPixTestServer(t)
	// Override the token endpoint to reject credentials.
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
	})
	ts.Server.Config.Handler = mux
	p := ts.provider(t, oneTenant("t1", "c", "s"), nil)
	if _, err := p.CreateImmediateCharge(context.Background(), "t1", ports.ChargeRequest{
		TenantID: "t1", PaymentID: "p", AmountCents: 1, Currency: "BRL",
	}, time.Hour); !errors.Is(err, shared.ErrUnauthorized) {
		t.Fatalf("bad credentials should map to ErrUnauthorized, got %v", err)
	}
}

func TestPixMissingCredential(t *testing.T) {
	t.Parallel()
	ts := newPixTestServer(t)
	p := ts.provider(t, &fakeCreds{creds: map[string]ports.BankCredential{}}, nil)
	if _, err := p.GetImmediateCharge(context.Background(), "unknown", "tx"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing credential should propagate ErrNotFound, got %v", err)
	}
	ts.mu.Lock()
	hits := ts.getHits
	ts.mu.Unlock()
	if hits != 0 {
		t.Fatalf("PIX endpoint must not be hit without a credential, hits=%d", hits)
	}
}

func TestPixContextCancellation(t *testing.T) {
	t.Parallel()
	ts := newPixTestServer(t)
	p := ts.provider(t, oneTenant("t1", "c", "s"), nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.CreateImmediateCharge(ctx, "t1", ports.ChargeRequest{
		TenantID: "t1", PaymentID: "p", AmountCents: 1, Currency: "BRL",
	}, time.Hour); err == nil {
		t.Fatal("expected error with a cancelled context")
	}
}

func TestFormatAmount(t *testing.T) {
	t.Parallel()
	cases := []struct {
		cents int64
		want  string
	}{
		{0, "0.00"},
		{5, "0.05"},
		{99, "0.99"},
		{100, "1.00"},
		{1050, "10.50"},
		{123456, "1234.56"},
		{-250, "-2.50"},
	}
	for _, tc := range cases {
		if got := formatAmount(tc.cents); got != tc.want {
			t.Fatalf("formatAmount(%d): want %q, got %q", tc.cents, tc.want, got)
		}
	}
}

func TestPixExpiresAt(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	p := &Provider{now: fixedClock(now)}

	if got := p.pixExpiresAt(pixCalendario{Expiracao: 0}); !got.IsZero() {
		t.Fatalf("zero expiracao should yield zero time, got %v", got)
	}
	// Invalid criacao falls back to the adapter clock.
	if got := p.pixExpiresAt(pixCalendario{Criacao: "not-a-time", Expiracao: 60}); !got.Equal(now.Add(time.Minute)) {
		t.Fatalf("invalid criacao should fall back to clock, got %v", got)
	}
	// Valid criacao anchors the expiry.
	c := now.Add(-time.Hour)
	if got := p.pixExpiresAt(pixCalendario{Criacao: c.Format(time.RFC3339), Expiracao: 60}); !got.Equal(c.Add(time.Minute)) {
		t.Fatalf("valid criacao should anchor expiry, got %v", got)
	}
}

func TestPixTxIDValid(t *testing.T) {
	t.Parallel()
	tx := pixTxID(ports.ChargeRequest{IdempotencyKey: "idem-1"})
	if len(tx) != pixTxIDLen {
		t.Fatalf("txid length: want %d, got %d (%q)", pixTxIDLen, len(tx), tx)
	}
	if len(tx) < 26 || len(tx) > 35 {
		t.Fatalf("txid out of BACEN range [26,35]: %d", len(tx))
	}
	for _, r := range tx {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'z')) {
			t.Fatalf("txid has non-alphanumeric rune %q", r)
		}
	}
	// Deterministic and anchored: same key => same txid; different key => different.
	if pixTxID(ports.ChargeRequest{IdempotencyKey: "idem-1"}) != tx {
		t.Fatal("txid not deterministic for the same key")
	}
	if pixTxID(ports.ChargeRequest{IdempotencyKey: "idem-2"}) == tx {
		t.Fatal("txid collided across distinct keys")
	}
}

// TestCreateImmediateChargeEmptyAnchorRejected proves the boundary guard: a
// request whose idempotency anchor is empty (both IdempotencyKey and PaymentID
// unset) is rejected with ErrValidation before any txid is derived, and the PIX
// endpoint is never touched. Without the guard the txid would be the constant
// sha256("")[:32] and two distinct charges would collide on the idempotent PUT
// (silent wrong-amount). SEC-1, SIN-64769.
func TestCreateImmediateChargeEmptyAnchorRejected(t *testing.T) {
	t.Parallel()
	ts := newPixTestServer(t)
	p := ts.provider(t, oneTenant("t1", "c", "s"), nil)

	_, err := p.CreateImmediateCharge(context.Background(), "t1", ports.ChargeRequest{
		TenantID: "t1", AmountCents: 1050, Currency: "BRL", // no IdempotencyKey, no PaymentID
	}, time.Hour)
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty anchor must map to ErrValidation, got %v", err)
	}
	ts.mu.Lock()
	hits := ts.putHits
	ts.mu.Unlock()
	if hits != 0 {
		t.Fatalf("PIX endpoint must not be touched on an empty anchor, putHits=%d", hits)
	}
}

// TestCreateImmediateChargeNonPositiveAmountRejected proves the boundary guard
// for a non-positive amount: there is no domain guarantee of AmountCents > 0, so
// the adapter rejects <=0 with ErrValidation and never touches the PSP. SEC-3,
// SIN-64769.
func TestCreateImmediateChargeNonPositiveAmountRejected(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		amount int64
	}{
		{"zero", 0},
		{"negative", -100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ts := newPixTestServer(t)
			p := ts.provider(t, oneTenant("t1", "c", "s"), nil)

			_, err := p.CreateImmediateCharge(context.Background(), "t1", ports.ChargeRequest{
				TenantID: "t1", PaymentID: "pay-1", IdempotencyKey: "idem-1", AmountCents: tc.amount, Currency: "BRL",
			}, time.Hour)
			if !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("amount %d must map to ErrValidation, got %v", tc.amount, err)
			}
			ts.mu.Lock()
			hits := ts.putHits
			ts.mu.Unlock()
			if hits != 0 {
				t.Fatalf("PIX endpoint must not be touched on a non-positive amount, putHits=%d", hits)
			}
		})
	}
}

// TestGetImmediateChargeReconcilesAmount proves the reconciled result carries
// both the expected (valor.original) and received (sum of pix[].valor) amounts,
// and that a CONCLUIDA charge paid in full reconciles.
func TestGetImmediateChargeReconcilesAmount(t *testing.T) {
	t.Parallel()
	ts := newPixTestServer(t)
	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	ts.cobs["tx-paid"] = pixChargeResponseBody{
		TxID:       "tx-paid",
		Status:     "CONCLUIDA",
		Calendario: pixCalendario{Criacao: now.Add(-time.Minute).Format(time.RFC3339), Expiracao: 3600},
		Valor:      pixValor{Original: "10.50"},
		Pix:        []pixReceipt{{Valor: "10.50"}},
	}
	p := ts.provider(t, oneTenant("t1", "c", "s"), fixedClock(now))

	res, err := p.GetImmediateCharge(context.Background(), "t1", "tx-paid")
	if err != nil {
		t.Fatalf("GetImmediateCharge: %v", err)
	}
	if res.ExpectedAmountCents != 1050 {
		t.Fatalf("expected amount: want 1050, got %d", res.ExpectedAmountCents)
	}
	if res.ReceivedAmountCents != 1050 {
		t.Fatalf("received amount: want 1050, got %d", res.ReceivedAmountCents)
	}
	if !res.AmountReconciled() {
		t.Fatalf("a fully-paid charge must reconcile: %+v", res)
	}
}

// TestGetImmediateChargeAmountMismatch proves a charge paid to a lesser value
// does not reconcile even when its status is CONCLUIDA — the signal a settlement
// use-case uses to refuse liquidation (threat W3).
func TestGetImmediateChargeAmountMismatch(t *testing.T) {
	t.Parallel()
	ts := newPixTestServer(t)
	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	ts.cobs["tx-partial"] = pixChargeResponseBody{
		TxID:       "tx-partial",
		Status:     "CONCLUIDA",
		Calendario: pixCalendario{Criacao: now.Add(-time.Minute).Format(time.RFC3339), Expiracao: 3600},
		Valor:      pixValor{Original: "10.50"},
		Pix:        []pixReceipt{{Valor: "5.00"}},
	}
	p := ts.provider(t, oneTenant("t1", "c", "s"), fixedClock(now))

	res, err := p.GetImmediateCharge(context.Background(), "t1", "tx-partial")
	if err != nil {
		t.Fatalf("GetImmediateCharge: %v", err)
	}
	if res.Status != "CONCLUIDA" {
		t.Fatalf("status: want CONCLUIDA, got %q", res.Status)
	}
	if res.ExpectedAmountCents != 1050 || res.ReceivedAmountCents != 500 {
		t.Fatalf("amounts: want expected=1050 received=500, got expected=%d received=%d",
			res.ExpectedAmountCents, res.ReceivedAmountCents)
	}
	if res.AmountReconciled() {
		t.Fatalf("a partial payment must NOT reconcile: %+v", res)
	}
}

// TestGetImmediateChargeSumsMultipleReceipts proves the received amount is the
// sum of every pix[] receipt, so a charge settled across several transactions
// reconciles to its original total.
func TestGetImmediateChargeSumsMultipleReceipts(t *testing.T) {
	t.Parallel()
	ts := newPixTestServer(t)
	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	ts.cobs["tx-split"] = pixChargeResponseBody{
		TxID:       "tx-split",
		Status:     "CONCLUIDA",
		Calendario: pixCalendario{Criacao: now.Add(-time.Minute).Format(time.RFC3339), Expiracao: 3600},
		Valor:      pixValor{Original: "10.50"},
		Pix:        []pixReceipt{{Valor: "4.00"}, {Valor: "6.50"}},
	}
	p := ts.provider(t, oneTenant("t1", "c", "s"), fixedClock(now))

	res, err := p.GetImmediateCharge(context.Background(), "t1", "tx-split")
	if err != nil {
		t.Fatalf("GetImmediateCharge: %v", err)
	}
	if res.ReceivedAmountCents != 1050 {
		t.Fatalf("received amount: want 1050 (4.00+6.50), got %d", res.ReceivedAmountCents)
	}
	if !res.AmountReconciled() {
		t.Fatalf("receipts summing to the original must reconcile: %+v", res)
	}
}

// TestGetImmediateChargeUnpaidHasNoReceipts proves an ATIVA charge reports the
// expected amount but zero received, and therefore does not reconcile.
func TestGetImmediateChargeUnpaidHasNoReceipts(t *testing.T) {
	t.Parallel()
	ts := newPixTestServer(t)
	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	ts.cobs["tx-active"] = pixChargeResponseBody{
		TxID:       "tx-active",
		Status:     "ATIVA",
		Calendario: pixCalendario{Criacao: now.Add(-time.Minute).Format(time.RFC3339), Expiracao: 3600},
		Valor:      pixValor{Original: "10.50"},
	}
	p := ts.provider(t, oneTenant("t1", "c", "s"), fixedClock(now))

	res, err := p.GetImmediateCharge(context.Background(), "t1", "tx-active")
	if err != nil {
		t.Fatalf("GetImmediateCharge: %v", err)
	}
	if res.ExpectedAmountCents != 1050 || res.ReceivedAmountCents != 0 {
		t.Fatalf("amounts: want expected=1050 received=0, got expected=%d received=%d",
			res.ExpectedAmountCents, res.ReceivedAmountCents)
	}
	if res.AmountReconciled() {
		t.Fatalf("an unpaid charge must NOT reconcile: %+v", res)
	}
}

// TestGetImmediateChargeMalformedAmount proves a present-but-corrupt money field
// is never read as zero: it maps to ErrUnavailable (malformed upstream body)
// rather than silently producing a reconcilable result.
func TestGetImmediateChargeMalformedAmount(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
	}{
		{"malformed original", `{"txid":"tx","status":"CONCLUIDA","valor":{"original":"abc"}}`},
		{"malformed receipt", `{"txid":"tx","status":"CONCLUIDA","valor":{"original":"10.50"},"pix":[{"valor":"10,50"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ts := newPixTestServer(t)
			ts.getHandler = func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tc.body))
			}
			p := ts.provider(t, oneTenant("t1", "c", "s"), nil)
			if _, err := p.GetImmediateCharge(context.Background(), "t1", "tx"); !errors.Is(err, shared.ErrUnavailable) {
				t.Fatalf("malformed amount should map to ErrUnavailable, got %v", err)
			}
		})
	}
}

func TestParseAmountCents(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"", 0, false},
		{"0.00", 0, false},
		{"0.05", 5, false},
		{"0.99", 99, false},
		{"1.00", 100, false},
		{"10.50", 1050, false},
		{"10.5", 1050, false},
		{"10.05", 1005, false},
		{"10", 1000, false},
		{"1234.56", 123456, false},
		{"-2.50", -250, false},
		{" 10.50 ", 1050, false},
		{"abc", 0, true},
		{"10.503", 0, true},
		{"1.2.3", 0, true},
		{".50", 0, true},
		{"10.5a", 0, true},
	}
	for _, tc := range cases {
		got, err := parseAmountCents(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("parseAmountCents(%q): want error, got %d", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parseAmountCents(%q): unexpected error %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("parseAmountCents(%q): want %d, got %d", tc.in, tc.want, got)
		}
	}
}

// TestFormatParseAmountRoundTrip proves parseAmountCents is the inverse of
// formatAmount across representative magnitudes and signs.
func TestFormatParseAmountRoundTrip(t *testing.T) {
	t.Parallel()
	for _, cents := range []int64{0, 5, 99, 100, 1050, 123456, -250} {
		got, err := parseAmountCents(formatAmount(cents))
		if err != nil {
			t.Fatalf("round-trip %d: %v", cents, err)
		}
		if got != cents {
			t.Fatalf("round-trip: %d -> %q -> %d", cents, formatAmount(cents), got)
		}
	}
}

// TestParseAmountCentsOverflowCeiling asserts the shared parser rejects amounts
// above the per-charge sanity ceiling explicitly, rather than relying on int64
// wrap-around being caught downstream by the >0 reconciliation guard (SIN-64777
// defense-in-depth). The ceiling boundary itself is accepted.
func TestParseAmountCentsOverflowCeiling(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"at ceiling accepted", "1000000000000.00", false},
		{"just above ceiling rejected", "1000000000001.00", true},
		{"absurd magnitude that would overflow int64 rejected", "100000000000000000.00", true},
		{"absurd negative magnitude rejected", "-100000000000000000.00", true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseAmountCents(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseAmountCents(%q): want error, got %d", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseAmountCents(%q): unexpected error %v", tc.in, err)
			}
		})
	}
}
