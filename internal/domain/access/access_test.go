package access

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

func mustPseudo(t *testing.T, key string) Pseudonymizer {
	t.Helper()
	p, err := NewPseudonymizer([]byte(key))
	if err != nil {
		t.Fatalf("NewPseudonymizer: %v", err)
	}
	return p
}

func TestNewEntryInvariants(t *testing.T) {
	at := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	base := NewEntryParams{
		ID:         "acc-1",
		At:         at,
		Duration:   3 * time.Millisecond,
		TenantID:   "tnt-1",
		ClientID:   "client-abc",
		OperatorID: "",
		SubjectRef: "hmac-sha256:deadbeef",
		Object:     "rec:idrec-1",
		Action:     ActionReadRec,
	}
	tests := []struct {
		name    string
		mutate  func(p *NewEntryParams)
		wantErr bool
	}{
		{"valid", func(p *NewEntryParams) {}, false},
		{"blank id", func(p *NewEntryParams) { p.ID = "  " }, true},
		{"unknown action", func(p *NewEntryParams) { p.Action = Action("pii.read.bogus") }, true},
		{"empty action", func(p *NewEntryParams) { p.Action = "" }, true},
		{"blank tenant", func(p *NewEntryParams) { p.TenantID = "" }, true},
		{"blank subject_ref", func(p *NewEntryParams) { p.SubjectRef = "  " }, true},
		{"blank object", func(p *NewEntryParams) { p.Object = "" }, true},
		{"negative duration", func(p *NewEntryParams) { p.Duration = -1 * time.Second }, true},
		{"empty operator ok", func(p *NewEntryParams) { p.OperatorID = "" }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			tc.mutate(&p)
			_, err := NewEntry(p)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr && err != nil && !errors.As(err, new(*shared.ValidationError)) {
				t.Fatalf("expected ValidationError, got %T: %v", err, err)
			}
		})
	}
}

func TestNewEntryAccessorsAndDurationMs(t *testing.T) {
	at := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	e, err := NewEntry(NewEntryParams{
		ID:         "acc-1",
		At:         at,
		Duration:   1500 * time.Microsecond, // 1.5ms -> 1ms whole
		TenantID:   "tnt-1",
		ClientID:   "client-abc",
		OperatorID: "op-9",
		SubjectRef: "hmac-sha256:abc",
		Object:     "rec:idrec-1",
		Action:     ActionReadRec,
	})
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	if e.ID() != "acc-1" || e.TenantID() != "tnt-1" || e.ClientID() != "client-abc" ||
		e.OperatorID() != "op-9" || e.SubjectRef() != "hmac-sha256:abc" ||
		e.Object() != "rec:idrec-1" || e.Action() != ActionReadRec {
		t.Fatalf("accessor mismatch: %+v", e)
	}
	if !e.At().Equal(at) {
		t.Fatalf("At mismatch: %v", e.At())
	}
	if e.DurationMs() != 1 {
		t.Fatalf("DurationMs = %d, want 1", e.DurationMs())
	}
}

// TestEntryNeverStoresPlaintextPII is the minimisation regression (ADR-0008 §4):
// there is no constructor path that lets a devedor document/name land in the entry
// in clear. We build an entry from a pseudonym and assert the raw document/name
// appear in NONE of the entry's rendered fields.
func TestEntryNeverStoresPlaintextPII(t *testing.T) {
	const doc = "12345678909"
	const nome = "Fulano de Tal"
	pseudo := mustPseudo(t, "service-key-0123456789abcdef")
	ref := pseudo.Ref(doc)
	if strings.Contains(ref, doc) {
		t.Fatalf("subject_ref leaked the plaintext document")
	}
	e, err := NewEntry(NewEntryParams{
		ID:         "acc-1",
		At:         time.Unix(0, 0).UTC(),
		Duration:   0,
		TenantID:   "tnt-1",
		SubjectRef: ref,
		Object:     "rec:idrec-1",
		Action:     ActionReadRec,
	})
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	fields := []string{e.ID(), e.TenantID(), e.ClientID(), e.OperatorID(), e.SubjectRef(), e.Object(), string(e.Action())}
	for _, f := range fields {
		if strings.Contains(f, doc) {
			t.Fatalf("entry field %q leaked the plaintext document", f)
		}
		if strings.Contains(f, nome) {
			t.Fatalf("entry field %q leaked the plaintext name", f)
		}
	}
}

func TestPseudonymizerStableAndNormalised(t *testing.T) {
	p := mustPseudo(t, "service-key-0123456789abcdef")
	a := p.Ref("123.456.789-09")
	b := p.Ref("12345678909")
	if a != b {
		t.Fatalf("normalisation failed: %q != %q", a, b)
	}
	if !strings.HasPrefix(a, "hmac-sha256:") {
		t.Fatalf("missing algorithm prefix: %q", a)
	}
	if p.Ref("12345678909") == p.Ref("99999999999") {
		t.Fatalf("distinct documents collided")
	}
	// A different key yields a different ref for the same document (keyed, not a
	// plain hash).
	other := mustPseudo(t, "another-key-fedcba9876543210")
	if other.Ref("12345678909") == a {
		t.Fatalf("ref did not depend on the key")
	}
}

func TestNewPseudonymizerRejectsShortKey(t *testing.T) {
	if _, err := NewPseudonymizer([]byte("short")); err == nil {
		t.Fatalf("expected error for short key")
	}
	if _, err := NewPseudonymizer(nil); err == nil {
		t.Fatalf("expected error for nil key")
	}
}

// TestPseudonymizerLogValueRedactsKey asserts the LogValuer is write-only for the
// secret key: rendering it through slog never emits the key bytes.
func TestPseudonymizerLogValueRedactsKey(t *testing.T) {
	const key = "top-secret-hmac-key-abcdef012345"
	p := mustPseudo(t, key)
	got := p.LogValue().String()
	if strings.Contains(got, key) {
		t.Fatalf("LogValue leaked the key: %q", got)
	}
	if !strings.Contains(strings.ToUpper(got), "REDACTED") {
		t.Fatalf("LogValue should mark the key redacted: %q", got)
	}
	// Also exercise it through a real slog handler to be sure nothing else renders
	// the key when the pseudonymizer is logged as an attribute value.
	var sb strings.Builder
	l := slog.New(slog.NewTextHandler(&sb, nil))
	l.LogAttrs(context.Background(), slog.LevelInfo, "cfg", slog.Any("pseudo", p))
	if strings.Contains(sb.String(), key) {
		t.Fatalf("slog output leaked the key: %q", sb.String())
	}
}

func TestRetentionPolicy(t *testing.T) {
	if _, err := NewRetentionPolicy(0); err == nil {
		t.Fatalf("expected error for zero window")
	}
	if _, err := NewRetentionPolicy(-time.Hour); err == nil {
		t.Fatalf("expected error for negative window")
	}
	rp, err := NewRetentionPolicy(DefaultRetention)
	if err != nil {
		t.Fatalf("NewRetentionPolicy: %v", err)
	}
	if rp.Window() != DefaultRetention {
		t.Fatalf("Window mismatch")
	}
	now := time.Date(2026, 8, 6, 0, 0, 0, 0, time.UTC)
	want := now.Add(-DefaultRetention)
	if !rp.Cutoff(now).Equal(want) {
		t.Fatalf("Cutoff = %v, want %v", rp.Cutoff(now), want)
	}
}
