package termsconsent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

func mustEvidence(t *testing.T, channel, ip, ua string) Evidence {
	t.Helper()
	e, err := NewEvidence(channel, ip, ua)
	if err != nil {
		t.Fatalf("NewEvidence(%q,%q,%q): %v", channel, ip, ua, err)
	}
	return e
}

func TestNewEvidence(t *testing.T) {
	t.Run("trims and stores", func(t *testing.T) {
		e, err := NewEvidence("  web-console  ", " 203.0.113.7 ", "  Mozilla/5.0  ")
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if e.Channel() != "web-console" || e.IP() != "203.0.113.7" || e.UserAgent() != "Mozilla/5.0" {
			t.Fatalf("unexpected evidence: %+v", e)
		}
	})
	t.Run("channel required", func(t *testing.T) {
		if _, err := NewEvidence("   ", "1.2.3.4", "ua"); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("want ErrValidation, got %v", err)
		}
	})
	t.Run("ip and user-agent optional", func(t *testing.T) {
		e, err := NewEvidence("api", "", "")
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if e.IP() != "" || e.UserAgent() != "" {
			t.Fatalf("want empty optional fields, got %+v", e)
		}
	})
}

func validParams() NewRecordParams {
	return NewRecordParams{
		ID:           "cns_01",
		TenantID:     "tenant-a",
		Subject:      "user-42",
		TermsVersion: "2026-07-01",
	}
}

func TestNewRecord(t *testing.T) {
	at := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)

	t.Run("valid", func(t *testing.T) {
		p := validParams()
		p.Evidence = mustEvidence(t, "web-console", "203.0.113.7", "Mozilla/5.0")
		r, err := NewRecord(p, at)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if r.ID() != "cns_01" || r.TenantID() != "tenant-a" || r.Subject() != "user-42" ||
			r.TermsVersion() != "2026-07-01" {
			t.Fatalf("unexpected record: %+v", r)
		}
		if !r.GrantedAt().Equal(at) {
			t.Fatalf("granted at = %v, want %v", r.GrantedAt(), at)
		}
		if r.Evidence().Channel() != "web-console" {
			t.Fatalf("evidence channel = %q", r.Evidence().Channel())
		}
	})

	t.Run("granted_at normalised to UTC", func(t *testing.T) {
		p := validParams()
		p.Evidence = mustEvidence(t, "api", "", "")
		loc := time.FixedZone("BRT", -3*3600)
		local := time.Date(2026, 7, 3, 9, 0, 0, 0, loc)
		r, err := NewRecord(p, local)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if r.GrantedAt().Location() != time.UTC {
			t.Fatalf("granted_at not UTC: %v", r.GrantedAt().Location())
		}
		if !r.GrantedAt().Equal(local) {
			t.Fatalf("instant changed: %v vs %v", r.GrantedAt(), local)
		}
	})

	t.Run("validation", func(t *testing.T) {
		cases := []struct {
			name   string
			mutate func(p *NewRecordParams)
			at     time.Time
		}{
			{"empty id", func(p *NewRecordParams) { p.ID = "  " }, at},
			{"empty tenant", func(p *NewRecordParams) { p.TenantID = "" }, at},
			{"empty subject", func(p *NewRecordParams) { p.Subject = " " }, at},
			{"empty version", func(p *NewRecordParams) { p.TermsVersion = "" }, at},
			{"zero evidence", func(p *NewRecordParams) { p.Evidence = Evidence{} }, at},
			{"zero time", func(p *NewRecordParams) {}, time.Time{}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				p := validParams()
				p.Evidence = mustEvidence(t, "web-console", "1.2.3.4", "ua")
				tc.mutate(&p)
				if _, err := NewRecord(p, tc.at); !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("want ErrValidation, got %v", err)
				}
			})
		}
	})

	t.Run("trims identifying fields", func(t *testing.T) {
		p := NewRecordParams{
			ID:           "  cns_02 ",
			TenantID:     " tenant-b ",
			Subject:      "  user-7 ",
			TermsVersion: "  v2 ",
			Evidence:     mustEvidence(t, "api", "", ""),
		}
		r, err := NewRecord(p, at)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if r.ID() != "cns_02" || r.TenantID() != "tenant-b" || r.Subject() != "user-7" || r.TermsVersion() != "v2" {
			t.Fatalf("fields not trimmed: %+v", r)
		}
	})
}

func TestRehydrate(t *testing.T) {
	at := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	e := mustEvidence(t, "web-console", "203.0.113.7", "Mozilla/5.0")
	r := Rehydrate("cns_03", "tenant-c", "user-9", "v3", at, e)
	if r.ID() != "cns_03" || r.TenantID() != "tenant-c" || r.Subject() != "user-9" ||
		r.TermsVersion() != "v3" || !r.GrantedAt().Equal(at) || r.Evidence() != e {
		t.Fatalf("unexpected rehydrated record: %+v", r)
	}
}

// TestLogValueRedactsPII asserts a Record never leaks the subject, IP or
// user-agent through structured logging (segredo/PII-zero em log). The non-PII
// descriptors (id/tenant/version/channel) must still be present so the log stays
// useful.
func TestLogValueRedactsPII(t *testing.T) {
	at := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	p := validParams()
	p.Subject = "cpf-12345678901"
	p.Evidence = mustEvidence(t, "web-console", "203.0.113.7", "Mozilla/5.0 SecretBrowser")
	r, err := NewRecord(p, at)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.LogAttrs(context.Background(), slog.LevelInfo, "consent", slog.Any("consent", r))
	out := buf.String()

	for _, leaked := range []string{"cpf-12345678901", "203.0.113.7", "SecretBrowser"} {
		if bytes.Contains(buf.Bytes(), []byte(leaked)) {
			t.Fatalf("PII %q leaked into log: %s", leaked, out)
		}
	}
	// Structure sanity: parse and confirm redaction markers + non-PII descriptors.
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("log not JSON: %v (%s)", err, out)
	}
	group, ok := parsed["consent"].(map[string]any)
	if !ok {
		t.Fatalf("consent group missing: %s", out)
	}
	if group["subject"] != "[REDACTED]" || group["ip"] != "[REDACTED]" || group["user_agent"] != "[REDACTED]" {
		t.Fatalf("PII not redacted: %v", group)
	}
	if group["terms_version"] != "2026-07-01" || group["channel"] != "web-console" || group["tenant_id"] != "tenant-a" {
		t.Fatalf("non-PII descriptors missing/wrong: %v", group)
	}
}
