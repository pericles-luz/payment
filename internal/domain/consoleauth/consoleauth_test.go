package consoleauth

import (
	"testing"
	"time"
)

func TestGenerateSessionIDUniqueAndSized(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id, err := GenerateSessionID()
		if err != nil {
			t.Fatalf("GenerateSessionID: %v", err)
		}
		if len(id) != 43 { // 32 bytes base64url unpadded
			t.Fatalf("session id length = %d, want 43", len(id))
		}
		if seen[id] {
			t.Fatalf("duplicate session id %q", id)
		}
		seen[id] = true
	}
}

func TestCredentialAccessors(t *testing.T) {
	t.Parallel()
	hash, _ := HashPassword("pw")
	c := NewCredential("pericles.luz", hash, "SECRET")
	if c.Username() != "pericles.luz" {
		t.Fatalf("username = %q", c.Username())
	}
	if c.PasswordHash() != hash {
		t.Fatal("password hash mismatch")
	}
	if c.TOTPSecret() != "SECRET" {
		t.Fatalf("secret = %q", c.TOTPSecret())
	}
	if !c.VerifyPassword("pw") {
		t.Fatal("VerifyPassword should pass for correct password")
	}
	if c.VerifyPassword("nope") {
		t.Fatal("VerifyPassword should fail for wrong password")
	}
	// Rehydrate is an alias.
	r := RehydrateCredential("u", hash, "s")
	if r.Username() != "u" || r.TOTPSecret() != "s" {
		t.Fatal("RehydrateCredential mismatch")
	}
}

func TestSessionValidity(t *testing.T) {
	t.Parallel()
	start := time.Unix(1000, 0).UTC()
	absolute := time.Hour
	idle := 15 * time.Minute
	s := NewSession("id", "pericles.luz", start, absolute)

	if s.Subject() != "pericles.luz" || s.ID() != "id" {
		t.Fatal("accessor mismatch")
	}
	if !s.CreatedAt().Equal(start) {
		t.Fatal("created at mismatch")
	}
	if !s.ExpiresAt().Equal(start.Add(absolute)) {
		t.Fatal("absolute expiry mismatch")
	}

	// Fresh: valid.
	if !s.Valid(start.Add(time.Minute), idle) {
		t.Fatal("fresh session should be valid")
	}
	// Past absolute expiry: invalid even if just touched.
	touched := s.Touched(start.Add(absolute - time.Second))
	if touched.Valid(start.Add(absolute+time.Second), idle) {
		t.Fatal("session past absolute expiry must be invalid")
	}
	// Idle timeout: last-seen too old.
	if s.Valid(start.Add(idle+time.Minute), idle) {
		t.Fatal("session past idle window must be invalid")
	}
	// Touch resets the idle clock.
	t2 := start.Add(10 * time.Minute)
	refreshed := s.Touched(t2)
	if !refreshed.LastSeenAt().Equal(t2) {
		t.Fatal("Touched did not advance last-seen")
	}
	if !refreshed.Valid(t2.Add(idle-time.Minute), idle) {
		t.Fatal("touched session should be valid within the new idle window")
	}
	// idle==0 disables the idle bound (only absolute applies).
	if !s.Valid(start.Add(absolute-time.Second), 0) {
		t.Fatal("idle==0 should ignore inactivity")
	}
}

func TestRehydrateSession(t *testing.T) {
	t.Parallel()
	start := time.Unix(1000, 0).UTC()
	s := RehydrateSession("id", "u", start, start.Add(time.Hour), start.Add(time.Minute))
	if s.ID() != "id" || s.Subject() != "u" {
		t.Fatal("rehydrate accessor mismatch")
	}
	if !s.LastSeenAt().Equal(start.Add(time.Minute)) {
		t.Fatal("rehydrate last-seen mismatch")
	}
}
