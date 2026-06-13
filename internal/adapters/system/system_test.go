package system_test

import (
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/system"
)

func TestClockNow(t *testing.T) {
	t.Parallel()
	before := time.Now().UTC().Add(-time.Second)
	got := system.Clock{}.Now()
	if got.Location() != time.UTC {
		t.Fatalf("clock not UTC: %v", got.Location())
	}
	if got.Before(before) {
		t.Fatal("clock returned a stale time")
	}
}

func TestIDProviderUniqueAndNonEmpty(t *testing.T) {
	t.Parallel()
	p := system.IDProvider{}
	seen := make(map[string]struct{})
	for i := 0; i < 1000; i++ {
		id := p.NewID()
		if len(id) != 32 {
			t.Fatalf("unexpected id length %d", len(id))
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate id %s", id)
		}
		seen[id] = struct{}{}
	}
}
