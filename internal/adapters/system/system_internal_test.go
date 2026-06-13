package system

import (
	"errors"
	"testing"
)

func TestNewIDPanicsOnEntropyFailure(t *testing.T) {
	orig := randRead
	t.Cleanup(func() { randRead = orig })
	randRead = func([]byte) (int, error) { return 0, errors.New("no entropy") }

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on entropy failure")
		}
	}()
	_ = IDProvider{}.NewID()
}
