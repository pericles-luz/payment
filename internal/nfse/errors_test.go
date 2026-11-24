package nfse

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestBusinessError(t *testing.T) {
	be := &BusinessError{HTTPStatus: 422, Items: []BusinessErrorItem{
		{Code: "E101", Message: "DPS duplicada"},
		{Code: "E102", Message: "IM inválida"},
	}}
	msg := be.Error()
	if !strings.Contains(msg, "E101") || !strings.Contains(msg, "DPS duplicada") || !strings.Contains(msg, "E102") {
		t.Errorf("msg = %q", msg)
	}

	empty := &BusinessError{HTTPStatus: 400}
	if !strings.Contains(empty.Error(), "400") {
		t.Errorf("empty msg = %q", empty.Error())
	}

	wrapped := fmt.Errorf("emit failed: %w", be)
	got, ok := AsBusinessError(wrapped)
	if !ok || got != be {
		t.Fatalf("AsBusinessError did not unwrap")
	}
	if _, ok := AsBusinessError(errors.New("plain")); ok {
		t.Error("plain error matched BusinessError")
	}
}

func TestTransportError(t *testing.T) {
	inner := errors.New("connection refused")
	te := &TransportError{Op: "do", Err: inner}
	if !strings.Contains(te.Error(), "do") || !strings.Contains(te.Error(), "connection refused") {
		t.Errorf("msg = %q", te.Error())
	}
	if !errors.Is(te, inner) {
		t.Error("TransportError should unwrap to inner")
	}
}
