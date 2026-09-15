package c6

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
)

const pdfBoletoID = "3f2a9c1d7e4b48a0b5c6d7e8f9a0b1c2"

// The happy path: raw PDF bytes come back verbatim, addressed by the reference.
func TestGetBoletoPDFReturnsRawBytes(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))

	doc, err := p.GetBoletoPDF(context.Background(), "t1", pdfBoletoID)
	if err != nil {
		t.Fatalf("GetBoletoPDF: %v", err)
	}
	if !bytes.HasPrefix(doc.Content, []byte("%PDF-")) {
		t.Fatalf("content is not a PDF: %q", doc.Content)
	}
	if doc.ContentType != "application/pdf" {
		t.Fatalf("content type = %q", doc.ContentType)
	}
	if !strings.Contains(doc.Filename, pdfBoletoID) {
		t.Fatalf("filename should name the boleto, got %q", doc.Filename)
	}
	if want := "/v2/bank_slips/" + externalReferenceID(pdfBoletoID) + "/pdf"; ps.path() != want {
		t.Fatalf("path = %q, want %q", ps.path(), want)
	}
}

// The v2 contract declares the 200 with NO content type, and the legacy v1 API returned the
// document base64-encoded inside JSON. Both are accepted: what identifies a PDF is its own
// signature, not a header the bank may not set.
func TestGetBoletoPDFAcceptsBase64Envelope(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	raw := []byte("%PDF-1.4\n% enveloped\n%%EOF\n")
	ps.boletoPDF = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"base64_pdf_file":"` + base64.StdEncoding.EncodeToString(raw) + `"}`))
	}
	p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))

	doc, err := p.GetBoletoPDF(context.Background(), "t1", pdfBoletoID)
	if err != nil {
		t.Fatalf("GetBoletoPDF: %v", err)
	}
	if !bytes.Equal(doc.Content, raw) {
		t.Fatalf("decoded content mismatch: %q", doc.Content)
	}
	if doc.ContentType != "application/pdf" {
		t.Fatalf("an unwrapped document must still be served as a PDF, got %q", doc.ContentType)
	}
}

// Anything that is not a PDF — an HTML error page, a JSON body with no document — must be
// refused rather than handed back labelled application/pdf.
func TestGetBoletoPDFRejectsNonPDF(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, body, ctype string
	}{
		{"html error page", "<html>upstream error</html>", "text/html"},
		{"json without a document", `{"message":"nope"}`, "application/json"},
		{"base64 of something else", `{"base64_pdf_file":"` + base64.StdEncoding.EncodeToString([]byte("not a pdf")) + `"}`, "application/json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ps := newProductServer(t)
			ps.boletoPDF = func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.ctype)
				_, _ = w.Write([]byte(tc.body))
			}
			p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))

			if _, err := p.GetBoletoPDF(context.Background(), "t1", pdfBoletoID); err == nil {
				t.Fatal("a non-PDF response must be an error, not a document")
			}
		})
	}
}

// A document that reaches the size ceiling is an ERROR, not a truncated success. A clipped
// JSON body fails to parse and is caught; a clipped PDF is a plausible-looking file that no
// longer opens, so the two cannot be treated the same way.
func TestGetBoletoPDFRejectsOversizeInsteadOfTruncating(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	ps.boletoPDF = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/pdf")
		_, _ = w.Write(append([]byte("%PDF-1.4\n"), bytes.Repeat([]byte("A"), maxDocumentBytes)...))
	}
	p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))

	_, err := p.GetBoletoPDF(context.Background(), "t1", pdfBoletoID)
	if err == nil {
		t.Fatal("an oversize document must fail rather than come back truncated")
	}
	if !errors.Is(err, shared.ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}

// A 404 from the bank stays a not-found, so the boundary can answer 404 without leaking
// whether the id exists under another tenant.
func TestGetBoletoPDFNotFound(t *testing.T) {
	t.Parallel()
	ps := newProductServer(t)
	ps.boletoPDF = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}
	p := ps.provider(t, oneTenant("t1", "client-1", "secret-1"))

	if _, err := p.GetBoletoPDF(context.Background(), "t1", pdfBoletoID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}
