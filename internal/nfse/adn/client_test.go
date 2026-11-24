package adn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/nfse"
	"github.com/ia-dev-sindireceita/payment/internal/nfse/custody"
)

// throwawayClientCert mints an ephemeral self-signed cert+key to present for
// mTLS in the transport-parsing tests. The custody LocalTestSigner's delegating
// signer intentionally refuses the TLS CertificateVerify signing scheme (that
// broader scheme negotiation is GA / KMS-adapter scope per ADR-0008), so a real
// handshake here uses a throwaway key. The production wiring — that the client
// pulls its cert from FiscalSigner.ClientCertificate — is proven separately by
// TestMTLSTransportPresentsCustodiedCert.
func throwawayClientCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// newMTLSClient builds a *Client whose HTTP client presents a client
// certificate for mTLS against ts and trusts ts's server cert.
func newMTLSClient(t *testing.T, ts *httptest.Server, signer custody.FiscalSigner, companyID string) *Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	clientCert := throwawayClientCert(t)
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: pool,
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return &clientCert, nil
				},
			},
		},
	}
	return NewClient(ts.URL, signer, WithHTTPClient(httpClient), WithTimeout(10*time.Second))
}

// provisionSigner returns a LocalTestSigner holding a cert for companyID.
func provisionSigner(t *testing.T, companyID string) *custody.LocalTestSigner {
	t.Helper()
	s := custody.NewLocalTestSigner()
	if _, _, err := s.Provision(companyID, "47064135000184", time.Hour); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	return s
}

// startADN starts a TLS server that requires (but does not verify a CA for) a
// client certificate — proving the mTLS handshake presents the custodied cert —
// and invokes handler for the request.
func startADN(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(handler)
	ts.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

// TestWithTimeoutAppliesToDefaultClient pins the SIN-67535 minor fix: WithTimeout
// must take effect even without WithHTTPClient and regardless of option order.
// Previously the option ran before NewClient built the default client, so it was
// a silent no-op and the mTLS transport always used defaultTimeout.
func TestWithTimeoutAppliesToDefaultClient(t *testing.T) {
	signer := provisionSigner(t, "tenant-A")

	// No injected client — the option must still be honoured.
	c := NewClient("https://adn.example", signer, WithTimeout(3*time.Second))
	if c.http.Timeout != 3*time.Second {
		t.Errorf("default client timeout = %v, want 3s", c.http.Timeout)
	}
	// The per-tenant mTLS transport inherits it.
	hc := c.mtlsTransport(context.Background(), "tenant-A")
	if hc.Timeout != 3*time.Second {
		t.Errorf("mtls transport timeout = %v, want 3s", hc.Timeout)
	}

	// Unset — falls back to the default.
	d := NewClient("https://adn.example", signer)
	if d.http.Timeout != defaultTimeout {
		t.Errorf("default timeout = %v, want %v", d.http.Timeout, defaultTimeout)
	}
}

// TestTransmitSuccess pins the Sefin Nacional contract (OpenAPI
// SefinNacional/swagger/docs/v1): POST /nfse with the DPS gzipped in
// dpsXmlGZipB64; 201 with chaveAcesso, idDps and the NFS-e gzipped in
// nfseXmlGZipB64, whose infNFSe/nNFSe is the NFS-e number.
func TestTransmitSuccess(t *testing.T) {
	const nfseXML = `<NFSe xmlns="http://www.sped.fazenda.gov.br/nfse"><infNFSe Id="NFS1"><nNFSe>1001</nNFSe></infNFSe></NFSe>`
	var gotClientCert bool
	var gotBody []byte
	var gotPath string
	ts := startADN(t, func(w http.ResponseWriter, r *http.Request) {
		gotClientCert = len(r.TLS.PeerCertificates) > 0
		gotPath = r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"chaveAcesso":    "35260647064135000184550010000010011234567890",
			"idDps":          "DPS355030824706413500018400001000000000000042",
			"nfseXmlGZipB64": gzipB64(t, nfseXML),
		})
	})
	signer := provisionSigner(t, "tenant-A")
	c := newMTLSClient(t, ts, signer, "tenant-A")

	rec, err := c.Transmit(context.Background(), "tenant-A", []byte("<DPS/>"))
	if err != nil {
		t.Fatalf("Transmit: %v", err)
	}
	if !gotClientCert {
		t.Error("server did not receive a client certificate (mTLS not presented)")
	}
	if gotPath != "/nfse" {
		t.Errorf("path = %q, want /nfse", gotPath)
	}
	if rec.ChaveAcesso == "" || rec.NFSeNumber != "1001" {
		t.Errorf("receipt not parsed: %+v", rec)
	}
	if string(rec.XML) != nfseXML {
		t.Errorf("nfse xml = %q", rec.XML)
	}
	// The request body must carry the gzipped, base64 signed DPS.
	var req map[string]string
	if err := json.Unmarshal(gotBody, &req); err != nil {
		t.Fatalf("server got non-JSON body: %v", err)
	}
	if dec := gunzipB64Test(t, req["dpsXmlGZipB64"]); dec != "<DPS/>" {
		t.Errorf("dps not transmitted gzipped in dpsXmlGZipB64: %q (body %s)", dec, gotBody)
	}
}

// TestTransmitSingleErroEnvelope: ResponseErro carries one "erro" object, and
// the complemento (where the Sefin puts the schema detail) reaches the message.
func TestTransmitSingleErroEnvelope(t *testing.T) {
	ts := startADN(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"erro": map[string]string{"codigo": "E1235", "descricao": "Falha no esquema XML do DF-e.", "complemento": "The 'Id' attribute is invalid"},
		})
	})
	signer := provisionSigner(t, "tenant-A")
	c := newMTLSClient(t, ts, signer, "tenant-A")
	_, err := c.Transmit(context.Background(), "tenant-A", []byte("<DPS/>"))
	be, ok := nfse.AsBusinessError(err)
	if !ok || len(be.Items) != 1 || be.Items[0].Code != "E1235" || !strings.Contains(be.Items[0].Message, "Id' attribute") {
		t.Fatalf("err = %v, want E1235 with complemento", err)
	}
}

// TestMTLSTransportAllowsRenegotiation: the Sefin front end requests the client
// certificate through a server-initiated TLS 1.2 renegotiation; without this
// every emission fails with "tls: no renegotiation".
func TestMTLSTransportAllowsRenegotiation(t *testing.T) {
	c := NewClient("https://sefin.example", provisionSigner(t, "tenant-A"))
	tr, ok := c.mtlsTransport(context.Background(), "tenant-A").Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil {
		t.Fatal("mTLS transport has no TLS config")
	}
	if tr.TLSClientConfig.Renegotiation != tls.RenegotiateOnceAsClient {
		t.Errorf("Renegotiation = %v, want RenegotiateOnceAsClient", tr.TLSClientConfig.Renegotiation)
	}
}

func gzipB64(t *testing.T, s string) string {
	t.Helper()
	gz, err := gzipBytes([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(gz)
}

func gunzipB64Test(t *testing.T, s string) string {
	t.Helper()
	b, err := gunzipB64(s)
	if err != nil {
		t.Fatalf("not gzip+base64: %v", err)
	}
	return string(b)
}

func TestTransmitBusinessErrorNon2xx(t *testing.T) {
	ts := startADN(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"erros": []map[string]string{{"codigo": "E101", "descricao": "DPS duplicada"}},
		})
	})
	signer := provisionSigner(t, "tenant-A")
	c := newMTLSClient(t, ts, signer, "tenant-A")

	_, err := c.Transmit(context.Background(), "tenant-A", []byte("<DPS/>"))
	be, ok := nfse.AsBusinessError(err)
	if !ok {
		t.Fatalf("err = %v, want BusinessError", err)
	}
	if be.HTTPStatus != 422 || len(be.Items) != 1 || be.Items[0].Code != "E101" {
		t.Errorf("business error = %+v", be)
	}
}

func TestTransmit2xxWithErrosIsBusinessError(t *testing.T) {
	// The DASN lesson: a 200 that carries an error envelope must NOT be a
	// silent success.
	ts := startADN(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"erros": []map[string]string{{"codigo": "E200", "descricao": "IM inválida"}},
		})
	})
	signer := provisionSigner(t, "tenant-A")
	c := newMTLSClient(t, ts, signer, "tenant-A")
	_, err := c.Transmit(context.Background(), "tenant-A", []byte("<DPS/>"))
	if be, ok := nfse.AsBusinessError(err); !ok || be.Items[0].Code != "E200" {
		t.Fatalf("err = %v, want business error E200", err)
	}
}

func TestTransmitNonJSON200IsTransportError(t *testing.T) {
	ts := startADN(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>Bad Gateway</html>"))
	})
	signer := provisionSigner(t, "tenant-A")
	c := newMTLSClient(t, ts, signer, "tenant-A")
	_, err := c.Transmit(context.Background(), "tenant-A", []byte("<DPS/>"))
	var te *nfse.TransportError
	if !errors.As(err, &te) {
		t.Fatalf("err = %v, want TransportError", err)
	}
}

func TestTransmit2xxEmptyReceiptIsTransportError(t *testing.T) {
	ts := startADN(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})
	signer := provisionSigner(t, "tenant-A")
	c := newMTLSClient(t, ts, signer, "tenant-A")
	_, err := c.Transmit(context.Background(), "tenant-A", []byte("<DPS/>"))
	var te *nfse.TransportError
	if !errors.As(err, &te) {
		t.Fatalf("err = %v, want TransportError for empty receipt", err)
	}
}

func TestTransmitConnectionErrorIsTransportError(t *testing.T) {
	signer := provisionSigner(t, "tenant-A")
	// Point at a closed port; the Do() will fail.
	c := NewClient("https://127.0.0.1:1", signer, WithHTTPClient(&http.Client{
		Timeout:   time.Second,
		Transport: &http.Transport{},
	}))
	_, err := c.Transmit(context.Background(), "tenant-A", []byte("<DPS/>"))
	var te *nfse.TransportError
	if !errors.As(err, &te) {
		t.Fatalf("err = %v, want TransportError", err)
	}
}

// TestMTLSTransportPresentsCustodiedCert exercises the default-transport path:
// the client builds its own mTLS *http.Client from the signer, whose
// GetClientCertificate returns the custodied certificate. White-box so it does
// not depend on TLS trust of the httptest server.
func TestMTLSTransportPresentsCustodiedCert(t *testing.T) {
	signer := provisionSigner(t, "tenant-A")
	c := NewClient("https://adn.example", signer)
	hc := c.mtlsTransport(context.Background(), "tenant-A")
	tr, ok := hc.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil || tr.TLSClientConfig.GetClientCertificate == nil {
		t.Fatalf("mtlsTransport did not wire GetClientCertificate")
	}
	cert, err := tr.TLSClientConfig.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		t.Fatalf("custodied cert not returned: %+v", cert)
	}

	// An unprovisioned tenant fails closed through the same callback.
	hc2 := c.mtlsTransport(context.Background(), "tenant-unknown")
	tr2 := hc2.Transport.(*http.Transport)
	if _, err := tr2.TLSClientConfig.GetClientCertificate(&tls.CertificateRequestInfo{}); err == nil {
		t.Error("unprovisioned tenant should fail to produce a client cert")
	}
}

const testChave = "35260647064135000184550010000010011234567890123456"

func TestGetDANFSe(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		chave   string
		noURL   bool
		wantErr error
		wantTE  bool
	}{
		{name: "ok", status: 200, body: "%PDF-1.7 fake", chave: testChave},
		{name: "not found", status: 404, chave: testChave, wantErr: nfse.ErrDANFSeUnavailable},
		{name: "server error", status: 500, chave: testChave, wantTE: true},
		{name: "not a pdf", status: 200, body: "<html>erro</html>", chave: testChave, wantTE: true},
		{name: "bad chave", chave: "123", wantErr: nfse.ErrDANFSeUnavailable},
		{name: "no url", chave: testChave, noURL: true, wantErr: nfse.ErrDANFSeUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotPath, gotAccept string
			var gotCert bool
			ts := startADN(t, func(w http.ResponseWriter, r *http.Request) {
				gotPath, gotAccept = r.URL.Path, r.Header.Get("Accept")
				gotCert = len(r.TLS.PeerCertificates) > 0
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			})
			signer := provisionSigner(t, "tenant-A")
			c := newMTLSClient(t, ts, signer, "tenant-A")
			if !tc.noURL {
				WithDANFSeURL(ts.URL + "/")(c)
			}
			pdf, err := c.GetDANFSe(context.Background(), "tenant-A", tc.chave)
			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
			case tc.wantTE:
				var te *nfse.TransportError
				if !errors.As(err, &te) {
					t.Fatalf("err = %v, want TransportError", err)
				}
			default:
				if err != nil || string(pdf) != tc.body {
					t.Fatalf("pdf=%q err=%v", pdf, err)
				}
				if gotPath != "/danfse/"+testChave || gotAccept != "application/pdf" || !gotCert {
					t.Errorf("path=%q accept=%q cert=%v", gotPath, gotAccept, gotCert)
				}
			}
		})
	}
}
