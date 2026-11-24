// Package adn is the transport adapter for the ADN / NFS-e Nacional REST API.
// It implements nfse.Transmitter: it presents the tenant's custodied
// certificate for mTLS client authentication (via custody.FiscalSigner), POSTs
// the signed DPS as JSON, and parses the response into a nfse.Receipt or a
// typed nfse error. It never treats a non-JSON 200 as success — the DASN "200
// OK com HTML de erro" regression on master is the reason business rejections
// are surfaced as *nfse.BusinessError, not swallowed.
package adn

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/nfse"
	"github.com/ia-dev-sindireceita/payment/internal/nfse/custody"
)

// defaultTimeout bounds a single ADN transmission. The ADN emits synchronously,
// so a request that hangs past this is a transport failure.
const defaultTimeout = 30 * time.Second

// Client is the ADN REST transport. Construct it with NewClient; it is safe for
// concurrent use.
type Client struct {
	baseURL   string
	danfseURL string
	signer    custody.FiscalSigner
	http      *http.Client
	timeout   time.Duration
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient overrides the underlying *http.Client. When set, the caller
// owns the TLS config; NewClient will not build its own mTLS transport. Used by
// tests to point at an httptest TLS server.
func WithHTTPClient(c *http.Client) Option {
	return func(cl *Client) { cl.http = c }
}

// WithTimeout overrides the per-request timeout. It applies whether or not
// WithHTTPClient is used and regardless of option order: the value is recorded
// and applied to the default client at construction, and also propagated to an
// already-injected client here so an explicit WithHTTPClient still honours it.
func WithTimeout(d time.Duration) Option {
	return func(cl *Client) {
		cl.timeout = d
		if cl.http != nil {
			cl.http.Timeout = d
		}
	}
}

// WithDANFSeURL sets the base URL of the ADN service that renders the DANFSe
// (GET {base}/danfse/{chaveAcesso}), e.g.
// "https://adn.producaorestrita.nfse.gov.br" in produção restrita. Without it
// GetDANFSe reports nfse.ErrDANFSeUnavailable.
func WithDANFSeURL(u string) Option {
	return func(cl *Client) { cl.danfseURL = strings.TrimRight(u, "/") }
}

// NewClient builds an ADN client for baseURL (e.g. the homologation base
// "https://sefin.producaorestrita.nfse.gov.br/SefinNacional"). signer supplies the mTLS client
// certificate per tenant via GetClientCertificate — the private key stays
// inside the custody adapter; the TLS stack only ever holds a delegating
// crypto.Signer.
func NewClient(baseURL string, signer custody.FiscalSigner, opts ...Option) *Client {
	c := &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		signer:  signer,
		timeout: defaultTimeout,
	}
	for _, o := range opts {
		o(c)
	}
	if c.http == nil {
		c.http = &http.Client{Timeout: c.timeout}
	}
	return c
}

// mtlsTransport builds an *http.Client whose TLS handshake presents companyID's
// custodied certificate. It is used when the caller did not inject an
// http.Client. GetClientCertificate is per-handshake so a long-lived Client can
// serve many tenants without rebuilding transports.
func (c *Client) mtlsTransport(ctx context.Context, companyID string) *http.Client {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// The Sefin Nacional front end asks for the client certificate in a
		// server-initiated TLS 1.2 renegotiation after the request is sent;
		// Go refuses renegotiation by default ("tls: no renegotiation").
		Renegotiation: tls.RenegotiateOnceAsClient,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert, err := c.signer.ClientCertificate(ctx, companyID)
			if err != nil {
				return nil, err
			}
			return &cert, nil
		},
	}
	return &http.Client{
		Timeout:   c.http.Timeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
}

// adnRequest is the JSON envelope POSTed to the ADN. The ADN expects the DPS
// XML gzipped+base64; this MVP sends base64 of the raw XML under an explicit
// field name and marks the encoding so the (homologation) server can branch.
// The gzip step is a one-line change here when the real endpoint requires it.
type adnRequest struct {
	DPSXMLGZipB64 string `json:"dpsXmlGZipB64"`
}

// adnResponse covers both envelopes of POST /nfse in the Sefin Nacional
// OpenAPI (SefinNacional/swagger/docs/v1): NFSePostResponseSucesso (201:
// chaveAcesso, idDps, nfseXmlGZipB64) and NFSePostResponseErro (erros[]). Some
// failures use ResponseErro, with a single erro object instead of the array.
// The NFS-e number is not a response field — it lives in the NFS-e XML.
type adnResponse struct {
	ChaveAcesso    string        `json:"chaveAcesso"`
	IDDps          string        `json:"idDps"`
	NFSeXMLGZipB64 string        `json:"nfseXmlGZipB64"`
	Erros          []adnMensagem `json:"erros"`
	Erro           *adnMensagem  `json:"erro"`
}

// adnMensagem is MensagemProcessamento.
type adnMensagem struct {
	Codigo      string `json:"codigo"`
	Descricao   string `json:"descricao"`
	Complemento string `json:"complemento"`
}

func (r adnResponse) businessItems() []nfse.BusinessErrorItem {
	msgs := r.Erros
	if r.Erro != nil {
		msgs = append(msgs, *r.Erro)
	}
	items := make([]nfse.BusinessErrorItem, 0, len(msgs))
	for _, m := range msgs {
		msg := m.Descricao
		if m.Complemento != "" {
			msg += " — " + m.Complemento
		}
		items = append(items, nfse.BusinessErrorItem{Code: m.Codigo, Message: msg})
	}
	return items
}

// Transmit POSTs the signed DPS to the ADN over mTLS and parses the response.
// It satisfies nfse.Transmitter. Error mapping:
//   - non-2xx with a JSON error envelope → *nfse.BusinessError
//   - 2xx with an "erros" array → *nfse.BusinessError (never a silent success)
//   - 2xx that is not JSON (e.g. an HTML error page) → *nfse.TransportError
//   - connection/TLS/read failure → *nfse.TransportError
func (c *Client) Transmit(ctx context.Context, companyID string, signedDPS []byte) (nfse.Receipt, error) {
	httpClient := c.http
	// When no client was injected, build a per-tenant mTLS transport.
	if httpClient.Transport == nil {
		httpClient = c.mtlsTransport(ctx, companyID)
	}

	gz, err := gzipBytes(signedDPS)
	if err != nil {
		return nfse.Receipt{}, &nfse.TransportError{Op: "gzip", Err: err}
	}
	body, err := json.Marshal(adnRequest{DPSXMLGZipB64: base64.StdEncoding.EncodeToString(gz)})
	if err != nil {
		return nfse.Receipt{}, &nfse.TransportError{Op: "marshal", Err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/nfse", bytes.NewReader(body))
	if err != nil {
		return nfse.Receipt{}, &nfse.TransportError{Op: "build_request", Err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nfse.Receipt{}, &nfse.TransportError{Op: "do", Err: err}
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nfse.Receipt{}, &nfse.TransportError{Op: "read", Err: err}
	}

	// Guard the DASN lesson: a success status with a non-JSON body (HTML error
	// page, gateway notice) is a transport failure, not an authorised NFS-e.
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "json") {
		return nfse.Receipt{}, &nfse.TransportError{
			Op:  "content_type",
			Err: fmt.Errorf("expected JSON, got %q (status %d)", ct, resp.StatusCode),
		}
	}

	var parsed adnResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nfse.Receipt{}, &nfse.TransportError{Op: "unmarshal", Err: err}
	}

	items := parsed.businessItems()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nfse.Receipt{}, &nfse.BusinessError{HTTPStatus: resp.StatusCode, Items: normalizeErrors(items)}
	}
	if len(items) > 0 {
		return nfse.Receipt{}, &nfse.BusinessError{HTTPStatus: resp.StatusCode, Items: items}
	}
	if parsed.ChaveAcesso == "" {
		// A 2xx JSON with neither a chave nor an erros array is unusable — fail
		// closed rather than persist an authorised record with no access key.
		return nfse.Receipt{}, &nfse.TransportError{Op: "empty_receipt", Err: fmt.Errorf("2xx response carried no chaveAcesso")}
	}

	nfseXML, err := gunzipB64(parsed.NFSeXMLGZipB64)
	if err != nil {
		// The NFS-e exists (it has a chave); keep the receipt rather than
		// failing an authorised emission over its XML copy.
		nfseXML = nil
	}
	return nfse.Receipt{
		ChaveAcesso: parsed.ChaveAcesso,
		NFSeNumber:  nfseNumberFromXML(nfseXML),
		XML:         nfseXML,
	}, nil
}

// maxDANFSeBytes bounds the PDF read from the ADN.
const maxDANFSeBytes = 10 << 20

// GetDANFSe downloads the official DANFSe (PDF) of an authorised NFS-e from the
// ADN, authenticating with companyID's custodied certificate (mTLS). A 404 (or
// no endpoint configured) is nfse.ErrDANFSeUnavailable; any other non-200, an
// oversized body or a body that is not a PDF is a *nfse.TransportError.
func (c *Client) GetDANFSe(ctx context.Context, companyID, chaveAcesso string) ([]byte, error) {
	if c.danfseURL == "" {
		return nil, nfse.ErrDANFSeUnavailable
	}
	if !chaveRe.MatchString(chaveAcesso) {
		return nil, nfse.ErrDANFSeUnavailable
	}
	httpClient := c.http
	if httpClient.Transport == nil {
		httpClient = c.mtlsTransport(ctx, companyID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.danfseURL+"/danfse/"+chaveAcesso, nil)
	if err != nil {
		return nil, &nfse.TransportError{Op: "build_request", Err: err}
	}
	req.Header.Set("Accept", "application/pdf")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, &nfse.TransportError{Op: "do", Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nfse.ErrDANFSeUnavailable
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &nfse.TransportError{Op: "danfse_status", Err: fmt.Errorf("status %d", resp.StatusCode)}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxDANFSeBytes+1))
	if err != nil {
		return nil, &nfse.TransportError{Op: "read", Err: err}
	}
	if len(raw) > maxDANFSeBytes {
		return nil, &nfse.TransportError{Op: "danfse_size", Err: fmt.Errorf("DANFSe larger than %d bytes", maxDANFSeBytes)}
	}
	if !bytes.HasPrefix(raw, []byte("%PDF-")) {
		return nil, &nfse.TransportError{Op: "danfse_content", Err: fmt.Errorf("body is not a PDF (status %d)", resp.StatusCode)}
	}
	return raw, nil
}

// chaveRe is the NFS-e access key: 50 digits.
var chaveRe = regexp.MustCompile(`^[0-9]{50}$`)

func gzipBytes(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func gunzipB64(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(io.LimitReader(zr, 8<<20))
}

// nfseNumberFromXML reads infNFSe/nNFSe from the authorised NFS-e XML.
func nfseNumberFromXML(x []byte) string {
	if len(x) == 0 {
		return ""
	}
	var doc struct {
		Inf struct {
			Num string `xml:"nNFSe"`
		} `xml:"infNFSe"`
	}
	if err := xml.Unmarshal(x, &doc); err != nil {
		return ""
	}
	return doc.Inf.Num
}

// normalizeErrors guarantees a non-empty item slice so a *BusinessError from a
// bare non-2xx always carries at least the HTTP status as context.
func normalizeErrors(items []nfse.BusinessErrorItem) []nfse.BusinessErrorItem {
	if len(items) > 0 {
		return items
	}
	return []nfse.BusinessErrorItem{{Code: "http", Message: "ADN returned a non-2xx status with no error detail"}}
}
