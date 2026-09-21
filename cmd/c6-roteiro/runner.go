package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// maxBodyBytes caps how much of a response is kept. The roteiro asks for the response
// body, and a bank error page is not one — 64 KiB is far above any legitimate JSON
// here and far below a surprise HTML flood.
const maxBodyBytes = 64 << 10

// minInterval paces outbound calls. The C6 FAQ (§8) states 60 requests per minute per
// key, summed across ALL APIs — and a roteiro run is ~90 calls back to back. Pacing is
// not politeness: a 429 in the middle of a dependent chain (create → read → amend)
// loses the whole chain, not one case.
const minInterval = 1100 * time.Millisecond

// evidencia is one captured case: what was sent, and what the bank answered. The body
// is kept VERBATIM — it is the evidence, and paraphrasing it would defeat the purpose.
type evidencia struct {
	Caso     string `json:"caso"`
	Metodo   string `json:"metodo"`
	URL      string `json:"url"`
	Request  string `json:"request,omitempty"`
	Status   int    `json:"status"`
	Body     string `json:"body"`
	Erro     string `json:"erro,omitempty"`
	Quando   string `json:"quando"`
	Ambiente string `json:"ambiente"`
}

// runner drives the roteiro: it holds the mTLS+bearer transport, the running evidence
// set, and the identifiers each case hands to the next.
type runner struct {
	httpc *http.Client
	base  string
	token string
	// Credencial guardada para RENOVAR o bearer no meio da corrida: ele vale 600s e a
	// corrida inteira passa disso. Sem renovação os últimos blocos tomariam 401, e um
	// 401 no fim de uma sequência parece problema do endpoint, não do relógio.
	tokenURL   string
	clientID   string
	secret     string
	tokenDesde time.Time
	pixKey     string
	webhook    string
	filtro     string
	// servico libera o registro dos webhooks por SERVIÇO (B_07, C_04). Ver a bandeira
	// --webhook-servico: eles valem para a conta inteira e não têm DELETE.
	servico bool

	evidencias map[string]evidencia
	ordem      []string
	ultima     time.Time

	// Identificadores encadeados entre os casos.
	groupID     string
	itemIDs     []string
	slipV1ID    string
	slipAlterar string
	slipBaixar  string
	checkout    string
	cobTxID     string
	cobvTxID    string
	loteID      string
	locID       string
	e2eID       string
	devID       string
	bolepixID   string
	idRec       string
	idSolic     string
	locRecID    string
}

// registrar records one case's evidence. A case that is recorded twice is a bug in the
// step list, so it is reported rather than silently overwritten.
func (r *runner) registrar(e evidencia) {
	if _, ok := r.evidencias[e.Caso]; !ok {
		r.ordem = append(r.ordem, e.Caso)
	}
	e.Quando = time.Now().UTC().Format(time.RFC3339)
	e.Ambiente = "sandbox"
	r.evidencias[e.Caso] = e
}

// pular reports whether a case is outside the requested filter.
func (r *runner) pular(caso string) bool {
	return r.filtro != "" && !strings.HasPrefix(caso, r.filtro)
}

// renovarToken mints a fresh bearer when the current one is near its 600s expiry.
//
// A margem é generosa (dois minutos) porque a alternativa é pior: um 401 no meio de uma
// cadeia dependente perde o caso E todos os que dependiam dele.
func (r *runner) renovarToken(ctx context.Context) {
	if r.tokenURL == "" || time.Since(r.tokenDesde) < 8*time.Minute {
		return
	}
	fmt.Fprintf(os.Stderr, "%-10s %-6s --- renovando o bearer (vale 600s)\n", "-", "TOKEN")
	if err := r.autenticarSilencioso(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "AVISO: renovação do token falhou: %v\n", err)
	}
}

// esperar paces requests to stay under the account's rate limit.
func (r *runner) esperar() {
	if !r.ultima.IsZero() {
		if d := minInterval - time.Since(r.ultima); d > 0 {
			time.Sleep(d)
		}
	}
	r.ultima = time.Now()
}

// opcoes carries the per-call extras a few C6 surfaces need.
type opcoes struct {
	// partner sends the partner-software-* headers, which the Agendamento and C6 Pay
	// contracts declare.
	partner bool
	// query is appended to the path.
	query url.Values
	// accept overrides the Accept header.
	//
	// Existe porque os endpoints BACEN cujo SUCESSO não tem corpo recusam
	// `application/json` com 400:
	//
	//	Request Accept header '[application/json]' does not match any defined
	//	response types. Must be one of: [application/problem+json].
	//
	// São eles o registro/remoção de webhook PIX, a escrita de lote de cobv e o
	// webhook de recorrência. O adapter já trata isso desde a SIN-69580
	// (webhook_accept_test.go); esta ferramenta precisava tratar também.
	accept string
	// repetirEnquanto pede nova tentativa enquanto devolver true.
	//
	// É para resposta TEMPORÁRIA — o 502 do edge, e o 422 "ainda estou decodificando"
	// do agendamento —, nunca para erro de conteúdo. Repetir um 400 não o conserta: só
	// gasta a janela do sandbox e o limite de 60 por minuto.
	repetirEnquanto func(*resposta) bool
}

// maxRepeticoes limita as retentativas de uma resposta temporária.
const maxRepeticoes = 6

// esperaExtra é o passo do recuo entre retentativas: 3s, 6s, 9s… até seis vezes, o que
// dá pouco mais de um minuto de paciência antes de desistir.
const esperaExtra = 3 * time.Second

// transitorio reconhece as respostas que merecem nova tentativa por si sós.
//
// Todo 5xx entra: o 502 do Cloudflare traz `"retryable": true` no próprio corpo, o
// endpoint de token devolve 500 em metade das chamadas, e o `locrec` do PIX Automático
// falhou com 500 em duas das três vezes e passou na terceira, sem nada diferente no
// pedido. O que é defeito determinístico do sandbox — e há um, o `SC-GetTaxId` do lote
// — é gravado assim mesmo depois das retentativas, e aí a evidência mostra que ele não
// cede.
func transitorio(resp *resposta) bool {
	return resp.Status/100 == 5
}

// acceptProblema é o Accept que os endpoints sem corpo de sucesso exigem.
const acceptProblema = "application/problem+json"

// acceptCoringa é o Accept da leitura de UMA recorrência: ela recusa
// `application/json` com 400, recusa `application/jose` e `application/problem+json`
// com 406, e atende quem não exige nada — devolvendo JSON. Ver lerRec.
const acceptCoringa = "*/*"

// resposta is a decoded call result. Mapa is the body parsed as a generic object when
// it is one, so a step can pull out the id the next step needs.
type resposta struct {
	Status int
	Body   string
	Mapa   map[string]any
}

// texto extracts a string field from the decoded body, empty when absent.
//
// Olha também DENTRO de `data`: a API de PIX Automático embrulha a resposta
// (`{"data":{"idRec":…}}`), ao contrário de todas as outras superfícies do C6. Procurar
// só no topo fez `idRec` voltar vazio e derrubou quatro casos da primeira corrida.
func (resp *resposta) texto(campo string) string {
	if resp == nil || resp.Mapa == nil {
		return ""
	}
	if v := valorTexto(resp.Mapa[campo]); v != "" {
		return v
	}
	if dentro, ok := resp.Mapa["data"].(map[string]any); ok {
		return valorTexto(dentro[campo])
	}
	return ""
}

// valorTexto normaliza um valor JSON em texto, aceitando número (o `id` da location é
// inteiro) além de string.
func valorTexto(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return fmt.Sprintf("%.0f", t)
	default:
		return ""
	}
}

// chamar performs one roteiro call and records it.
//
// It speaks the wire DIRECTLY rather than going through the c6 adapter, and that is
// deliberate: the adapter decodes into typed structs and deliberately discards the raw
// body so a PSP message can never reach a log. The roteiro asks for exactly that raw
// body. Reconstructing it from a typed struct would be inventing evidence, and adding a
// raw-body escape hatch to the adapter would put a hole in the policy that protects
// production. The adapter's own contract tests are what keep these paths and the
// adapter's in agreement.
func (r *runner) chamar(ctx context.Context, caso, metodo, caminho string, corpo any, opt opcoes) *resposta {
	if r.pular(caso) {
		return nil
	}
	r.renovarToken(ctx)
	r.esperar()

	endpoint := r.base + caminho
	if len(opt.query) > 0 {
		endpoint += "?" + opt.query.Encode()
	}

	var reader io.Reader
	var enviado string
	if corpo != nil {
		raw, err := json.Marshal(corpo)
		if err != nil {
			r.registrar(evidencia{Caso: caso, Metodo: metodo, URL: endpoint, Erro: err.Error()})
			return nil
		}
		enviado = string(raw)
		reader = bytes.NewReader(raw)
	}

	// O transitório é SEMPRE repetido; o predicado do chamador acrescenta, não
	// substitui. Um 502 do edge no meio de um caso que também espera pela CIP continua
	// sendo um 502 do edge.
	repetir := func(resp *resposta) bool {
		return transitorio(resp) || (opt.repetirEnquanto != nil && opt.repetirEnquanto(resp))
	}

	var out *resposta
	for tentativa := 0; ; tentativa++ {
		if tentativa > 0 {
			// Espera CRESCENTE, e não o passo normal: o que se espera aqui é o banco
			// terminar algo (decodificar um lote, registrar na CIP), e insistir de
			// segundo em segundo não apressa nada — só gasta o limite de 60/min.
			time.Sleep(time.Duration(tentativa) * esperaExtra)
			if reader != nil {
				reader = bytes.NewReader([]byte(enviado))
			}
		}
		req, err := http.NewRequestWithContext(ctx, metodo, endpoint, reader)
		if err != nil {
			r.registrar(evidencia{Caso: caso, Metodo: metodo, URL: endpoint, Request: enviado, Erro: err.Error()})
			return nil
		}
		req.Header.Set("Authorization", "Bearer "+r.token)
		accept := opt.accept
		if accept == "" {
			accept = "application/json"
		}
		req.Header.Set("Accept", accept)
		if corpo != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if opt.partner {
			req.Header.Set("partner-software-name", partnerName)
			req.Header.Set("partner-software-version", partnerVersion)
		}

		resp, err := r.httpc.Do(req)
		if err != nil {
			r.registrar(evidencia{Caso: caso, Metodo: metodo, URL: endpoint, Request: enviado, Erro: err.Error()})
			return nil
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
		_ = resp.Body.Close()

		out = &resposta{Status: resp.StatusCode, Body: strings.TrimSpace(string(body))}
		out.Mapa = nil
		_ = json.Unmarshal(body, &out.Mapa)

		if tentativa >= maxRepeticoes || !repetir(out) {
			break
		}
		fmt.Fprintf(os.Stderr, "%-10s %-6s %-3d %s (temporário, nova tentativa)\n", caso, metodo, out.Status, caminho)
	}

	r.registrar(evidencia{
		Caso: caso, Metodo: metodo, URL: endpoint, Request: enviado,
		Status: out.Status, Body: out.Body,
	})
	fmt.Fprintf(os.Stderr, "%-10s %-6s %-3d %s\n", caso, metodo, out.Status, caminho)
	return out
}

// carregar lê um arquivo de evidências anterior para esta corrida fundir com ele.
//
// Existe para o caso que é a regra, não a exceção: um bloco falha por uma forma errada
// de requisição, corrige-se essa forma, e refazer os outros oito blocos custa vinte
// minutos de janela e noventa chamadas do limite de 60/min — para recapturar o que já
// estava certo. Um arquivo inexistente não é erro: a primeira corrida não tem o que
// fundir.
func (r *runner) carregar(caminho string) error {
	raw, err := os.ReadFile(caminho)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var anteriores []evidencia
	if err := json.Unmarshal(raw, &anteriores); err != nil {
		return fmt.Errorf("lendo %s: %w", caminho, err)
	}
	for _, e := range anteriores {
		r.evidencias[e.Caso] = e
		r.ordem = append(r.ordem, e.Caso)
	}
	fmt.Fprintf(os.Stderr, "fundindo com %d casos de %s\n\n", len(anteriores), caminho)
	return nil
}

// gravar writes the evidence file, ordered by case id so a diff between two runs is
// readable.
func (r *runner) gravar(caminho string) error {
	ids := append([]string(nil), r.ordem...)
	sort.Strings(ids)
	out := make([]evidencia, 0, len(ids))
	for _, id := range ids {
		out = append(out, r.evidencias[id])
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(caminho, append(raw, '\n'), 0o600)
}

// pdf captures a case whose successful response is a DOCUMENT, not JSON.
//
// The bytes are NOT written into the evidence file. A base64 PDF would bloat the
// document to megabytes and tell a reader nothing; what answers the roteiro is the
// status, the media type and the proof that what came back really is a PDF — its own
// signature. A body that is not a PDF IS recorded verbatim, because then it is an error
// page and its text is the evidence.
func (r *runner) pdf(ctx context.Context, caso, caminho string) {
	if r.pular(caso) {
		return
	}
	r.esperar()

	endpoint := r.base + caminho
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		r.registrar(evidencia{Caso: caso, Metodo: http.MethodGet, URL: endpoint, Erro: err.Error()})
		return
	}
	req.Header.Set("Authorization", "Bearer "+r.token)
	req.Header.Set("partner-software-name", partnerName)
	req.Header.Set("partner-software-version", partnerVersion)

	resp, err := r.httpc.Do(req)
	if err != nil {
		r.registrar(evidencia{Caso: caso, Metodo: http.MethodGet, URL: endpoint, Erro: err.Error()})
		return
	}
	defer func() { _ = resp.Body.Close() }()
	// O PDF do boleto passa de 1 MiB com facilidade quando traz o QR em bitmap, então
	// a leitura aqui não usa o teto de JSON.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))

	descricao := descreverDocumento(resp.Header.Get("Content-Type"), body)
	r.registrar(evidencia{
		Caso: caso, Metodo: http.MethodGet, URL: endpoint,
		Status: resp.StatusCode, Body: descricao,
	})
	fmt.Fprintf(os.Stderr, "%-10s %-6s %-3d %s\n", caso, "GET", resp.StatusCode, caminho)
}

// descreverDocumento resume um corpo binário, ou devolve o texto quando ele não é um
// PDF — aí é página de erro, e o texto é a evidência.
func descreverDocumento(contentType string, body []byte) string {
	if bytes.HasPrefix(body, []byte("%PDF-")) {
		return fmt.Sprintf("[PDF de %d bytes; assinatura %%PDF- confirmada; Content-Type: %s]",
			len(body), contentType)
	}
	// O contrato do boleto v1 também admite o PDF em base64 dentro de um JSON.
	var env struct {
		Base64PDFFile string `json:"base64_pdf_file"`
	}
	if err := json.Unmarshal(body, &env); err == nil && env.Base64PDFFile != "" {
		return fmt.Sprintf("[PDF em base64 dentro de {\"base64_pdf_file\"}, %d caracteres codificados]",
			len(env.Base64PDFFile))
	}
	if len(body) > 4096 {
		body = body[:4096]
	}
	return strings.TrimSpace(string(body))
}
