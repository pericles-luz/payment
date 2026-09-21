// Command c6-roteiro executes the C6 homologation script ("Roteiro de Testes - C6
// Developers v3.0") against the sandbox and records, per case, the status code and the
// response body the bank returned.
//
// It exists because the roteiro asks for the RAW response of every case, and the
// production adapter deliberately throws that away: it decodes into typed structs and
// never lets a PSP body reach a log (ADR-0008). Printing and keeping the raw body is
// the whole point here, and it is a scoped exception — this is a one-shot operator run
// whose output goes to a file the operator then hands to the bank, never to a log sink.
// Do not wire it into a service.
//
// # Regras que estão no código e não no runbook
//
//   - Valores ≤ R$ 10,00. A autoconfirmação de PIX no sandbox só dispara nessa faixa;
//     R$ 15,00 já custou um smoke ao vivo (SIN-65917).
//   - Uma chamada a cada 1,1 s. O limite é 60 por minuto por chave, somando TODAS as
//     APIs (FAQ §8), e uma corrida são ~90 chamadas encadeadas.
//   - CPF/CNPJ com dígito verificador válido. O banco recusa `12345678901` com 422.
//   - Janela do sandbox: seg–sex, 7h–23h BRT.
//
// # Uso
//
//	c6-roteiro \
//	  --cert /caminho/cliente.crt --key /caminho/cliente.key \
//	  --client-id <id> --client-secret <segredo> \
//	  --pix-key <chave-evp> \
//	  --webhook-url https://payment.lmhost.com.br/webhooks/c6/<ref> \
//	  --out evidencias.json [--only P_01]
//
// O segredo e a chave PIX podem vir do ambiente (C6_CLIENT_SECRET, C6_PIX_KEY) para não
// ficarem na linha de comando, que o histórico do shell guarda.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/adapters/bank/c6"
)

const (
	// partnerName / partnerVersion identify this software to the two C6 surfaces that
	// declare the headers. They match what the adapter and the operator probes send, so
	// the bank sees one identity.
	partnerName    = "payment-gateway"
	partnerVersion = "1.0.0"

	sandboxBase     = "https://baas-api-sandbox.c6bank.info"
	sandboxTokenURL = "https://baas-api-sandbox.c6bank.info/v1/auth/"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\nc6-roteiro: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		certPath = flag.String("cert", "", "PEM do certificado de cliente (mTLS)")
		keyPath  = flag.String("key", "", "PEM da chave privada do certificado")
		clientID = flag.String("client-id", "", "client_id da credencial C6")
		secret   = flag.String("client-secret", os.Getenv("C6_CLIENT_SECRET"), "client_secret (prefira C6_CLIENT_SECRET)")
		pixKey   = flag.String("pix-key", os.Getenv("C6_PIX_KEY"), "chave PIX do recebedor (prefira C6_PIX_KEY)")
		webhook  = flag.String("webhook-url", "", "URL HTTPS de webhook a registrar (vazio pula os casos de webhook)")
		barcode  = flag.String("boleto-barcode", "",
			"linha digitável de um boleto REAL a incluir no lote do agendamento. Vazio usa a do "+
				"boleto que B_01 emitir. Serve para refazer só o bloco AP (--only AP --merge) sem "+
				"reemitir o boleto e desencontrar a evidência de B_01 da de B_05")
		base     = flag.String("base", sandboxBase, "base da API")
		tokenURL = flag.String("token-url", sandboxTokenURL, "endpoint do token")
		out      = flag.String("out", "evidencias.json", "arquivo de saída")
		only     = flag.String("only", "", "roda só os casos com este prefixo (ex.: P_01)")
		merge    = flag.Bool("merge", false,
			"funde com o que já existe em --out, sobrescrevendo só os casos desta corrida. "+
				"Use com --only para recapturar um bloco sem refazer os outros — a janela do "+
				"sandbox é de 16 horas por dia e o limite é de 60 chamadas por minuto")
		servico = flag.Bool("webhook-servico", false,
			"também registra os webhooks POR SERVIÇO (B_07 BANK_SLIP, C_04 CHECKOUT). "+
				"DESLIGADO por padrão: diferente do webhook PIX, que é chaveado pela chave, "+
				"esses são da CONTA inteira, a superfície não expõe DELETE, e registrar "+
				"SUBSTITUI o destino que a integração existente usa naquela conta de sandbox")
		timeout = flag.Duration("timeout", 30*time.Second, "timeout por requisição")
	)
	flag.Parse()

	switch {
	case *certPath == "" || *keyPath == "":
		return fmt.Errorf("--cert e --key são obrigatórios (o C6 exige mTLS além do bearer)")
	case *clientID == "" || *secret == "":
		return fmt.Errorf("--client-id e --client-secret (ou C6_CLIENT_SECRET) são obrigatórios")
	case *pixKey == "":
		return fmt.Errorf("--pix-key (ou C6_PIX_KEY) é obrigatória: sem ela a cobrança não roteia")
	}
	if !strings.HasPrefix(*base, "https://") || !strings.HasPrefix(*tokenURL, "https://") {
		return fmt.Errorf("base e token precisam ser https")
	}
	if *webhook != "" && !strings.HasPrefix(*webhook, "https://") {
		return fmt.Errorf("--webhook-url precisa ser https")
	}
	avisarJanela()

	httpc, err := c6.MTLSHTTPClient(*certPath, *keyPath, *timeout)
	if err != nil {
		return err
	}

	ctx := context.Background()
	r := &runner{
		httpc:         httpc,
		base:          strings.TrimRight(*base, "/"),
		pixKey:        *pixKey,
		webhook:       *webhook,
		filtro:        *only,
		servico:       *servico,
		boletoBarcode: strings.TrimSpace(*barcode),
		evidencias:    map[string]evidencia{},
	}
	if *merge {
		if err := r.carregar(*out); err != nil {
			return err
		}
	}

	// AT_01 is both the first case and the prerequisite for every other one: without a
	// token nothing else can run, so a failure here stops the run instead of producing
	// sixty-nine 401s that say nothing.
	if err := r.autenticar(ctx, *tokenURL, *clientID, *secret); err != nil {
		_ = r.gravar(*out)
		return err
	}

	// BOLETO antes de AGENDAMENTO, fora da ordem do documento: o lote do agendamento
	// leva uma linha digitável, e quem a produz é B_01.
	r.rodarBoleto(ctx)
	r.rodarAgendamento(ctx)
	r.rodarCheckout(ctx)
	r.rodarExtrato(ctx)
	r.rodarPix(ctx)
	r.rodarRecebiveis(ctx)
	r.rodarPixAutomatico(ctx)
	r.rodarBolepix(ctx)
	r.finalizar(ctx)

	if err := r.gravar(*out); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\n%d casos gravados em %s\n", len(r.ordem), *out)
	r.resumir()
	return nil
}

// avisarJanela warns when the run is outside the sandbox's service hours, because the
// failures it produces look like contract problems and are not.
func avisarJanela() {
	loc, err := time.LoadLocation("America/Sao_Paulo")
	if err != nil {
		return
	}
	agora := time.Now().In(loc)
	fimDeSemana := agora.Weekday() == time.Saturday || agora.Weekday() == time.Sunday
	foraDoHorario := agora.Hour() < 7 || agora.Hour() >= 23
	if fimDeSemana || foraDoHorario {
		fmt.Fprintf(os.Stderr,
			"AVISO: a janela do sandbox é seg–sex, 7h–23h BRT, e agora são %s.\n"+
				"       O que falhar aqui provavelmente é a janela, não o contrato.\n\n",
			agora.Format("Mon 15:04"))
	}
}

// resumir prints a one-line tally so a run's outcome is readable without opening the
// file: how many cases answered 2xx, and which did not.
func (r *runner) resumir() {
	var ok int
	var ruins []string
	for _, id := range r.ordem {
		e := r.evidencias[id]
		if e.Status/100 == 2 {
			ok++
			continue
		}
		ruins = append(ruins, fmt.Sprintf("%s(%d)", id, e.Status))
	}
	fmt.Fprintf(os.Stderr, "2xx: %d/%d\n", ok, len(r.ordem))
	if len(ruins) > 0 {
		fmt.Fprintf(os.Stderr, "sem 2xx: %s\n", strings.Join(ruins, " "))
	}
}

// autenticar performs AT_01 and keeps the bearer for the rest of the run.
//
// The credential goes in the BODY (client_secret_post), which is what the published
// contract requires — see internal/adapters/bank/c6/token.go.
//
// It retries on 5xx because the sandbox token endpoint answers 500 intermittently:
// measured 21/09/2026, sixteen attempts alternating the two ways of presenting the
// credential, 3/8 succeeded each way. A roteiro run that dies on AT_01 for that reason
// wastes the window, and the C6 FAQ (§9) says a new token does not invalidate the
// current one, so retrying is safe.
//
// The access token is NEVER written to the evidence file. What is recorded is the
// envelope with the token replaced by its length — the roteiro needs the scopes, and a
// live bearer inside a document that goes out by e-mail is a credential in an inbox.
func (r *runner) autenticar(ctx context.Context, tokenURL, clientID, secret string) error {
	r.tokenURL, r.clientID, r.secret = tokenURL, clientID, secret
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {secret},
	}.Encode()

	var (
		status     int
		redigido   string
		token      string
		tentativas int
	)
	for tentativas = 1; tentativas <= authMaxTentativas; tentativas++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")

		resp, err := r.httpc.Do(req)
		if err != nil {
			return fmt.Errorf("AT_01: %w", err)
		}
		raw, _ := readAll(resp)
		status = resp.StatusCode
		_ = resp.Body.Close()
		token, redigido = redigirToken(raw)

		fmt.Fprintf(os.Stderr, "%-10s %-6s %-3d %s (tentativa %d)\n", "AT_01", "POST", status, tokenURL, tentativas)
		if status/100 != 5 {
			break
		}
		time.Sleep(time.Duration(tentativas) * 500 * time.Millisecond)
	}

	nota := ""
	if tentativas > 1 {
		nota = fmt.Sprintf(" [%d tentativas: o endpoint de token do sandbox devolve 500 "+
			"de forma intermitente]", tentativas)
	}
	r.registrar(evidencia{
		Caso: "AT_01", Metodo: http.MethodPost, URL: tokenURL,
		Request: "grant_type=client_credentials&client_id=" + clientID + "&client_secret=<redigido>",
		Status:  status, Body: redigido + nota,
	})

	if status/100 != 2 || token == "" {
		return fmt.Errorf("AT_01 falhou (HTTP %d): sem token não há o que rodar", status)
	}
	r.token = token
	r.tokenDesde = time.Now()
	return nil
}

// autenticarSilencioso renova o bearer sem tocar na evidência de AT_01: o caso já foi
// capturado, e regravá-lo trocaria a captura do roteiro por uma renovação de rotina.
func (r *runner) autenticarSilencioso(ctx context.Context) error {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {r.clientID},
		"client_secret": {r.secret},
	}.Encode()

	for tentativa := 1; tentativa <= authMaxTentativas; tentativa++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.tokenURL, strings.NewReader(form))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		resp, err := r.httpc.Do(req)
		if err != nil {
			return err
		}
		raw, _ := readAll(resp)
		status := resp.StatusCode
		_ = resp.Body.Close()
		if token, _ := redigirToken(raw); status/100 == 2 && token != "" {
			r.token = token
			r.tokenDesde = time.Now()
			return nil
		}
		if status/100 != 5 {
			return fmt.Errorf("HTTP %d", status)
		}
		time.Sleep(time.Duration(tentativa) * 500 * time.Millisecond)
	}
	return fmt.Errorf("token não renovado após %d tentativas", authMaxTentativas)
}

// authMaxTentativas bounds the AT_01 retries.
const authMaxTentativas = 5
