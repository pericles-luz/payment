package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// Os casos do roteiro, bloco a bloco, na ordem em que o documento os numera.
//
// A ORDEM DE EXECUÇÃO às vezes difere da ordem do documento, e onde difere está dito
// por quê: um caso que precisa do identificador que outro devolve tem de rodar depois
// dele. O arquivo de evidências é gravado ordenado pelo id do caso, então a ordem de
// execução não afeta o documento.

// janela devolve a janela inicio/fim que as listas BACEN exigem, em RFC3339.
func janela() url.Values {
	q := url.Values{}
	q.Set("inicio", instante(-7))
	q.Set("fim", instante(1))
	return q
}

// valor é o valor usado em toda cobrança criada aqui: R$ 5,00, e ele está espremido
// entre um piso e um teto.
//
//   - **Piso 5.** Boleto, BolePix e checkout recusam menos: "O campo 'amount' deve ser
//     no mínimo 5 e no máximo 500000" (medido 21/09/2026; o BACEN não tem piso, então
//     as cobranças PIX passavam com R$ 1,00 e as outras três não).
//   - **Teto 10.** A autoconfirmação de PIX do sandbox só dispara até R$ 10,00
//     (SIN-65917).
//
// R$ 5,00 é o único valor redondo que satisfaz os dois.
const valor = "5.00"

// valorNum é o mesmo valor como número, para os contratos que mandam decimal em vez de
// string.
const valorNum = 5.00

// nota registra um caso cuja evidência NÃO pode vir de uma chamada nossa ao banco.
//
// Existe porque dois casos do bloco de checkout pedem o RECEBIMENTO de um evento no
// nosso webhook, e nenhuma requisição de saída produz isso. Inventar uma chamada
// parecida e apresentá-la como a evidência pedida seria pior do que dizer o que falta.
func (r *runner) nota(caso, texto string) {
	if r.pular(caso) {
		return
	}
	r.registrar(evidencia{Caso: caso, Body: texto})
	fmt.Fprintf(os.Stderr, "%-10s %-6s --- %s\n", caso, "NOTA", texto)
}

// --- AGENDAMENTO DE PAGAMENTOS (AP) ---------------------------------------------

func (r *runner) rodarAgendamento(ctx context.Context) {
	const base = "/v1/schedule_payments"
	partner := opcoes{partner: true}

	// AP_01 envia TRÊS pagamentos porque os casos seguintes consomem itens: AP_04
	// remove uma lista, AP_05 remove um, e AP_06 precisa de lote não vazio para
	// submeter.
	pagamentos := map[string]any{"items": []any{
		map[string]any{
			"content": r.pixKey, "amount": valorNum,
			"description": "Roteiro AP item 1", "payer_name": nomePagador,
			"transaction_date": hoje(),
		},
		// Valores DISTINTOS de propósito: dois itens com a mesma referência e o mesmo
		// valor fazem o banco marcar o segundo com "WARN! This item is duplicated".
		map[string]any{"content": r.pixKey, "amount": valorNum + 1, "description": "Roteiro AP item 2"},
		map[string]any{"content": r.pixKey, "amount": valorNum + 2, "description": "Roteiro AP item 3"},
	}}
	if resp := r.chamar(ctx, "AP_01", http.MethodPost, base+"/decode", pagamentos, partner); resp != nil {
		r.groupID = resp.texto("group_id")
	}

	r.chamar(ctx, "AP_02", http.MethodGet, base+"/query", nil, partner)

	if r.groupID == "" {
		r.nota("AP_03", "sem group_id de AP_01, não há grupo para ler")
		r.nota("AP_04", "sem group_id de AP_01")
		r.nota("AP_05", "sem group_id de AP_01")
		r.nota("AP_06", "sem group_id de AP_01")
		return
	}

	// O banco decodifica o lote de forma ASSÍNCRONA. Ler cedo demais devolve 422
	// "Alguns itens no grupo ainda estão no processo de decodificação", que não é erro
	// de requisição — é pressa. Reler até sair da decodificação é o que torna AP_03 e
	// AP_06 capturáveis.
	esperandoDecode := partner
	esperandoDecode.repetirEnquanto = decodificando
	if resp := r.chamar(ctx, "AP_03", http.MethodGet, base+"/"+r.groupID+"/items", nil, esperandoDecode); resp != nil {
		r.itemIDs = idsDosItens(resp)
	}

	// O corpo do DELETE em lote é um ARRAY puro de {id}, não um objeto com uma lista.
	if len(r.itemIDs) > 0 {
		corpo := []any{map[string]any{"id": r.itemIDs[0]}}
		r.chamar(ctx, "AP_04", http.MethodDelete, base+"/"+r.groupID+"/items", corpo, partner)
	} else {
		r.nota("AP_04", "AP_03 não devolveu item algum para remover")
	}
	if len(r.itemIDs) > 1 {
		r.chamar(ctx, "AP_05", http.MethodDelete, base+"/"+r.groupID+"/items/"+r.itemIDs[1], nil, partner)
	} else {
		r.nota("AP_05", "AP_03 não devolveu um segundo item para remover")
	}

	// O grupo viaja no CORPO do submit, não no caminho, e uploader_name é obrigatório.
	r.chamar(ctx, "AP_06", http.MethodPost, base+"/submit", map[string]any{
		"group_id": r.groupID, "uploader_name": "Roteiro C6 v3.0",
	}, esperandoDecode)
}

// decodificando reconhece a resposta "ainda estou decodificando este lote", que é
// temporária e merece nova leitura — ao contrário de qualquer outro 422, que é
// afirmação sobre o conteúdo enviado e não muda sozinho.
func decodificando(resp *resposta) bool {
	return resp.Status == 422 && strings.Contains(resp.Body, "processo de decodifica")
}

// idsDosItens extrai os ids dos itens de um grupo.
func idsDosItens(resp *resposta) []string {
	itens, _ := resp.Mapa["items"].([]any)
	var out []string
	for _, it := range itens {
		m, _ := it.(map[string]any)
		if id, _ := m["id"].(string); id != "" {
			out = append(out, id)
		}
	}
	return out
}

// --- BOLETO BANCÁRIO v1 (B) ------------------------------------------------------

func (r *runner) rodarBoleto(ctx context.Context) {
	const base = "/v1/bank_slips"
	partner := opcoes{partner: true}

	pagador := map[string]any{
		"name": nomePagador, "tax_id": cpfValido,
		"address": map[string]any{
			"street": "Rua das Flores", "number": 123,
			"city": "Brasília", "state": "DF", "zip_code": "70000000",
		},
	}
	// B_01 — emissão simples com juros diários e multa por atraso, ambos percentuais.
	b1 := map[string]any{
		"external_reference_id": refBoletoV1(),
		"amount":                valorNum,
		"due_date":              emDias(7),
		"billing_scheme":        "21",
		"payer":                 pagador,
		"fine":                  map[string]any{"type": "P", "value": 2.00, "dead_line": 1},
		"interest":              map[string]any{"type": "P", "value": 1.00, "dead_line": 1},
	}
	if resp := r.chamar(ctx, "B_01", http.MethodPost, base+"/", b1, partner); resp != nil {
		r.slipV1ID = resp.texto("id")
	}

	// B_02 — juros e multa VARIÁVEIS: o contrato admite valor fixo ("V") ou percentual
	// ("P") por bloco, então este manda uma de cada forma para exercitar as duas.
	b2 := map[string]any{
		"external_reference_id": refBoletoV1(),
		"amount":                valorNum,
		"due_date":              emDias(7),
		"billing_scheme":        "21",
		"payer":                 pagador,
		"fine":                  map[string]any{"type": "V", "value": 0.50, "dead_line": 1},
		"interest":              map[string]any{"type": "P", "value": 1.00, "dead_line": 1},
	}
	if resp := r.chamar(ctx, "B_02", http.MethodPost, base+"/", b2, partner); resp != nil {
		// Guardado para B_04: alterar um boleto exige que a CIP já o tenha registrado,
		// e esse registro leva MINUTOS. Usar um boleto diferente do que B_05/B_06 leem,
		// e alterá-lo só no fim da corrida, faz a própria duração do roteiro ser a
		// espera — em vez de repetir a mesma recusa durante um minuto e desistir.
		r.slipAlterar = resp.texto("id")
	}

	// B_03 — desconto por antecipação, nas TRÊS faixas que só o v1 tem. Prazos
	// estritamente decrescentes: é regra do banco.
	b3 := map[string]any{
		"external_reference_id": refBoletoV1(),
		"amount":                valorNum,
		"due_date":              emDias(15),
		"billing_scheme":        "21",
		"payer":                 pagador,
		"discount": map[string]any{
			"discount_type": "P",
			"first":         map[string]any{"value": 10.00, "dead_line": 10},
			"second":        map[string]any{"value": 5.00, "dead_line": 5},
			"third":         map[string]any{"value": 2.00, "dead_line": 1},
		},
	}
	if resp := r.chamar(ctx, "B_03", http.MethodPost, base+"/", b3, partner); resp != nil {
		r.slipBaixar = resp.texto("id") // para B_08, pelo mesmo motivo de B_04
	}

	if r.slipV1ID == "" {
		for _, c := range []string{"B_05", "B_06"} {
			r.nota(c, "sem id de B_01, não há boleto para ler")
		}
	} else {
		r.chamar(ctx, "B_05", http.MethodGet, base+"/"+r.slipV1ID, nil, partner)
		r.pdf(ctx, "B_06", base+"/"+r.slipV1ID+"/pdf")
	}

	// B_07 — o webhook de boleto é registrado na API de notificações, não na de boleto.
	r.webhookServico(ctx, "B_07", "BANK_SLIP")

}

// --- CHECKOUT (C) -----------------------------------------------------------------

func (r *runner) rodarCheckout(ctx context.Context) {
	const base = "/v1/checkouts"

	c1 := map[string]any{
		"amount": valorNum,
		"payment": map[string]any{
			"card": map[string]any{
				"type": "CREDIT", "installments": 1, "authenticate": "NOT_REQUIRED",
			},
		},
	}
	if resp := r.chamar(ctx, "C_01", http.MethodPost, base+"/", c1, opcoes{}); resp != nil {
		r.checkout = resp.texto("id")
	}

	if r.checkout == "" {
		r.nota("C_02", "sem id de C_01, não há checkout para ler")
		r.nota("C_03", "sem id de C_01, não há checkout para cancelar")
	} else {
		r.chamar(ctx, "C_02", http.MethodGet, base+"/"+r.checkout, nil, opcoes{})
		r.chamar(ctx, "C_03", http.MethodPut, base+"/"+r.checkout+"/cancel", nil, opcoes{})
	}

	r.webhookServico(ctx, "C_04", "CHECKOUT")

	// C_0501 e C_0502 pedem o RECEBIMENTO de um evento no nosso webhook. Nenhuma
	// requisição de saída produz isso: a evidência é a entrega que o banco faz, e ela
	// aparece no log do receptor, não aqui.
	r.nota("C_0501",
		"evento de entrada. Cadastrar o webhook (C_04), gerar o link (C_01) e colher a "+
			"entrega CREATED no log do receptor em "+r.webhookOuVazio())
	r.nota("C_0502",
		"evento de entrada, e exige PAGAR o link com cartão. Não há cartão de teste "+
			"documentado para o sandbox; a liquidação nunca foi observada nesta conta (ADR-0013)")
}

// webhookServico registra um webhook POR SERVIÇO, se autorizado.
//
// Fica atrás de uma bandeira porque não é como o webhook PIX. O do PIX é chaveado pela
// CHAVE — a nossa é nova e não é usada por ninguém, e P_06_03 a apaga no fim. Este vale
// para a CONTA inteira, registrar SUBSTITUI o destino que a integração existente usa
// naquela conta de sandbox, e a superfície não expõe DELETE: registrado, fica.
func (r *runner) webhookServico(ctx context.Context, caso, servico string) {
	switch {
	case r.webhook == "":
		r.nota(caso, "sem --webhook-url: registro de webhook não executado")
	case !r.servico:
		r.nota(caso, "pulado por segurança: registrar o webhook de serviço "+servico+
			" substitui o destino da CONTA de sandbox inteira e não há DELETE para desfazer. "+
			"Rode com --webhook-servico, em janela combinada, para capturar este caso")
	default:
		r.chamar(ctx, caso, http.MethodPost, "/v1/webhooks", map[string]any{
			"url": r.webhook, "service": servico,
		}, opcoes{})
	}
}

func (r *runner) webhookOuVazio() string {
	if r.webhook == "" {
		return "<--webhook-url não informada>"
	}
	return r.webhook
}

// --- EXTRATO (E) ------------------------------------------------------------------

func (r *runner) rodarExtrato(ctx context.Context) {
	q := url.Values{}
	q.Set("start_date", emDias(-7))
	q.Set("end_date", hoje())
	r.chamar(ctx, "E_01", http.MethodGet, "/v1/statement", nil, opcoes{query: q})
}

// --- PIX (P) ----------------------------------------------------------------------

func (r *runner) rodarPix(ctx context.Context) {
	const base = "/v2/pix"

	// P_04_01 roda ANTES de P_01_01, fora da ordem do documento: a location precisa
	// existir para a cobrança nascer vinculada a ela, e sem esse vínculo o
	// desvinculamento de P_04_04 não teria o que desvincular.
	if resp := r.chamar(ctx, "P_04_01", http.MethodPost, base+"/loc",
		map[string]any{"tipoCob": "cob"}, opcoes{}); resp != nil {
		r.locID = resp.texto("id")
	}

	// P_01_01 — cobrança imediata COM txid (PUT idempotente).
	r.cobTxID = txid()
	cob := map[string]any{
		"calendario": map[string]any{"expiracao": 3600},
		"devedor":    map[string]any{"cpf": cpfValido, "nome": nomePagador},
		"valor":      map[string]any{"original": valor},
		"chave":      r.pixKey,
	}
	if r.locID != "" {
		cob["loc"] = map[string]any{"id": numero(r.locID)}
	}
	r.chamar(ctx, "P_01_01", http.MethodPut, base+"/cob/"+r.cobTxID, cob, opcoes{})

	// P_01_02 — cobrança imediata SEM txid: quem escolhe é o PSP.
	semTxid := map[string]any{
		"calendario": map[string]any{"expiracao": 3600},
		"valor":      map[string]any{"original": valor},
		"chave":      r.pixKey,
	}
	r.chamar(ctx, "P_01_02", http.MethodPost, base+"/cob", semTxid, opcoes{})

	// P_01_03 — revisão. PATCH altera; mandar o corpo inteiro de criação seria outra
	// operação.
	r.chamar(ctx, "P_01_03", http.MethodPatch, base+"/cob/"+r.cobTxID, map[string]any{
		"valor": map[string]any{"original": "6.00"},
	}, opcoes{})

	r.chamar(ctx, "P_01_04", http.MethodGet, base+"/cob/"+r.cobTxID, nil, opcoes{})
	r.chamar(ctx, "P_01_05", http.MethodGet, base+"/cob", nil, opcoes{query: janela()})

	// P_02 — cobrança com vencimento. O devedor de uma cobv precisa de ENDEREÇO, ao
	// contrário do de uma cobrança imediata: a cobv é documento formal de cobrança.
	r.cobvTxID = txid()
	cobv := map[string]any{
		"calendario": map[string]any{
			"dataDeVencimento":       emDias(7),
			"validadeAposVencimento": 30,
		},
		"devedor": map[string]any{
			"cpf": cpfValido, "nome": nomePagador,
			"logradouro": "Rua das Flores 123", "cidade": "Brasília",
			"uf": "DF", "cep": "70000000",
		},
		"valor": map[string]any{"original": valor},
		"chave": r.pixKey,
	}
	r.chamar(ctx, "P_02_01", http.MethodPut, base+"/cobv/"+r.cobvTxID, cobv, opcoes{})
	r.chamar(ctx, "P_02_02", http.MethodPatch, base+"/cobv/"+r.cobvTxID, map[string]any{
		"valor": map[string]any{"original": "6.00"},
	}, opcoes{})
	r.chamar(ctx, "P_02_03", http.MethodGet, base+"/cobv/"+r.cobvTxID, nil, opcoes{})
	r.chamar(ctx, "P_02_04", http.MethodGet, base+"/cobv", nil, opcoes{query: janela()})

	// P_03 — lote de cobranças com vencimento. A escrita responde 202: o PSP ACEITA o
	// lote, as cobranças ainda não existem. O resultado por cobrança só sai em P_03_03.
	r.loteID = id(20)
	loteTx := txid()
	lote := map[string]any{
		"descricao": "Roteiro C6 v3.0 — lote de homologação",
		"cobsv": []any{
			mesclar(map[string]any{"txid": loteTx}, cobv),
		},
	}
	// O lote recusou `application/json` pedindo `application/problem+json`, e recusou
	// `application/problem+json` com 406. Mandar os dois é o que resta — e, se ainda
	// assim não passar, a evidência registra um endpoint que não aceita nenhum Accept
	// que ele próprio nomeia.
	semCorpo := opcoes{accept: "application/json, application/problem+json"}
	r.chamar(ctx, "P_03_01", http.MethodPut, base+"/lotecobv/"+r.loteID, lote, semCorpo)
	loteRevisado := map[string]any{
		"descricao": "Roteiro C6 v3.0 — lote revisado",
		"cobsv": []any{
			mesclar(map[string]any{"txid": loteTx}, cobv),
		},
	}
	r.chamar(ctx, "P_03_02", http.MethodPatch, base+"/lotecobv/"+r.loteID, loteRevisado, semCorpo)
	r.chamar(ctx, "P_03_03", http.MethodGet, base+"/lotecobv/"+r.loteID, nil, opcoes{})
	r.chamar(ctx, "P_03_04", http.MethodGet, base+"/lotecobv", nil, opcoes{query: janela()})

	// P_04_02..04 — o resto do bloco de location.
	r.chamar(ctx, "P_04_02", http.MethodGet, base+"/loc", nil, opcoes{query: janela()})
	if r.locID == "" {
		r.nota("P_04_03", "P_04_01 não devolveu id de location")
		r.nota("P_04_04", "P_04_01 não devolveu id de location")
	} else {
		r.chamar(ctx, "P_04_03", http.MethodGet, base+"/loc/"+r.locID, nil, opcoes{})
		r.chamar(ctx, "P_04_04", http.MethodDelete, base+"/loc/"+r.locID+"/txid", nil, opcoes{})
	}

	// P_05_02 roda ANTES de P_05_01, fora da ordem do documento: a consulta por e2eid
	// precisa de um e2eid, e o único jeito de descobrir um é listando os recebidos.
	if resp := r.chamar(ctx, "P_05_02", http.MethodGet, base+"/pix", nil, opcoes{query: janela()}); resp != nil {
		r.e2eID = primeiroE2E(resp)
	}
	if r.e2eID == "" {
		const semPix = "nenhum PIX recebido na janela consultada (P_05_02 voltou lista vazia). " +
			"Um PIX recebido depende de alguém pagar uma cobrança; no sandbox isso não " +
			"acontece sozinho e a liquidação nunca foi observada nesta conta (ADR-0013)"
		r.nota("P_05_01", semPix)
		r.nota("P_05_03", semPix+" — sem PIX recebido não há o que devolver")
		r.nota("P_05_04", semPix)
	} else {
		r.chamar(ctx, "P_05_01", http.MethodGet, base+"/pix/"+r.e2eID, nil, opcoes{})
		// O id da devolução é NOSSO: é ele que torna a operação idempotente, de modo
		// que um reenvio nunca devolve duas vezes.
		r.devID = id(30)
		r.chamar(ctx, "P_05_03", http.MethodPut, base+"/pix/"+r.e2eID+"/devolucao/"+r.devID,
			map[string]any{"valor": "0.01", "natureza": "ORIGINAL", "descricao": "Roteiro"}, opcoes{})
		r.chamar(ctx, "P_05_04", http.MethodGet, base+"/pix/"+r.e2eID+"/devolucao/"+r.devID, nil, opcoes{})
	}

	// P_06 — webhook PIX, chaveado pela CHAVE, não por tenant. A exclusão vem por
	// último: apagar antes tiraria de P_06_02 o registro que ela lê.
	if r.webhook == "" {
		for _, c := range []string{"P_06_01", "P_06_02", "P_06_03"} {
			r.nota(c, "sem --webhook-url: registro de webhook não executado")
		}
		return
	}
	chave := url.PathEscape(r.pixKey)
	// O registro e a remoção respondem SEM corpo, e nesses o BACEN recusa
	// `application/json`. A leitura responde com corpo e aceita json — é por isso que
	// só dois dos três trocam o Accept.
	r.chamar(ctx, "P_06_01", http.MethodPut, base+"/webhook/"+chave,
		map[string]any{"webhookUrl": r.webhook}, opcoes{accept: acceptProblema})
	r.chamar(ctx, "P_06_02", http.MethodGet, base+"/webhook/"+chave, nil, opcoes{})
	r.chamar(ctx, "P_06_03", http.MethodDelete, base+"/webhook/"+chave, nil, opcoes{accept: acceptProblema})
}

// primeiroE2E devolve o endToEndId do primeiro PIX recebido da lista, se houver.
func primeiroE2E(resp *resposta) string {
	lista, _ := resp.Mapa["pix"].([]any)
	for _, it := range lista {
		m, _ := it.(map[string]any)
		if e, _ := m["endToEndId"].(string); e != "" {
			return e
		}
	}
	return ""
}

// mesclar devolve a união de dois mapas, sem alterar nenhum deles.
func mesclar(a, b map[string]any) map[string]any {
	out := make(map[string]any, len(a)+len(b))
	for k, v := range b {
		out[k] = v
	}
	for k, v := range a {
		out[k] = v
	}
	return out
}

// numero converte um id textual em número quando ele é numérico, devolvendo o texto
// original quando não é. O `loc.id` do BACEN é inteiro; o nosso transporte o carrega
// como texto porque o contrato do lote o declara das duas formas.
func numero(s string) any {
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err == nil && fmt.Sprint(n) == strings.TrimSpace(s) {
		return n
	}
	return s
}

// --- TRANSAÇÕES E RECEBÍVEIS (TR) -------------------------------------------------

func (r *runner) rodarRecebiveis(ctx context.Context) {
	q := url.Values{}
	q.Set("start_date", emDias(-7))
	q.Set("end_date", hoje())
	q.Set("page", "1")
	q.Set("size", "200")
	partner := opcoes{partner: true, query: q}
	r.chamar(ctx, "TR_01", http.MethodGet, "/v1/c6pay/statement/receivables", nil, partner)
	r.chamar(ctx, "TR_02", http.MethodGet, "/v1/c6pay/statement/transactions", nil, partner)
}

// --- PIX AUTOMÁTICO (PA) ----------------------------------------------------------

func (r *runner) rodarPixAutomatico(ctx context.Context) {
	const base = "/v2/pix"

	// O corpo de uma recorrência: calendário (data inicial + periodicidade), política
	// de retentativa e o vínculo (contrato + devedor). idRec tem 29 caracteres e é
	// escolhido por quem chama.
	// O corpo de CRIAÇÃO não é o `RecBase` da leitura, e a diferença custou quatro
	// casos na primeira corrida. O banco foi explícito:
	//
	//	Object instance has properties which are not allowed by the schema:
	//	["idRec","retentativa"], Object has missing required properties:
	//	["politicaRetentativa"]
	//
	// Ou seja: quem escolhe o idRec é o PSP, não nós; e a política de retentativa vai
	// SOLTA no topo, não dentro de um objeto `retentativa`.
	novoRec := func(extra map[string]any) map[string]any {
		corpo := map[string]any{
			"calendario": map[string]any{
				"dataInicial":   emDias(7),
				"periodicidade": "MENSAL",
			},
			"politicaRetentativa": "NAO_PERMITE",
			"vinculo": map[string]any{
				"contrato": "ROTEIRO-C6-V3",
				"objeto":   "Assinatura de homologação",
				"devedor":  map[string]any{"cpf": cpfValido, "nome": nomePagador},
			},
			"valor": map[string]any{"valorRec": valor},
		}
		return mesclar(extra, corpo)
	}

	// PA_01 — jornada 1: criar a recorrência e a solicitação de consentimento.
	if resp := r.chamar(ctx, "PA_01_01", http.MethodPost, base+"/rec", novoRec(nil), opcoes{}); resp != nil {
		r.idRec = resp.texto("idRec")
	}
	solic := map[string]any{
		"idRec": r.idRec,
		"calendario": map[string]any{
			"dataExpiracaoSolicitacao": instante(7),
		},
		"destinatario": map[string]any{
			"cpf": cpfValido, "conta": "12345678", "agencia": "0001",
			"ispbParticipante": "00000000",
		},
	}
	if r.idRec == "" {
		r.nota("PA_01_02", "PA_01_01 não devolveu idRec; a solicitação de consentimento precisa dele")
	} else if resp := r.chamar(ctx, "PA_01_02", http.MethodPost, base+"/solicrec", solic, opcoes{}); resp != nil {
		r.idSolic = resp.texto("idSolicRec")
	}
	if r.idSolic == "" {
		r.nota("PA_01_03", "PA_01_02 não devolveu idSolicRec")
	} else {
		r.chamar(ctx, "PA_01_03", http.MethodGet, base+"/solicrec/"+r.idSolic, nil, opcoes{})
	}

	// PA_02 — jornada 2: location da recorrência, recorrência vinculada a ela, webhook,
	// leitura.
	if resp := r.chamar(ctx, "PA_02_01", http.MethodPost, base+"/locrec", nil, opcoes{}); resp != nil {
		r.locRecID = resp.texto("id")
	}
	corpo2 := novoRec(nil)
	if r.locRecID != "" {
		corpo2["loc"] = numero(r.locRecID)
	}
	var idRec2 string
	if resp := r.chamar(ctx, "PA_02_02", http.MethodPost, base+"/rec", corpo2, opcoes{}); resp != nil {
		idRec2 = resp.texto("idRec")
	}
	// O roteiro diz POST; o contrato diz PUT, e um POST aqui responde 405. A evidência
	// é o que o banco devolve ao verbo do CONTRATO.
	r.webhookRec(ctx, "PA_02_03", base+"/webhookrec")
	r.lerRec(ctx, "PA_02_04", base, idRec2, "")

	// PA_03 — jornada 3: a recorrência nasce vinculada a uma cobrança imediata já
	// existente, pelo txid dela.
	r.chamar(ctx, "PA_03_01", http.MethodPost, base+"/locrec", nil, opcoes{})
	corpo3 := novoRec(map[string]any{
		"ativacao": map[string]any{"dadosJornada": map[string]any{"txid": r.cobTxID}},
	})
	var idRec3 string
	if resp := r.chamar(ctx, "PA_03_02", http.MethodPost, base+"/rec", corpo3, opcoes{}); resp != nil {
		idRec3 = resp.texto("idRec")
	}
	r.webhookRec(ctx, "PA_03_03", base+"/webhookrec")
	r.lerRec(ctx, "PA_03_04", base, idRec3, r.cobTxID)

	// PA_04 — jornada 4: mesma forma, ancorada numa cobrança COM VENCIMENTO.
	r.chamar(ctx, "PA_04_01", http.MethodPost, base+"/locrec", nil, opcoes{})
	corpo4 := novoRec(map[string]any{
		"ativacao": map[string]any{"dadosJornada": map[string]any{"txid": r.cobvTxID}},
	})
	var idRec4 string
	if resp := r.chamar(ctx, "PA_04_02", http.MethodPost, base+"/rec", corpo4, opcoes{}); resp != nil {
		idRec4 = resp.texto("idRec")
	}
	r.webhookRec(ctx, "PA_04_03", base+"/webhookrec")
	r.lerRec(ctx, "PA_04_04", base, idRec4, r.cobvTxID)
}

// lerRec lê UMA recorrência.
//
// O Accept não é `application/json` porque este endpoint o recusa, e não é nenhum dos
// dois que ele diz exigir porque recusa os dois também. Medido em 21/09/2026:
//
//	application/json          → 400 "must be one of: [application/jose, application/problem+json]"
//	application/jose          → 406
//	application/problem+json  → 406
//	*/*                       → 200, e o corpo que volta é application/json
//
// Não contradiz a correção de 28/08/2026: aquela foi medida na LISTA (`GET /rec`), que
// aceita json. São endpoints diferentes, e este aqui não tem valor específico certo.
func (r *runner) lerRec(ctx context.Context, caso, base, idRec, txid string) {
	if idRec == "" {
		r.nota(caso, "a criação da recorrência não devolveu idRec; não há o que ler")
		return
	}
	opt := opcoes{accept: acceptCoringa}
	if txid != "" {
		opt.query = url.Values{"txId": {txid}}
	}
	r.chamar(ctx, caso, http.MethodGet, base+"/rec/"+idRec, nil, opt)
}

// webhookRec registra o webhook de recorrência, ou anota a falta da URL.
func (r *runner) webhookRec(ctx context.Context, caso, caminho string) {
	if r.webhook == "" {
		r.nota(caso, "sem --webhook-url: registro de webhook de recorrência não executado")
		return
	}
	r.chamar(ctx, caso, http.MethodPut, caminho, map[string]any{"webhookUrl": r.webhook},
		opcoes{accept: acceptProblema})
}

// --- BOLEPIX (BP) -----------------------------------------------------------------

func (r *runner) rodarBolepix(ctx context.Context) {
	const base = "/v2/bank_slips"
	partner := opcoes{partner: true}

	pagador := map[string]any{
		"name": nomePagador, "tax_id": cpfValido,
		"address": map[string]any{
			"address": "Rua das Flores 123", "neighborhood": "Asa Sul",
			"city": "Brasília", "state": "DF", "zip_code": "70000000",
		},
	}
	corpo := func(ref string) map[string]any {
		return map[string]any{
			"external_reference_id": ref,
			"amount":                valorNum,
			"due_date":              emDias(7),
			"description":           "Roteiro C6 v3.0",
			"payer":                 pagador,
			"payment_method": map[string]any{
				"bank_slip": map[string]any{"billing_scheme": "21"},
				"pix":       map[string]any{"key": r.pixKey, "type": "EVP"},
			},
		}
	}

	r.bolepixID = refBolepix()
	r.chamar(ctx, "BP_01_01", http.MethodPost, base, corpo(r.bolepixID), partner)

	// BP_01_02 — reenviar a MESMA external_reference_id: a resposta esperada é a
	// cobrança já existente, não uma segunda cobrança.
	r.chamar(ctx, "BP_01_02", http.MethodPost, base, corpo(r.bolepixID), partner)

	r.chamar(ctx, "BP_03", http.MethodGet, base+"/"+r.bolepixID, nil, partner)
	r.pdf(ctx, "BP_04", base+"/"+r.bolepixID+"/pdf")

	// BP_02 e BP_05 — a alteração e a baixa — ficam para o fim da corrida, pelo mesmo
	// motivo de B_04 e B_08. Ver finalizar.

	// BP_06 — a listagem recusou TODOS os parâmetros que o contrato declara
	// ("query parameter is unexpected: size, page, due_date_to, due_date_from"), então
	// a chamada vai sem nenhum. Se ela passar assim, o contrato publicado está à frente
	// do que o sandbox expõe, e é isso que a evidência mostra.
	r.chamar(ctx, "BP_06", http.MethodGet, base+"/list", nil, partner)
}

// aguardandoCIP reconhece a recusa temporária "já existe uma requisição à CIP sujeita a
// aprovação": a cobrança recém-criada ainda está sendo registrada na CIP, e alterar ou
// baixar nesse meio-tempo é recusado. É espera, não erro de conteúdo — a mesma
// requisição passa depois.
//
// O reconhecimento é pela MENSAGEM e não pelo status, porque o mesmo impedimento chega
// como 422 no BolePix e como 400 no boleto v1. Casar por status deixaria metade dos
// casos de fora.
func aguardandoCIP(resp *resposta) bool {
	return strings.Contains(resp.Body, "CIP sujeita a aprova")
}

// --- Escritas que dependem da CIP (B_04, B_08, BP_02, BP_05) ---------------------

// finalizar roda as operações que o banco só aceita depois de registrar a cobrança na
// CIP.
//
// Elas são as últimas da corrida de propósito. A recusa é sempre a mesma — "Evento não
// pode ser realizado, pois já existe uma requisição à CIP sujeita a aprovação" — e ela
// cede com TEMPO, não com insistência: na primeira corrida, seis retentativas ao longo
// de um minuto não foram suficientes. Deixar para o fim usa os minutos que o resto do
// roteiro já gasta, de graça, e ainda assim cada uma repete enquanto for essa recusa.
//
// Cada caso opera uma cobrança DIFERENTE: alterar e baixar a mesma faria a segunda
// esperar a primeira, somando as duas esperas.
func (r *runner) finalizar(ctx context.Context) {
	// Duas tentativas, não seis.
	//
	// Medido em 21/09/2026: um boleto emitido QUARENTA MINUTOS antes continuava
	// recusando a alteração com a mesma mensagem. No sandbox a requisição à CIP não
	// parece se resolver — nem em minutos, nem na mesma sessão. Insistir não muda o
	// resultado; só queima a janela e o limite de 60 chamadas por minuto. Duas
	// tentativas provam que não foi pressa, e a evidência guarda a recusa do banco,
	// que se explica sozinha.
	naCIP := opcoes{partner: true, repetirEnquanto: aguardandoCIP, maxRepeticoes: 1}

	if r.slipAlterar == "" {
		r.nota("B_04", "B_02 não devolveu id; não há boleto para alterar")
	} else {
		r.chamar(ctx, "B_04", http.MethodPut, "/v1/bank_slips/"+r.slipAlterar,
			map[string]any{"due_date": emDias(20)}, naCIP)
	}
	if r.slipBaixar == "" {
		r.nota("B_08", "B_03 não devolveu id; não há boleto para baixar")
	} else {
		r.chamar(ctx, "B_08", http.MethodPut, "/v1/bank_slips/"+r.slipBaixar+"/cancel", nil, naCIP)
	}

	if r.bolepixID == "" {
		r.nota("BP_02", "BP_01_01 não devolveu referência; não há cobrança para alterar")
		r.nota("BP_05", "BP_01_01 não devolveu referência; não há cobrança para baixar")
		return
	}
	r.chamar(ctx, "BP_02", http.MethodPatch, "/v2/bank_slips/"+r.bolepixID,
		map[string]any{"amount": valorNum + 1}, naCIP)
	r.chamar(ctx, "BP_05", http.MethodPut, "/v2/bank_slips/"+r.bolepixID+"/cancel", nil, naCIP)
}
