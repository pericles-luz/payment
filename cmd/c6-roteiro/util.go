package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// readAll reads a bounded response body.
func readAll(resp *http.Response) ([]byte, error) {
	return io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
}

// redigirToken extracts the access token and returns the envelope with the token
// replaced by its length.
//
// The roteiro wants the auth response, and what makes it evidence is the `scope` list —
// not the bearer. A live token in a document that goes out by e-mail is a credential in
// an inbox, so it is removed here rather than "remembered to be removed" later.
func redigirToken(raw []byte) (token, redigido string) {
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", strings.TrimSpace(string(raw))
	}
	if t, ok := env["access_token"].(string); ok {
		token = t
		env["access_token"] = fmt.Sprintf("<redigido: %d caracteres>", len(t))
	}
	// Encoder com SetEscapeHTML(false): o json.Marshal padrão vira `<` em `\u003c`, e o
	// corpo daqui vai para um documento que uma pessoa lê. Escapar HTML num arquivo que
	// não é HTML só atrapalha quem confere.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(env); err != nil {
		return token, strings.TrimSpace(string(raw))
	}
	return token, strings.TrimSpace(buf.String())
}

// alfabeto is the character set of the identifiers the C6 contracts accept
// (`[A-Z0-9]`), shared by the txid and the BolePix external reference.
const alfabeto = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// id gera um identificador aleatório de n caracteres de `alfabeto`.
//
// Aleatório, e não sequencial nem derivado da hora: duas corridas do roteiro no mesmo
// dia precisam criar cobranças DIFERENTES. Um txid repetido não dá erro — o PUT é
// idempotente, então a segunda corrida "cria" a cobrança da primeira e a evidência sai
// com data errada, sem nada indicando o problema.
func id(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand não falha em prática; se falhar, uma marca temporal é melhor do
		// que um identificador previsível.
		return strings.ToUpper(fmt.Sprintf("%X", time.Now().UnixNano()))[:n]
	}
	for i := range buf {
		buf[i] = alfabeto[int(buf[i])%len(alfabeto)]
	}
	return string(buf)
}

// txid gera um txid BACEN válido (26..35 de [a-zA-Z0-9]).
func txid() string { return "HML" + id(29) }

// refBolepix gera um external_reference_id do BolePix: EXATAMENTE 26 de [A-Z0-9].
func refBolepix() string { return id(26) }

// refBoletoV1 gera um external_reference_id do boleto v1: até 10 alfanuméricos.
func refBoletoV1() string { return id(10) }

// hoje / emDias rendem datas no formato `date` dos contratos (YYYY-MM-DD), no fuso de
// São Paulo — que é o fuso em que o banco decide o que é "hoje".
func hoje() string { return emDias(0) }

func emDias(n int) string {
	loc, err := time.LoadLocation("America/Sao_Paulo")
	if err != nil {
		loc = time.UTC
	}
	return time.Now().In(loc).AddDate(0, 0, n).Format("2006-01-02")
}

// instante rende um instante RFC3339 deslocado de n dias, que é o formato das janelas
// inicio/fim das listas BACEN.
func instante(n int) string {
	return time.Now().UTC().AddDate(0, 0, n).Format(time.RFC3339)
}

// pagadorPF é o devedor usado nas emissões.
//
// O CPF tem dígito verificador VÁLIDO. O `12345678901` que estava nas fixtures do
// repositório é recusado pelo banco com 422 e uma mensagem da Matera que não menciona
// CPF — uma hora de diagnóstico, registrada na ADR-0013.
const cpfValido = "11144477735"

const nomePagador = "Fulano de Tal"
