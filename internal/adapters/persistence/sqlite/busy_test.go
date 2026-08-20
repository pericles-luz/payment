package sqlite

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Um cartão de R$ 15,00 foi pago, o C6 avisou, e o aviso foi RECUSADO com 500:
//
//	mark processed: database is locked (5) (SQLITE_BUSY)
//
// A marca de anti-replay é a primeira escrita da transação de liquidação, e ela
// esbarrou no trabalhador de entrega de saída, que escreve a cada dois segundos.
// Nenhuma das duas estava errada — o banco é que não tinha instrução para esperar.
//
// O pagamento só não se perdeu porque o C6 repetiu o aviso sozinho. Pior: como a marca
// não gravou, a repetição foi reprocessada do zero, com o anti-replay valendo nada.

// TestEscritasConcorrentesEsperamEmVezDeFalhar reproduz a forma exata do defeito:
// escritas simultâneas em transações separadas. Sem o busy_timeout, a perdedora falha
// na hora com SQLITE_BUSY em vez de esperar os milissegundos que a disputa duraria.
func TestEscritasConcorrentesEsperamEmVezDeFalhar(t *testing.T) {
	t.Parallel()
	db, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `CREATE TABLE t (k INTEGER PRIMARY KEY)`); err != nil {
		t.Fatalf("criar tabela: %v", err)
	}

	const escritores = 12
	var wg sync.WaitGroup
	erros := make(chan error, escritores)
	for i := 0; i < escritores; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				erros <- err
				return
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO t (k) VALUES (?)`, i); err != nil {
				_ = tx.Rollback()
				erros <- err
				return
			}
			if err := tx.Commit(); err != nil {
				erros <- err
			}
		}(i)
	}
	wg.Wait()
	close(erros)

	for err := range erros {
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "locked") || strings.Contains(msg, "busy") {
			t.Fatalf("escritas concorrentes ainda colidem: %v\né esta colisão que recusou, com 500, um pagamento que já tinha sido feito", err)
		}
		t.Fatalf("escrita concorrente falhou: %v", err)
	}

	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM t`).Scan(&n); err != nil {
		t.Fatalf("contar: %v", err)
	}
	if n != escritores {
		t.Fatalf("gravou %d de %d escritas", n, escritores)
	}
}

// O pragma vai no DSN para valer em TODA conexão que o driver abrir. Um DSN que já
// traz busy_timeout não é sobrescrito: quem foi explícito tem a última palavra.
func TestBusyTimeoutVaiNoDSN(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ nome, dsn, quer string }{
		{"caminho simples", "/tmp/x.db", "/tmp/x.db?_pragma=busy_timeout(5000)"},
		{"já tem parâmetro", "file:x.db?mode=rw", "file:x.db?mode=rw&_pragma=busy_timeout(5000)"},
		{"já define o timeout", "file:x.db?_pragma=busy_timeout(99)", "file:x.db?_pragma=busy_timeout(99)"},
	} {
		if got := withBusyTimeout(tc.dsn); got != tc.quer {
			t.Errorf("%s: got %q, want %q", tc.nome, got, tc.quer)
		}
	}
}

// Guarda contra o remédio errado. SetMaxOpenConns(1) parece a correção óbvia e TRAVA
// este código: ListInvoices consulta invoice_items dentro do rows ainda aberto de
// invoices, e com uma conexão só a de dentro espera para sempre pela de fora. Trocar um
// erro barulhento por uma requisição pendurada seria pior.
//
// Se alguém eliminar as consultas aninhadas e quiser serializar, este teste é o lugar
// de registrar a mudança.
func TestNaoSerializaConexoes(t *testing.T) {
	t.Parallel()
	db, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	if got := db.Stats().MaxOpenConnections; got == 1 {
		t.Fatal("o pool foi limitado a uma conexão: com as consultas aninhadas que este\npacote ainda tem, isso pendura a requisição em vez de falhar")
	}
}
