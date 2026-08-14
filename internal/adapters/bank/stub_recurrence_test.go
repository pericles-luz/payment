package bank

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

func stubRecReq() ports.CreateRecRequest {
	return ports.CreateRecRequest{
		Vinculo:             ports.RecVinculo{Contrato: "CT-1", Devedor: ports.RecDevedor{CPF: "12345678909", Nome: "Fulano"}},
		Calendario:          ports.RecCalendario{DataInicial: "2026-08-01", Periodicidade: ports.RecMensal},
		PoliticaRetentativa: ports.Retry3R7D,
	}
}

func TestStubRecLifecycle(t *testing.T) {
	t.Parallel()
	s := newStub(t)
	ctx := context.Background()

	res, err := s.CreateRec(ctx, "t1", stubRecReq())
	if err != nil {
		t.Fatalf("CreateRec: %v", err)
	}
	if len(res.IDRec) != 29 || res.Status != ports.RecCriada || res.TipoJornada != "AGUARDANDO_DEFINICAO" {
		t.Fatalf("unexpected: %+v", res)
	}

	// Idempotent on the contract seed: a repeat create returns the same mandate.
	again, err := s.CreateRec(ctx, "t1", stubRecReq())
	if err != nil || again.IDRec != res.IDRec {
		t.Fatalf("repeat create not idempotent: %+v / %v", again, err)
	}

	got, err := s.GetRec(ctx, "t1", res.IDRec)
	if err != nil || got.Status != ports.RecCriada {
		t.Fatalf("GetRec: %+v / %v", got, err)
	}

	cancelled, err := s.CancelRec(ctx, "t1", res.IDRec)
	if err != nil || cancelled.Status != ports.RecCancelada {
		t.Fatalf("CancelRec: %+v / %v", cancelled, err)
	}
	if again, err := s.CancelRec(ctx, "t1", res.IDRec); err != nil || again.Status != ports.RecCancelada {
		t.Fatalf("repeat cancel: %+v / %v", again, err)
	}
}

func TestStubRecIdempotencyKey(t *testing.T) {
	t.Parallel()
	s := newStub(t)
	ctx := context.Background()
	a := stubRecReq()
	a.IdempotencyKey = "k1"
	b := stubRecReq()
	b.IdempotencyKey = "k1"
	b.Vinculo.Contrato = "CT-DIFFERENT" // same key ⇒ same mandate regardless of contract
	r1, _ := s.CreateRec(ctx, "t1", a)
	r2, _ := s.CreateRec(ctx, "t1", b)
	if r1.IDRec != r2.IDRec {
		t.Fatalf("same idempotency key must collapse: %s vs %s", r1.IDRec, r2.IDRec)
	}
}

func TestStubRecErrors(t *testing.T) {
	t.Parallel()
	s := newStub(t)
	ctx := context.Background()

	if _, err := s.CreateRec(ctx, "other", stubRecReq()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown tenant: %v", err)
	}
	bad := stubRecReq()
	bad.Vinculo.Contrato = ""
	if _, err := s.CreateRec(ctx, "t1", bad); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
	if _, err := s.GetRec(ctx, "t1", "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if _, err := s.CancelRec(ctx, "t1", "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if _, err := s.GetRec(ctx, "other", "x"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("creds checked on read: %v", err)
	}
	if _, err := s.CancelRec(ctx, "other", "x"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("creds checked on cancel: %v", err)
	}
}

func TestStubSolicRecLifecycle(t *testing.T) {
	t.Parallel()
	s := newStub(t)
	ctx := context.Background()
	exp := time.Now().Add(24 * time.Hour)
	req := ports.CreateSolicRecRequest{IDRec: "RR1", Destinatario: ports.SolicRecDestinatario{CPF: "1"}, ExpiraEm: exp}

	res, err := s.CreateSolicRec(ctx, "t1", req)
	if err != nil {
		t.Fatalf("CreateSolicRec: %v", err)
	}
	if len(res.IDSolicRec) != 29 || res.Status != "CRIADA" || res.IDRec != "RR1" {
		t.Fatalf("unexpected: %+v", res)
	}
	again, err := s.CreateSolicRec(ctx, "t1", req)
	if err != nil || again.IDSolicRec != res.IDSolicRec {
		t.Fatalf("repeat not idempotent: %+v / %v", again, err)
	}
	got, err := s.GetSolicRec(ctx, "t1", res.IDSolicRec)
	if err != nil || got.IDRec != "RR1" {
		t.Fatalf("GetSolicRec: %+v / %v", got, err)
	}
}

func TestStubSolicRecErrors(t *testing.T) {
	t.Parallel()
	s := newStub(t)
	ctx := context.Background()
	if _, err := s.CreateSolicRec(ctx, "other", ports.CreateSolicRecRequest{IDRec: "RR1", ExpiraEm: time.Now().Add(time.Hour)}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown tenant: %v", err)
	}
	if _, err := s.CreateSolicRec(ctx, "t1", ports.CreateSolicRecRequest{ExpiraEm: time.Now().Add(time.Hour)}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("empty idRec: %v", err)
	}
	if _, err := s.CreateSolicRec(ctx, "t1", ports.CreateSolicRecRequest{IDRec: "RR1"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("zero expiry: %v", err)
	}
	if _, err := s.GetSolicRec(ctx, "t1", "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if _, err := s.GetSolicRec(ctx, "other", "x"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("creds checked on read: %v", err)
	}
}

func TestStubCobRLifecycle(t *testing.T) {
	t.Parallel()
	s := newStub(t)
	ctx := context.Background()
	req := ports.CreateCobRRequest{IDRec: "RR1", TxID: "tx1", DataVencimento: "2026-09-01", ValorCents: 1050, Recebedor: ports.CobRRecebedor{Conta: "1", TipoConta: ports.ContaCorrente}}

	res, err := s.CreateCobR(ctx, "t1", req)
	if err != nil {
		t.Fatalf("CreateCobR: %v", err)
	}
	if res.TxID != "tx1" || res.ValorCents != 1050 || res.Status != "CRIADA" {
		t.Fatalf("unexpected: %+v", res)
	}
	// Idempotent on txid (anti-double-bill): a repeat create returns the original.
	dup := req
	dup.ValorCents = 9999
	if again, err := s.CreateCobR(ctx, "t1", dup); err != nil || again.ValorCents != 1050 {
		t.Fatalf("txid must collapse to one charge: %+v / %v", again, err)
	}

	got, err := s.GetCobR(ctx, "t1", "tx1")
	if err != nil || got.ValorCents != 1050 {
		t.Fatalf("GetCobR: %+v / %v", got, err)
	}

	rev := req
	rev.ValorCents = 2000
	revised, err := s.ReviseCobR(ctx, "t1", rev)
	if err != nil || revised.ValorCents != 2000 {
		t.Fatalf("ReviseCobR: %+v / %v", revised, err)
	}

	retried, err := s.RetryCobR(ctx, "t1", "tx1", "2026-09-08")
	if err != nil || retried.TxID != "tx1" {
		t.Fatalf("RetryCobR: %+v / %v", retried, err)
	}
}

func TestStubCobRErrors(t *testing.T) {
	t.Parallel()
	s := newStub(t)
	ctx := context.Background()
	good := ports.CreateCobRRequest{IDRec: "RR1", TxID: "tx1", ValorCents: 100}

	if _, err := s.CreateCobR(ctx, "other", good); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown tenant: %v", err)
	}
	for name, mut := range map[string]func(r *ports.CreateCobRRequest){
		"empty txid":  func(r *ports.CreateCobRRequest) { r.TxID = "" },
		"empty idRec": func(r *ports.CreateCobRRequest) { r.IDRec = "" },
		"zero amount": func(r *ports.CreateCobRRequest) { r.ValorCents = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			req := good
			mut(&req)
			if _, err := s.CreateCobR(ctx, "t1", req); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("want ErrValidation, got %v", err)
			}
		})
	}
	if _, err := s.GetCobR(ctx, "t1", "missing"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("GetCobR missing: %v", err)
	}
	if _, err := s.GetCobR(ctx, "other", "x"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("creds checked on read: %v", err)
	}
	if _, err := s.ReviseCobR(ctx, "t1", good); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("ReviseCobR missing: %v", err)
	}
	if _, err := s.ReviseCobR(ctx, "other", good); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("creds checked on revise: %v", err)
	}
	if _, err := s.ReviseCobR(ctx, "t1", ports.CreateCobRRequest{IDRec: "RR1", TxID: ""}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("revise validation: %v", err)
	}
	if _, err := s.RetryCobR(ctx, "t1", "missing", "2026-09-08"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("RetryCobR missing: %v", err)
	}
	if _, err := s.RetryCobR(ctx, "other", "x", "d"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("creds checked on retry: %v", err)
	}
	if _, err := s.RetryCobR(ctx, "t1", "", "d"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("retry validation: %v", err)
	}
}
