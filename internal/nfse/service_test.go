package nfse

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/nfse/custody"
)

// fakeTransmitter is a scripted Transmitter for the service tests.
type fakeTransmitter struct {
	calls   int
	receipt Receipt
	err     error
	lastXML []byte
}

func (f *fakeTransmitter) Transmit(_ context.Context, _ string, signedDPS []byte) (Receipt, error) {
	f.calls++
	f.lastXML = signedDPS
	return f.receipt, f.err
}

const (
	testCompany = "tenant-A"
	testCNPJ    = "47064135000184"
	otherCNPJ   = "11222333000181"
)

// provisionEmitter wires a LocalTestSigner + MemoryCertStore for testCompany
// holding a cert for cnpj valid for validFor, plus the given transmitter.
func provisionEmitter(t *testing.T, cnpj string, validFor time.Duration, tx Transmitter, opts ...EmitterOption) (*Emitter, *custody.MemoryCertStore) {
	t.Helper()
	signer := custody.NewLocalTestSigner(custody.WithClock(func() time.Time { return testNow }))
	chain, meta, err := signer.Provision(testCompany, cnpj, validFor)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	store := custody.NewMemoryCertStore()
	if err := store.PutA1(context.Background(), testCompany, chain, meta); err != nil {
		t.Fatalf("PutA1: %v", err)
	}
	e := NewEmitter(store, signer, tx, NewMemoryStore(), append([]EmitterOption{WithClock(func() time.Time { return testNow })}, opts...)...)
	return e, store
}

func validCommand() EmitCommand {
	return EmitCommand{
		CompanyID:         testCompany,
		TenantID:          "keyA",
		EmitterCNPJ:       testCNPJ,
		Series:            "1",
		Number:            "42",
		Competencia:       Competencia{Year: 2026, Month: 6},
		MunicipalityCode:  "3550308",
		Description:       "Consultoria",
		ServiceValueCents: 15000,
		ServiceCode:       "010501",
	}
}

func TestEmitHappyPath(t *testing.T) {
	tx := &fakeTransmitter{receipt: Receipt{ChaveAcesso: "35260600...50", NFSeNumber: "1001"}}
	e, _ := provisionEmitter(t, testCNPJ, 24*time.Hour, tx)

	em, err := e.Emit(context.Background(), validCommand())
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if em.Status != StatusAuthorized {
		t.Errorf("status = %s", em.Status)
	}
	if em.ChaveAcesso != "35260600...50" || em.NFSeNumber != "1001" {
		t.Errorf("receipt not mapped: %+v", em)
	}
	if em.DPSID == "" || em.ID == "" {
		t.Errorf("missing ids: %+v", em)
	}
	if tx.calls != 1 {
		t.Errorf("transmit calls = %d", tx.calls)
	}
	// Stored + retrievable, scoped to the key.
	got, err := e.Status(context.Background(), "keyA", em.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if got.ID != em.ID {
		t.Errorf("stored id mismatch")
	}
}

func TestEmitIdempotentReplay(t *testing.T) {
	tx := &fakeTransmitter{receipt: Receipt{ChaveAcesso: "abc"}}
	e, _ := provisionEmitter(t, testCNPJ, 24*time.Hour, tx)
	cmd := validCommand()
	cmd.IdempotencyKey = "idem-1"

	first, err := e.Emit(context.Background(), cmd)
	if err != nil {
		t.Fatalf("first Emit: %v", err)
	}
	second, err := e.Emit(context.Background(), cmd)
	if err != nil {
		t.Fatalf("second Emit: %v", err)
	}
	if first.ID != second.ID {
		t.Errorf("replay returned new id: %s vs %s", first.ID, second.ID)
	}
	if tx.calls != 1 {
		t.Errorf("idempotent replay re-transmitted: calls = %d", tx.calls)
	}
}

func TestEmitEmitterMismatch(t *testing.T) {
	tx := &fakeTransmitter{receipt: Receipt{ChaveAcesso: "abc"}}
	// Cert holder is otherCNPJ, but the command emits as testCNPJ.
	e, _ := provisionEmitter(t, otherCNPJ, 24*time.Hour, tx)
	_, err := e.Emit(context.Background(), validCommand())
	if !errors.Is(err, ErrEmitterMismatch) {
		t.Fatalf("err = %v, want ErrEmitterMismatch", err)
	}
	if tx.calls != 0 {
		t.Error("must not transmit on mismatch")
	}
}

func TestEmitExpiredCertificate(t *testing.T) {
	tx := &fakeTransmitter{}
	// Cert already expired relative to testNow (validFor -1h).
	e, _ := provisionEmitter(t, testCNPJ, -1*time.Hour, tx)
	_, err := e.Emit(context.Background(), validCommand())
	if !errors.Is(err, ErrCertExpired) {
		t.Fatalf("err = %v, want ErrCertExpired", err)
	}
	if tx.calls != 0 {
		t.Error("must not transmit with expired cert")
	}
}

func TestEmitNoCertificate(t *testing.T) {
	tx := &fakeTransmitter{}
	signer := custody.NewLocalTestSigner()
	store := custody.NewMemoryCertStore() // empty
	e := NewEmitter(store, signer, tx, NewMemoryStore(), WithClock(func() time.Time { return testNow }))
	_, err := e.Emit(context.Background(), validCommand())
	if !errors.Is(err, ErrNoCertificate) {
		t.Fatalf("err = %v, want ErrNoCertificate", err)
	}
}

func TestEmitInvalidCommand(t *testing.T) {
	tx := &fakeTransmitter{}
	e, _ := provisionEmitter(t, testCNPJ, 24*time.Hour, tx)
	cmd := validCommand()
	cmd.ServiceValueCents = 0
	_, err := e.Emit(context.Background(), cmd)
	if !errors.Is(err, ErrNonPositiveValue) {
		t.Fatalf("err = %v, want ErrNonPositiveValue", err)
	}
	if tx.calls != 0 {
		t.Error("must not transmit an invalid DPS")
	}
}

func TestEmitBusinessErrorPersistsRejection(t *testing.T) {
	be := &BusinessError{HTTPStatus: 422, Items: []BusinessErrorItem{{Code: "E101", Message: "DPS duplicada"}}}
	tx := &fakeTransmitter{err: be}
	e, _ := provisionEmitter(t, testCNPJ, 24*time.Hour, tx)

	cmd := validCommand()
	cmd.IdempotencyKey = "idem-x"
	em, err := e.Emit(context.Background(), cmd)
	if !errors.Is(err, be) {
		t.Fatalf("err = %v, want business error", err)
	}
	if em.Status != StatusRejected || em.RejectionCode != "E101" {
		t.Errorf("rejection not captured: %+v", em)
	}
	// The rejected record is retrievable by id and by idempotency replay.
	got, gerr := e.Status(context.Background(), "keyA", em.ID)
	if gerr != nil || got.Status != StatusRejected {
		t.Errorf("rejected record not stored: %+v err=%v", got, gerr)
	}
	replay, rerr := e.Emit(context.Background(), cmd)
	if rerr != nil {
		t.Fatalf("replay of rejected: %v", rerr)
	}
	if replay.ID != em.ID {
		t.Errorf("replay id mismatch")
	}
	if tx.calls != 1 {
		t.Errorf("replay re-transmitted rejected: calls=%d", tx.calls)
	}
}

func TestEmitTransportError(t *testing.T) {
	te := &TransportError{Op: "do", Err: errors.New("timeout")}
	tx := &fakeTransmitter{err: te}
	e, _ := provisionEmitter(t, testCNPJ, 24*time.Hour, tx)
	_, err := e.Emit(context.Background(), validCommand())
	if !errors.Is(err, te) {
		t.Fatalf("err = %v, want transport error", err)
	}
}
