package nfse

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/ia-dev-sindireceita/payment/internal/nfse/custody"
)

// Receipt is the ADN's response to a successful transmission.
type Receipt struct {
	// ChaveAcesso is the NFS-e access key (50 digits).
	ChaveAcesso string
	// NFSeNumber is the ADN-assigned NFS-e number.
	NFSeNumber string
	// XML is the returned NFS-e XML (may be empty in homologation).
	XML []byte
}

// Transmitter delivers a signed DPS to the ADN over mTLS and parses the
// response. A business rejection is returned as *BusinessError; a
// connection/TLS/parse failure as *TransportError. It NEVER returns a nil error
// with an unparsed body. internal/nfse/adn implements it.
type Transmitter interface {
	Transmit(ctx context.Context, companyID string, signedDPS []byte) (Receipt, error)
}

// Sequencer hands out DPS numbers (nDPS) for an emitter CNPJ + série. The
// number must be unique per (CNPJ, série): the Sefin dedupes on the DPS Id,
// which embeds it. Several callers may emit for the same CNPJ, so the
// numbering belongs to the emitter, not to the client. A gap (a number taken
// by an attempt that failed before transmission) is harmless.
type Sequencer interface {
	NextDPSNumber(ctx context.Context, emitterCNPJ, series string) (int64, error)
}

// reservationTTL bounds how long a pending Idempotency-Key reservation blocks
// retries. It must exceed the worst-case Emit (the ADN client times out at
// 30s); past it the holder is presumed crashed and a retry may take the key
// over. A takeover that re-sends a DPS the ADN already accepted is rejected by
// the ADN as a duplicate DPS, so it cannot issue a second NFS-e.
const reservationTTL = 2 * time.Minute

// Emitter is the NFS-e emission use-case. It orchestrates the custody ports
// (CertStore for the public chain + metadata, FiscalSigner for the private-key
// operations), the DPS assembly/signing, the Transmitter, and the Store. No
// private-key material ever crosses into this type.
type Emitter struct {
	certs  custody.CertStore
	signer custody.FiscalSigner
	tx     Transmitter
	store  Store
	env    Environment
	seq    Sequencer

	now   func() time.Time
	newID func() string
}

// EmitterOption configures an Emitter.
type EmitterOption func(*Emitter)

// WithClock overrides the emitter clock (test hook).
func WithClock(now func() time.Time) EmitterOption {
	return func(e *Emitter) { e.now = now }
}

// WithIDGen overrides the emission ID generator (test hook).
func WithIDGen(gen func() string) EmitterOption {
	return func(e *Emitter) { e.newID = gen }
}

// WithEnvironment overrides the ADN environment tag (defaults to homologação).
func WithEnvironment(env Environment) EmitterOption {
	return func(e *Emitter) { e.env = env }
}

// WithSequencer makes the emitter assign the DPS number when the command
// carries none.
func WithSequencer(seq Sequencer) EmitterOption {
	return func(e *Emitter) { e.seq = seq }
}

// NewEmitter wires the emitter. certs, signer, tx, and store are required.
func NewEmitter(certs custody.CertStore, signer custody.FiscalSigner, tx Transmitter, store Store, opts ...EmitterOption) *Emitter {
	e := &Emitter{
		certs:  certs,
		signer: signer,
		tx:     tx,
		store:  store,
		env:    EnvHomologacao,
		now:    time.Now,
		newID:  newEmissionID,
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

// EmitCommand is the validated input to Emit. The web boundary builds it after
// authenticating, validating, and resolving the tenant.
type EmitCommand struct {
	// CompanyID is the tenant that owns the custodied certificate.
	CompanyID string
	// TenantID owns the resulting emission record.
	TenantID string
	// IdempotencyKey, when set, dedupes retries.
	IdempotencyKey string
	// EmitterCNPJ is the MEI providing the service. Must equal the certificate
	// holder (Modelo B invariant).
	EmitterCNPJ string
	Series      string
	// Number is the DPS number; empty means "assign one" (WithSequencer).
	Number      string
	Competencia Competencia
	// MunicipalityCode is the 7-digit IBGE code of the place of provision.
	MunicipalityCode string
	Description      string
	// ServiceValueCents is the service value in cents.
	ServiceValueCents int64
	// ServiceCode is the national taxation code (cTribNac, 6 digits).
	ServiceCode string
	// Regime is the emitter's Simples Nacional situation; zero means MEI.
	Regime SimplesNacional
	// SimplesTaxRateBps is pTotTribSN in basis points; ME/EPP only.
	SimplesTaxRateBps int
	// EmitterMunicipalityCode is the emitting establishment's IBGE code
	// (cLocEmi); empty means MunicipalityCode.
	EmitterMunicipalityCode string
	// Tomador is the service taker; nil omits it.
	Tomador *Tomador
	// MunicipalServiceCode (cTribMun) and NBSCode (cNBS) are optional.
	MunicipalServiceCode string
	NBSCode              string
}

// Emit assembles, signs, and transmits a DPS, persists the result, and returns
// the stored emission. It is idempotent: a prior emission for
// (TenantID, IdempotencyKey) is returned unchanged without re-transmitting,
// and a concurrent request with the same key gets ErrEmissionInFlight instead
// of transmitting a second DPS.
//
// Fail-closed order: idempotency reservation → certificate present & not expired →
// emitter equals certificate holder → aggregate invariants → sign → transmit.
// A business rejection from the ADN is persisted as a rejected emission AND
// returned as *BusinessError so the boundary can answer 422 while still
// exposing the record via GET /{id}.
func (e *Emitter) Emit(ctx context.Context, cmd EmitCommand) (em Emission, err error) {
	now := e.now().UTC()
	id := e.newID()

	var stale Emission
	if cmd.IdempotencyKey != "" {
		prior, reserved, rerr := e.store.Reserve(ctx, Emission{
			ID:                id,
			TenantID:          cmd.TenantID,
			IdempotencyKey:    cmd.IdempotencyKey,
			EmitterCNPJ:       cmd.EmitterCNPJ,
			Competencia:       cmd.Competencia,
			ServiceValueCents: cmd.ServiceValueCents,
			Status:            StatusPending,
			CreatedAt:         now,
		}, now.Add(-reservationTTL))
		if rerr != nil {
			return Emission{}, rerr
		}
		if !reserved {
			return prior, nil
		}
		stale = prior // non-zero only when a crashed reservation was taken over
		// Free the key for a retry unless the ADN answered. Once it has
		// (authorised or rejected), the reservation must stay even if Save
		// fails: a retry would re-send a DPS the ADN already has.
		defer func() {
			if err != nil && !adnAnswered(err) {
				_ = e.store.Release(context.WithoutCancel(ctx), cmd.TenantID, cmd.IdempotencyKey, id)
			}
		}()
	}

	chain, meta, err := e.certs.Get(ctx, cmd.CompanyID)
	if err != nil {
		if errors.Is(err, custody.ErrCertNotFound) {
			return Emission{}, ErrNoCertificate
		}
		return Emission{}, err
	}
	if len(chain) == 0 {
		return Emission{}, ErrNoCertificate
	}
	if meta.IsExpired(now) {
		return Emission{}, ErrCertExpired
	}
	// Modelo B core invariant: the DPS emitter must be the certificate holder.
	if custody.HashCNPJ(cmd.EmitterCNPJ) != meta.CNPJHash {
		return Emission{}, ErrEmitterMismatch
	}

	number := cmd.Number
	assign := number == ""
	if assign {
		if e.seq == nil {
			return Emission{}, ErrNoNumber
		}
		number = "1" // placeholder: validate before consuming a real number
	}
	dps, err := NewDPS(NewDPSParams{
		EmitterCNPJ:       cmd.EmitterCNPJ,
		Series:            cmd.Series,
		Number:            number,
		Competencia:       cmd.Competencia,
		MunicipalityCode:  cmd.MunicipalityCode,
		Description:       cmd.Description,
		ServiceValueCents: cmd.ServiceValueCents,
		Environment:       e.env,
		Now:               now,

		ServiceCode:             cmd.ServiceCode,
		Regime:                  cmd.Regime,
		SimplesTaxRateBps:       cmd.SimplesTaxRateBps,
		EmitterMunicipalityCode: cmd.EmitterMunicipalityCode,
		Tomador:                 cmd.Tomador,
		MunicipalServiceCode:    cmd.MunicipalServiceCode,
		NBSCode:                 cmd.NBSCode,
	})
	if err != nil {
		return Emission{}, err
	}

	base := Emission{
		ID:                id,
		TenantID:          cmd.TenantID,
		IdempotencyKey:    cmd.IdempotencyKey,
		EmitterCNPJ:       dps.EmitterCNPJ,
		Competencia:       dps.Competencia,
		ServiceValueCents: dps.ServiceValueCents,
		Series:            dps.Series,
		CreatedAt:         now,
	}
	if dps.Tomador != nil {
		base.TomadorDocument = dps.Tomador.Document
		base.TomadorName = dps.Tomador.Name
	}

	if assign {
		switch {
		case stale.Number != "" && stale.Series == dps.Series && stale.EmitterCNPJ == dps.EmitterCNPJ:
			// The crashed attempt may have reached the ADN: re-send the same
			// DPS so the Sefin dedupes it instead of issuing a second NFS-e.
			dps.Number = stale.Number
		default:
			n, serr := e.seq.NextDPSNumber(ctx, dps.EmitterCNPJ, dps.Series)
			if serr != nil {
				return Emission{}, serr
			}
			dps.Number = strconv.FormatInt(n, 10)
			if !numberRe.MatchString(dps.Number) {
				return Emission{}, ErrInvalidSeriesNumber
			}
		}
		if cmd.IdempotencyKey != "" {
			// Pin the number on the reservation before transmitting.
			pending := base
			pending.Status = StatusPending
			pending.Number = dps.Number
			if serr := e.store.Save(ctx, pending); serr != nil {
				return Emission{}, serr
			}
		}
	}
	base.Number = dps.Number

	leaf := chain[0]
	signFn := func(digest []byte) ([]byte, error) {
		return e.signer.SignDigest(ctx, cmd.CompanyID, meta.Serial, digest)
	}
	signed, err := Sign(dps, signFn, leaf.Raw)
	if err != nil {
		return Emission{}, err
	}

	base.DPSID = signed.ID

	receipt, err := e.tx.Transmit(ctx, cmd.CompanyID, signed.XML)
	if err != nil {
		if be, ok := AsBusinessError(err); ok {
			rej := base
			rej.Status = StatusRejected
			if len(be.Items) > 0 {
				rej.RejectionCode = be.Items[0].Code
				rej.RejectionMessage = be.Items[0].Message
			}
			// Persist the rejected record so GET /{id} can surface it, then
			// still return the typed business error for the 422.
			if serr := e.store.Save(ctx, rej); serr != nil {
				return Emission{}, &adnAnsweredError{err: serr}
			}
			return rej, err
		}
		return Emission{}, err
	}

	ok := base
	ok.Status = StatusAuthorized
	ok.ChaveAcesso = receipt.ChaveAcesso
	ok.NFSeNumber = receipt.NFSeNumber
	ok.XML = receipt.XML
	if serr := e.store.Save(ctx, ok); serr != nil {
		return Emission{}, &adnAnsweredError{err: serr}
	}
	return ok, nil
}

// adnAnsweredError wraps a failure that happened after the ADN answered (the
// result could not be persisted), so Emit keeps the reservation.
type adnAnsweredError struct{ err error }

func (a *adnAnsweredError) Error() string { return a.err.Error() }
func (a *adnAnsweredError) Unwrap() error { return a.err }

// adnAnswered reports whether err means the ADN already answered the DPS: a
// business rejection, or a persistence failure after an answer.
func adnAnswered(err error) bool {
	if _, ok := AsBusinessError(err); ok {
		return true
	}
	var a *adnAnsweredError
	return errors.As(err, &a)
}

// Status returns a stored emission by id, scoped to tenantID.
func (e *Emitter) Status(ctx context.Context, tenantID, id string) (Emission, error) {
	return e.store.GetByID(ctx, tenantID, id)
}
