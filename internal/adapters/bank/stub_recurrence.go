package bank

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"

	"github.com/ia-dev-sindireceita/payment/internal/domain/shared"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// StubProvider PIX Automático (Recorrência) methods (SIN-66035). Deterministic and
// idempotent, mirroring the real C6 lifecycle (a Rec starts CRIADA and is approved
// out-of-band; a CobR is anchored by its txid) so wiring and use-cases run
// end-to-end without C6. Like CreateCharge, every method resolves the tenant's
// credential first to demonstrate per-tenant isolation; the secret is never logged.

// compile-time assertions that StubProvider satisfies the Recorrência ports.
var (
	_ ports.RecProvider                = (*StubProvider)(nil)
	_ ports.SolicRecProvider           = (*StubProvider)(nil)
	_ ports.CobRProvider               = (*StubProvider)(nil)
	_ ports.LocRecProvider             = (*StubProvider)(nil)
	_ ports.RecurrenceWebhookRegistrar = (*StubProvider)(nil)
)

// stubHTTPSURL reports whether raw is an absolute https:// URL with a host,
// mirroring the real adapter's boundary check (a recurrence callback MUST be HTTPS
// so the secret per-tenant ref it embeds is never sent in plaintext).
func stubHTTPSURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	return u.Scheme == "https" && u.Host != ""
}

// RegisterRecWebhook records the singleton Rec-status callback for the tenant.
// HTTPS-only and tenant-scoped (the credential is resolved first), idempotent (a
// re-register replaces the URL).
func (s *StubProvider) RegisterRecWebhook(ctx context.Context, tenantID, webhookURL string) error {
	return s.registerRecurrenceWebhook(ctx, tenantID, webhookURL, s.recWebhooks)
}

// GetRecWebhook reads back the registered Rec callback; unregistered → ErrNotFound.
func (s *StubProvider) GetRecWebhook(ctx context.Context, tenantID string) (ports.WebhookRegistration, error) {
	return s.getRecurrenceWebhook(ctx, tenantID, s.recWebhooks)
}

// RegisterCobRWebhook records the singleton CobR callback for the tenant.
func (s *StubProvider) RegisterCobRWebhook(ctx context.Context, tenantID, webhookURL string) error {
	return s.registerRecurrenceWebhook(ctx, tenantID, webhookURL, s.cobrWebhooks)
}

// GetCobRWebhook reads back the registered CobR callback; unregistered → ErrNotFound.
func (s *StubProvider) GetCobRWebhook(ctx context.Context, tenantID string) (ports.WebhookRegistration, error) {
	return s.getRecurrenceWebhook(ctx, tenantID, s.cobrWebhooks)
}

func (s *StubProvider) registerRecurrenceWebhook(ctx context.Context, tenantID, webhookURL string, into map[string]ports.WebhookRegistration) error {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return err
	}
	if strings.TrimSpace(tenantID) == "" || !stubHTTPSURL(webhookURL) {
		return shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	into[tenantID] = ports.WebhookRegistration{WebhookURL: webhookURL, CreatedAt: s.now()}
	return nil
}

func (s *StubProvider) getRecurrenceWebhook(ctx context.Context, tenantID string, from map[string]ports.WebhookRegistration) (ports.WebhookRegistration, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.WebhookRegistration{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	reg, ok := from[tenantID]
	if !ok {
		return ports.WebhookRegistration{}, shared.ErrNotFound
	}
	return reg, nil
}

// stubRecID derives a deterministic BACEN-shaped id ("RN"/"SC" + 27 hex = 29
// chars, matching [a-zA-Z0-9]{29}) from a stable seed so a repeat create is
// idempotent.
func stubRecID(prefix, seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return prefix + hex.EncodeToString(sum[:])[:27]
}

// CreateRec registers a recurring mandate deterministically. A repeat call with the
// same idempotency anchor (or contract) returns the existing mandate.
func (s *StubProvider) CreateRec(ctx context.Context, tenantID string, req ports.CreateRecRequest) (ports.RecResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.RecResult{}, err
	}
	if req.Vinculo.Contrato == "" || req.Calendario.DataInicial == "" || req.PoliticaRetentativa == "" {
		return ports.RecResult{}, shared.ErrValidation
	}
	seed := req.IdempotencyKey
	if seed == "" {
		seed = tenantID + "\x00" + req.Vinculo.Contrato
	}
	idRec := stubRecID("RN", seed)
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(tenantID, idRec)
	if prev, ok := s.recs[k]; ok {
		return prev, nil
	}
	res := ports.RecResult{
		IDRec:               idRec,
		Status:              ports.RecCriada,
		Vinculo:             req.Vinculo,
		Calendario:          req.Calendario,
		PoliticaRetentativa: req.PoliticaRetentativa,
		TipoJornada:         "AGUARDANDO_DEFINICAO",
		LocID:               req.LocID,
		Location:            s.locRecs[key(tenantID, strconv.FormatInt(req.LocID, 10))].Location,
		ValorRecCents:       req.ValorRecCents,
	}
	// Remember which immediate charge this mandate was composed against, so a later
	// GetRecForQR can reproduce the real bank's rule: the composite QR only exists
	// when the mandate and the referenced charge agree on the txid.
	if txid := strings.TrimSpace(req.JornadaTxID); txid != "" {
		s.recJornadaTxID[k] = txid
	}
	s.recs[k] = res
	return res, nil
}

// GetRecForQR mirrors the bank's composite-QR read. It reproduces the two rules that
// matter for a caller to be exercised honestly against the stub:
//
//   - the jornada is chosen by what the txid refers to — the mandate's own journey
//     txid composes JORNADA_3, no txid composes JORNADA_2;
//   - dadosQR is filled ONLY when the QR is actually composable. Asking for JORNADA_3
//     with a txid the mandate was not created against leaves dadosQR empty rather
//     than inventing a QR, so a caller that forgets to thread the txid through fails
//     here instead of in front of a payer.
func (s *StubProvider) GetRecForQR(ctx context.Context, tenantID, idRec, txID string) (ports.RecResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.RecResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(tenantID, idRec)
	res, ok := s.recs[k]
	if !ok {
		return ports.RecResult{}, shared.ErrNotFound
	}
	txID = strings.TrimSpace(txID)
	switch {
	case txID == "":
		res.DadosQR = ports.RecDadosQR{Jornada: "JORNADA_2", PixCopiaECola: stubBRCode(idRec, "")}
	case s.recJornadaTxID[k] == txID:
		res.DadosQR = ports.RecDadosQR{Jornada: "JORNADA_3", PixCopiaECola: stubBRCode(idRec, txID)}
	}
	return res, nil
}

// stubBRCode derives a deterministic, obviously-fake Pix Copia e Cola for a composed
// QR. It is not a valid BR Code and must never reach a payer — it exists so tests and
// the stub smoke run can assert that a QR was composed for the right (idRec, txid).
func stubBRCode(idRec, txID string) string {
	sum := sha256.Sum256([]byte("brcode\x00" + idRec + "\x00" + txID))
	return "00020101021226STUB" + strings.ToUpper(hex.EncodeToString(sum[:])[:32])
}

// CreateLocRec mints a payload location. Ids are sequential int64s like the bank's;
// a retried mint with the same idempotency key returns the location already minted.
func (s *StubProvider) CreateLocRec(ctx context.Context, tenantID, idempotencyKey string) (ports.LocRecResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.LocRecResult{}, err
	}
	if strings.TrimSpace(tenantID) == "" {
		return ports.LocRecResult{}, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if idem := strings.TrimSpace(idempotencyKey); idem != "" {
		if id, ok := s.locRecByIdem[key(tenantID, idem)]; ok {
			return s.locRecs[key(tenantID, strconv.FormatInt(id, 10))], nil
		}
	}
	s.locRecSeq++
	id := s.locRecSeq
	res := ports.LocRecResult{
		ID:       id,
		Location: "https://pix.stub.example/qr/v2/rec/" + stubRecID("LC", tenantID+"\x00"+strconv.FormatInt(id, 10)),
		Criacao:  s.now(),
	}
	s.locRecs[key(tenantID, strconv.FormatInt(id, 10))] = res
	if idem := strings.TrimSpace(idempotencyKey); idem != "" {
		s.locRecByIdem[key(tenantID, idem)] = id
	}
	return res, nil
}

// GetLocRec reads one location back for the tenant; unknown → ErrNotFound.
func (s *StubProvider) GetLocRec(ctx context.Context, tenantID string, id int64) (ports.LocRecResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.LocRecResult{}, err
	}
	if id <= 0 {
		return ports.LocRecResult{}, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, ok := s.locRecs[key(tenantID, strconv.FormatInt(id, 10))]
	if !ok {
		return ports.LocRecResult{}, shared.ErrNotFound
	}
	return res, nil
}

// UnlinkLocRec detaches the mandate from a location. Idempotent: unlinking a location
// that is already free succeeds and returns it.
func (s *StubProvider) UnlinkLocRec(ctx context.Context, tenantID string, id int64) (ports.LocRecResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.LocRecResult{}, err
	}
	if id <= 0 {
		return ports.LocRecResult{}, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(tenantID, strconv.FormatInt(id, 10))
	res, ok := s.locRecs[k]
	if !ok {
		return ports.LocRecResult{}, shared.ErrNotFound
	}
	res.IDRec = ""
	s.locRecs[k] = res
	return res, nil
}

// GetRec returns the authoritative mandate state for reconciliation.
func (s *StubProvider) GetRec(ctx context.Context, tenantID, idRec string) (ports.RecResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.RecResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, ok := s.recs[key(tenantID, idRec)]
	if !ok {
		return ports.RecResult{}, shared.ErrNotFound
	}
	return res, nil
}

// ApproveRec simulates the OUT-OF-BAND approval: in the real journey the payer
// authorizes the mandate inside their own bank's app, and the PSP then reports it as
// APROVADA. Nothing in our API can cause that, which is exactly why it needs to be
// expressible against the stub — without it no stub-mode run (dev, tests, the smoke
// runbook) could ever reach a chargeable mandate, and the whole recurring-charge half
// of the product would be unreachable outside production.
//
// It moves the stub's view only. The durable mandate still changes only through the
// reconciled webhook, so a caller cannot use this to skip the reconcile step.
func (s *StubProvider) ApproveRec(ctx context.Context, tenantID, idRec string) (ports.RecResult, error) {
	return s.setRecStatus(ctx, tenantID, idRec, ports.RecAprovada)
}

// SetRecStatus moves the stub's view of a mandate to any lifecycle status, so a test
// can exercise the rejected/expired paths as well as approval.
func (s *StubProvider) SetRecStatus(ctx context.Context, tenantID, idRec string, status ports.RecStatus) (ports.RecResult, error) {
	return s.setRecStatus(ctx, tenantID, idRec, status)
}

func (s *StubProvider) setRecStatus(ctx context.Context, tenantID, idRec string, status ports.RecStatus) (ports.RecResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.RecResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(tenantID, idRec)
	res, ok := s.recs[k]
	if !ok {
		return ports.RecResult{}, shared.ErrNotFound
	}
	res.Status = status
	if status == ports.RecAprovada && s.recJornadaTxID[k] != "" {
		// A mandate approved through the composite QR records WHICH journey carried the
		// authorization, mirroring the real ativacao.tipoJornada.
		res.TipoJornada = "JORNADA_3"
	}
	s.recs[k] = res
	return res, nil
}

// CancelRec revokes a mandate. Idempotent: a second cancel of an already-cancelled
// mandate succeeds and returns the cancelled state.
func (s *StubProvider) CancelRec(ctx context.Context, tenantID, idRec string) (ports.RecResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.RecResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(tenantID, idRec)
	res, ok := s.recs[k]
	if !ok {
		return ports.RecResult{}, shared.ErrNotFound
	}
	res.Status = ports.RecCancelada
	s.recs[k] = res
	return res, nil
}

// CreateSolicRec registers a recurrence-activation request deterministically; a
// repeat call for the same anchor returns the existing request.
func (s *StubProvider) CreateSolicRec(ctx context.Context, tenantID string, req ports.CreateSolicRecRequest) (ports.SolicRecResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.SolicRecResult{}, err
	}
	if req.IDRec == "" || req.ExpiraEm.IsZero() {
		return ports.SolicRecResult{}, shared.ErrValidation
	}
	seed := req.IdempotencyKey
	if seed == "" {
		seed = tenantID + "\x00" + req.IDRec
	}
	idSolicRec := stubRecID("SC", seed)
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(tenantID, idSolicRec)
	if prev, ok := s.solicRecs[k]; ok {
		return prev, nil
	}
	res := ports.SolicRecResult{
		IDSolicRec:   idSolicRec,
		IDRec:        req.IDRec,
		Status:       "CRIADA",
		Destinatario: req.Destinatario,
		ExpiraEm:     req.ExpiraEm,
	}
	s.solicRecs[k] = res
	return res, nil
}

// GetSolicRec returns the authoritative activation-request state.
func (s *StubProvider) GetSolicRec(ctx context.Context, tenantID, idSolicRec string) (ports.SolicRecResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.SolicRecResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, ok := s.solicRecs[key(tenantID, idSolicRec)]
	if !ok {
		return ports.SolicRecResult{}, shared.ErrNotFound
	}
	return res, nil
}

// CreateCobR creates a recurring charge instance anchored by its txid. Idempotent:
// a repeat create with the same txid returns the existing charge (anti-double-bill).
func (s *StubProvider) CreateCobR(ctx context.Context, tenantID string, req ports.CreateCobRRequest) (ports.CobRResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.CobRResult{}, err
	}
	if req.TxID == "" || req.IDRec == "" || req.ValorCents <= 0 {
		return ports.CobRResult{}, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(tenantID, req.TxID)
	if prev, ok := s.cobrs[k]; ok {
		return prev, nil
	}
	res := ports.CobRResult{
		TxID:       req.TxID,
		IDRec:      req.IDRec,
		Status:     "CRIADA",
		ValorCents: req.ValorCents,
	}
	s.cobrs[k] = res
	return res, nil
}

// GetCobR returns the authoritative charge state for reconciliation.
func (s *StubProvider) GetCobR(ctx context.Context, tenantID, txID string) (ports.CobRResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.CobRResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, ok := s.cobrs[key(tenantID, txID)]
	if !ok {
		return ports.CobRResult{}, shared.ErrNotFound
	}
	return res, nil
}

// CancelCobR cancels one scheduled charge instance. The charge must exist; cancelling
// an already-cancelled one is a no-op that returns the cancelled state (idempotent).
func (s *StubProvider) CancelCobR(ctx context.Context, tenantID, txID string) (ports.CobRResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.CobRResult{}, err
	}
	if strings.TrimSpace(txID) == "" {
		return ports.CobRResult{}, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(tenantID, txID)
	res, ok := s.cobrs[k]
	if !ok {
		return ports.CobRResult{}, shared.ErrNotFound
	}
	res.Status = "CANCELADA"
	s.cobrs[k] = res
	return res, nil
}

// RetryCobR schedules a retry of a failed charge. The charge must exist.
func (s *StubProvider) RetryCobR(ctx context.Context, tenantID, txID, dataRetentativa string) (ports.CobRResult, error) {
	if _, err := s.creds.GetBankCredential(ctx, tenantID, s.bankID); err != nil {
		return ports.CobRResult{}, err
	}
	if txID == "" || dataRetentativa == "" {
		return ports.CobRResult{}, shared.ErrValidation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, ok := s.cobrs[key(tenantID, txID)]
	if !ok {
		return ports.CobRResult{}, shared.ErrNotFound
	}
	return res, nil
}
