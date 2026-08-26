package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/ia-dev-sindireceita/payment/internal/domain/outboundqueue"
)

// OutboundDeliveryStore is the durable implementation of the F1 inbound→Conta
// attribution outbox (SIN-69491, F1 of SIN-69486). It backs two tables (migration
// 0015): account_outbound_delivery (the per-Conta outbox F2 forwards from) and
// account_outbound_dead_letter (the park for events whose owning Conta could not be
// determined). It satisfies the app-layer app.OutboundDeliveryQueue and
// app.DeadLetterSink ports.
//
// SECURITY: unlike the F0 config store, nothing here is a secret or PII, so nothing is
// sealed — the rows hold only internal opaque ids, the dedup event_key, a constant
// event_type and a classified reason (see migration 0015 for the rationale). Writes are
// idempotent: a redelivered inbound event collides on the unique (account_id,event_key)
// / (tenant_id,event_key) index and ON CONFLICT DO NOTHING makes it a silent no-op, so
// the same event never enqueues a duplicate forward (dedup reuses event_key).
type OutboundDeliveryStore struct {
	db *sql.DB
}

// NewOutboundDeliveryStore wraps a database handle. No cipher is needed (no secret at
// rest), so the constructor is intentionally minimal.
func NewOutboundDeliveryStore(db *sql.DB) *OutboundDeliveryStore {
	return &OutboundDeliveryStore{db: db}
}

// EnqueueDelivery persists an attributed Delivery on its Conta's outbox. It is
// idempotent on (account_id, event_key): a duplicate inbound event is a no-op (ON
// CONFLICT DO NOTHING), so a bank redelivery never double-enqueues a forward.
func (s *OutboundDeliveryStore) EnqueueDelivery(ctx context.Context, d *outboundqueue.Delivery) error {
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO account_outbound_delivery
		     (id, account_id, tenant_id, event_key, tx_id, event_type, status, created_at,
		      amount_cents, installments, message)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		 ON CONFLICT (account_id, event_key) DO NOTHING`,
		d.ID(), d.AccountID(), d.TenantID(), d.EventKey(), d.TxID(), d.EventType(),
		string(d.Status()), d.CreatedAt().UTC().Format(tsLayout),
		d.Detail().AmountCents, d.Detail().Installments, d.Detail().Message); err != nil {
		return fmt.Errorf("enqueue outbound delivery: %w", err)
	}
	return nil
}

// DeadLetter parks an unattributable inbound event for inspection/replay. It is
// idempotent on (tenant_id, event_key): a duplicate is a no-op (ON CONFLICT DO NOTHING).
func (s *OutboundDeliveryStore) DeadLetter(ctx context.Context, dl *outboundqueue.DeadLetter) error {
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO account_outbound_dead_letter
		     (id, tenant_id, event_key, tx_id, event_type, reason, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (tenant_id, event_key) DO NOTHING`,
		dl.ID(), dl.TenantID(), dl.EventKey(), dl.TxID(), dl.EventType(),
		string(dl.Reason()), dl.CreatedAt().UTC().Format(tsLayout)); err != nil {
		return fmt.Errorf("dead-letter outbound event: %w", err)
	}
	return nil
}

// PendingDeliveries returns a Conta's queued (pending) outbox deliveries, oldest first
// — the read F2 consumes and an operator inspects. It is account-scoped (A01): it
// returns only the given Conta's rows.
func (s *OutboundDeliveryStore) PendingDeliveries(ctx context.Context, accountID string) ([]*outboundqueue.Delivery, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, account_id, tenant_id, event_key, tx_id, event_type, status, created_at,
		        amount_cents, installments, message
		   FROM account_outbound_delivery
		  WHERE account_id = $1 AND status = $2
		  ORDER BY created_at ASC, id ASC`,
		accountID, string(outboundqueue.StatusPending))
	if err != nil {
		return nil, fmt.Errorf("query pending deliveries: %w", err)
	}
	defer rows.Close()

	var out []*outboundqueue.Delivery
	for rows.Next() {
		var id, acct, tenantID, eventKey, txID, eventType, status, createdAt, message string
		var amountCents int64
		var installments int
		if err := rows.Scan(&id, &acct, &tenantID, &eventKey, &txID, &eventType, &status, &createdAt,
			&amountCents, &installments, &message); err != nil {
			return nil, fmt.Errorf("scan pending delivery: %w", err)
		}
		out = append(out, outboundqueue.RehydrateDelivery(
			id, acct, tenantID, eventKey, txID, eventType,
			outboundqueue.DeliveryStatus(status), parseTime(createdAt),
			outboundqueue.Detail{AmountCents: amountCents, Installments: installments, Message: message}))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pending deliveries: %w", err)
	}
	return out, nil
}

// ClaimPendingDeliveries returns up to limit pending outbox deliveries ACROSS all Contas,
// oldest first — the batch F2's processor forwards on each tick. It is the cross-account
// consumer read (contrast the account-scoped PendingDeliveries used for inspection); A01
// is preserved downstream because the processor loads each Conta's endpoint by the row's
// own account_id, never crosses it. A non-positive limit yields an empty batch.
//
// It "claims" nothing, despite the name, and the query is deliberately identical to the
// sqlite adapter's. FOR UPDATE SKIP LOCKED — the obvious fix — cannot work behind this
// port signature: the method returns rows and the caller then makes an HTTP call before
// DeleteDelivery, so any row lock this statement takes is released by the implicit
// transaction the moment the method returns, long before the forward happens. It would
// read as solved while excluding nothing.
//
// A real claim needs a lease the row carries: a claimed_at column, a claimed status, and
// a reclaim clause (status = 'claimed' AND claimed_at < now - lease) so a forwarder that
// dies mid-flight does not strand the delivery. That is a schema plus domain change, not
// a persistence port, so it belongs with the work that actually makes a second instance
// possible — the in-process rate limiters and caches (internal/adapters/outbound/limiter.go,
// internal/app/consoleauth.go) rule one out today regardless.
//
// Until then this is safe for exactly the reason it is safe under sqlite: one process,
// one ticker (cmd/api/main.go). Running two API instances against one database WILL
// deliver some webhooks twice.
func (s *OutboundDeliveryStore) ClaimPendingDeliveries(ctx context.Context, limit int) ([]*outboundqueue.Delivery, error) {
	if limit <= 0 {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, account_id, tenant_id, event_key, tx_id, event_type, status, created_at,
		        amount_cents, installments, message
		   FROM account_outbound_delivery
		  WHERE status = $1
		  ORDER BY created_at ASC, id ASC
		  LIMIT $2`,
		string(outboundqueue.StatusPending), limit)
	if err != nil {
		return nil, fmt.Errorf("claim pending deliveries: %w", err)
	}
	defer rows.Close()

	var out []*outboundqueue.Delivery
	for rows.Next() {
		var id, acct, tenantID, eventKey, txID, eventType, status, createdAt, message string
		var amountCents int64
		var installments int
		if err := rows.Scan(&id, &acct, &tenantID, &eventKey, &txID, &eventType, &status, &createdAt,
			&amountCents, &installments, &message); err != nil {
			return nil, fmt.Errorf("scan pending delivery: %w", err)
		}
		out = append(out, outboundqueue.RehydrateDelivery(
			id, acct, tenantID, eventKey, txID, eventType,
			outboundqueue.DeliveryStatus(status), parseTime(createdAt),
			outboundqueue.Detail{AmountCents: amountCents, Installments: installments, Message: message}))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pending deliveries: %w", err)
	}
	return out, nil
}

// DeleteDelivery removes a delivery from the outbox by id — the terminal step F2 takes
// once a delivery is settled (forwarded 2xx, or given up and dead-lettered). The outbox
// is a work queue, so a settled row leaves it; the audit trail (delivered / dead_letter)
// is the durable record of the outcome. It is idempotent: deleting an absent id is a
// no-op.
func (s *OutboundDeliveryStore) DeleteDelivery(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM account_outbound_delivery WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete outbound delivery: %w", err)
	}
	return nil
}

// DeadLetters returns all parked dead-letters, oldest first, for operator inspection /
// replay. The park has no Conta owner by definition, so it is not account-scoped.
func (s *OutboundDeliveryStore) DeadLetters(ctx context.Context) ([]*outboundqueue.DeadLetter, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, tenant_id, event_key, tx_id, event_type, reason, created_at
		   FROM account_outbound_dead_letter
		  ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("query dead-letters: %w", err)
	}
	defer rows.Close()

	var out []*outboundqueue.DeadLetter
	for rows.Next() {
		var id, tenantID, eventKey, txID, eventType, reason, createdAt string
		if err := rows.Scan(&id, &tenantID, &eventKey, &txID, &eventType, &reason, &createdAt); err != nil {
			return nil, fmt.Errorf("scan dead-letter: %w", err)
		}
		out = append(out, outboundqueue.RehydrateDeadLetter(
			id, tenantID, eventKey, txID, eventType,
			outboundqueue.Reason(reason), parseTime(createdAt)))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate dead-letters: %w", err)
	}
	return out, nil
}
