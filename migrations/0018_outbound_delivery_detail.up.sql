-- 0018_outbound_delivery_detail.up.sql — carry the settlement DETAIL on a Conta's
-- outbound delivery so the forwarded webhook tells the empresa what actually settled
-- (SIN-69580, extends 0015 / F1-F2 of SIN-69486).
--
-- WHY: the forwarded envelope carried only routing fields (event_key, event_type,
-- tx_id, account_id, timestamp), so a reseller learned THAT something settled but not
-- for how much, in how many parcelas, or what the PSP said about the capture — it had
-- to call our API back for every event. A card checkout in particular is settled in
-- installments the empresa needs to reconcile against.
--
-- CENTS, NEVER REAIS: amount_cents is integer minor units. The PSP reports checkout
-- amounts as decimal reais on the wire ("amount": 5.01); the adapter parses those to
-- integer cents by string (never a float), and cents is the only representation that
-- crosses this boundary or leaves it. There is no decimal column here by design — a
-- rounding difference in an amount is a money bug.
--
-- STILL NOT ENCRYPTED, and still not a PII surface (the property 0015 relies on): an
-- amount, an installment count and a PSP status message ("Transacao capturada com
-- sucesso") identify no natural person. The devedor PII a Pix payload can carry
-- (sin-68744) is still deliberately absent, so this stays outside the sealed tables.
--
-- Backfill: the three columns are nullable/defaulted, so rows written before this
-- migration read back as zero/empty and forward exactly as they do today. Existing
-- deliveries are NOT rewritten.
--
-- Reversibility: purely additive (three ADD COLUMNs); 0018_*.down.sql rebuilds the
-- table without them. Touches no other table.
--
-- Portability (same conventions as 0001..0017): INTEGER minor units, TEXT message.

ALTER TABLE account_outbound_delivery ADD COLUMN amount_cents INTEGER NOT NULL DEFAULT 0;
ALTER TABLE account_outbound_delivery ADD COLUMN installments INTEGER NOT NULL DEFAULT 0;
ALTER TABLE account_outbound_delivery ADD COLUMN message      TEXT    NOT NULL DEFAULT '';
