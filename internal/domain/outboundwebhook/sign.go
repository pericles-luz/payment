package outboundwebhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// sign.go is the pure signing half of the outbound webhook domain (SIN-69492, F2 of
// SIN-69486). It computes the per-Conta HMAC that lets a receiver prove a POST really
// came from us and was not forged or replayed (threat model SIN-69489 §5, threats
// S2/E2). It is pure crypto over the standard library — no I/O, no adapter concern —
// so the actual network forward stays entirely in the outbound adapter (hexagonal).
//
// Design (SIN-69489 §5, non-negotiable):
//   - Algorithm is FIXED to HMAC-SHA256. It is never negotiated in the wire header, so
//     there is no algorithm-confusion surface (no "alg" a receiver could be tricked
//     into downgrading). It is a symmetric MAC — the right primitive for a secret both
//     we and the Conta hold — not an asymmetric signature.
//   - The MAC covers timestamp || "." || raw_body: the EXACT bytes we transmit plus the
//     timestamp, bound together. Signing the raw body (not a re-serialisation) closes
//     any parser-differential between what we sign and what we send; binding the
//     timestamp into the MAC is the anti-replay control — a captured body replayed with
//     a fresh timestamp changes the MAC, so the receiver's timestamp-window check and
//     the signature check reinforce each other.
//   - The secret never leaves this computation: it is an HMAC key, never emitted, never
//     placed in a URL, never logged (Config.LogValue redacts it).

const (
	// SignatureHeader carries the hex HMAC-SHA256 of the signed content, prefixed with
	// the fixed algorithm tag so a receiver library can assert the algorithm without a
	// negotiable field: `sha256=<hex>`.
	SignatureHeader = "X-Webhook-Signature"

	// TimestampHeader carries the unix-seconds timestamp that is bound into the MAC.
	// The receiver rejects a delivery whose timestamp is outside its freshness window
	// (recommended 300s), which — together with the timestamp being part of the signed
	// content — defeats replay of a captured body (threat E2).
	TimestampHeader = "X-Webhook-Timestamp"

	// IdempotencyHeader lets the receiver dedup a redelivered event (a bounded retry or
	// a bank redelivery can cause the same event_key to be forwarded more than once).
	// It carries the inbound event_key, which is a stable, non-secret dedup identifier.
	IdempotencyHeader = "X-Webhook-Idempotency-Key"

	// sigPrefix is the fixed algorithm tag on the signature value. It is not negotiable
	// (only sha256 is ever produced), so it documents the algorithm without offering a
	// downgrade knob.
	sigPrefix = "sha256="
)

// Sign computes the outbound delivery signature: sigPrefix + hex(HMAC-SHA256(secret,
// "<timestampUnix>.<body>")). The timestamp is bound into the MAC so a replay with a
// new timestamp fails verification. It is a pure function of its inputs — deterministic,
// no I/O — so it is trivially testable and can be reused by a receiver reference impl.
func Sign(secret string, timestampUnix int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	// signedContent = timestamp || "." || body, written incrementally to avoid an
	// intermediate copy of the (potentially large) body.
	mac.Write([]byte(strconv.FormatInt(timestampUnix, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return sigPrefix + hex.EncodeToString(mac.Sum(nil))
}

// Sign computes this Config's signature over (timestampUnix, body) using its transient
// plaintext signing secret. It is a thin method over the package Sign so the caller
// (the F2 forwarder) never has to touch the raw secret — it hands the Config the bytes
// to sign and gets back the header value.
func (c *Config) Sign(timestampUnix int64, body []byte) string {
	return Sign(c.signingSecret, timestampUnix, body)
}
