package consoleauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP is RFC 6238 (time-based one-time password) over HMAC-SHA1, 6 digits, a
// 30-second step — the parameters every authenticator app (Google Authenticator,
// Authy, 1Password, …) defaults to, so the otpauth URI provisions without extra
// configuration. Verification allows ±1 step of skew (the RFC's recommended
// tolerance) to absorb clock drift between the server and the operator's device.
//
// This package only decides whether a code matches the secret for some step in
// the window; the single-use REPLAY guard (rejecting a code already consumed in
// its window) is enforced by the app layer against a store, because it is stateful
// I/O. VerifyTOTP returns the matched step precisely so the app can persist it.
const (
	totpDigits = 6
	totpPeriod = 30 // seconds per step
	// totpSecretBytes is the shared-secret entropy: 20 bytes (160 bits), the
	// SHA-1 block-matched size RFC 4226 recommends.
	totpSecretBytes = 20
	// totpDefaultSkew is the number of steps on EACH side of the current step that
	// VerifyTOTP will accept (±1 ⇒ a 90s acceptance window centred on now).
	totpDefaultSkew = 1
)

// base32NoPad is the RFC 4648 base32 alphabet without padding — the encoding
// authenticator apps expect for the otpauth `secret` parameter.
var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret mints a fresh 160-bit TOTP shared secret encoded base32
// (no padding), ready to embed in an otpauth URI. Returns an error only if the
// system CSPRNG fails.
func GenerateTOTPSecret() (string, error) {
	b := make([]byte, totpSecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("consoleauth: read totp secret: %w", err)
	}
	return base32NoPad.EncodeToString(b), nil
}

// VerifyTOTP reports whether code is a valid TOTP for secret at now, scanning the
// current step ±totpDefaultSkew. On a match it returns that step so the caller can
// enforce single-use (reject any step ≤ the last consumed one). A malformed secret
// or a code of the wrong shape yields (0, false). The digit comparison is
// constant-time so a partially-correct code is not distinguishable by timing.
func VerifyTOTP(secret, code string, now time.Time) (step int64, ok bool) {
	return verifyTOTPSkew(secret, code, now, totpDefaultSkew)
}

// verifyTOTPSkew is VerifyTOTP with an explicit skew, kept separate so tests can
// pin the window without exporting the knob.
func verifyTOTPSkew(secret, code string, now time.Time, skew int) (int64, bool) {
	key, err := decodeSecret(secret)
	if err != nil || len(key) == 0 {
		return 0, false
	}
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0, false
	}
	current := now.Unix() / totpPeriod
	for i := -skew; i <= skew; i++ {
		s := current + int64(i)
		if s < 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(hotp(key, uint64(s))), []byte(code)) == 1 {
			return s, true
		}
	}
	return 0, false
}

// decodeSecret decodes a base32 TOTP secret, tolerant of lower-case and stray
// spaces (authenticator apps sometimes group the secret with spaces).
func decodeSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	return base32NoPad.DecodeString(s)
}

// hotp computes the RFC 4226 HOTP value for a counter and renders it zero-padded
// to totpDigits. TOTP is HOTP with counter = unix/step.
func hotp(key []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	// Dynamic truncation (RFC 4226 §5.3).
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	return fmt.Sprintf("%0*d", totpDigits, bin%1_000_000)
}

// OTPAuthURI builds the otpauth://totp provisioning URI for an authenticator app
// (rendered as a QR code / shown as text at bootstrap). It pins the same
// algorithm/digits/period this package verifies with, so a scan configures the
// device to match exactly. The secret appears in this URI — it is shown to the
// operator ONCE at bootstrap over the authenticated response and never logged.
func OTPAuthURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", totpDigits))
	q.Set("period", fmt.Sprintf("%d", totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
