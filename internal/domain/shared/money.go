package shared

import "regexp"

// currencyRe matches an ISO-4217 alphabetic currency code (3 uppercase letters).
var currencyRe = regexp.MustCompile(`^[A-Z]{3}$`)

// Money is a value object representing a non-negative monetary amount in the
// smallest currency unit (cents). It is immutable once constructed.
type Money struct {
	cents    int64
	currency string
}

// NewMoney builds a Money, enforcing the invariant that the amount is positive
// and the currency is a valid ISO-4217 code.
func NewMoney(cents int64, currency string) (Money, error) {
	if cents <= 0 {
		return Money{}, NewValidationError("amount", "must be greater than zero")
	}
	if !currencyRe.MatchString(currency) {
		return Money{}, NewValidationError("currency", "must be a 3-letter ISO-4217 code")
	}
	return Money{cents: cents, currency: currency}, nil
}

// Cents returns the amount in the smallest currency unit.
func (m Money) Cents() int64 { return m.cents }

// Currency returns the ISO-4217 currency code.
func (m Money) Currency() string { return m.currency }

// IsZero reports whether the Money is the zero value (uninitialised).
func (m Money) IsZero() bool { return m.cents == 0 && m.currency == "" }
