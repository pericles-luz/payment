package shared

import (
	"math"
	"regexp"
)

// currencyRe matches an ISO-4217 alphabetic currency code (3 uppercase letters).
var currencyRe = regexp.MustCompile(`^[A-Z]{3}$`)

// AddCents returns a+b in cents, rejecting an int64 overflow as a validation
// error instead of silently wrapping. Accumulating item amounts with a bare
// `sum += amount` lets a set of individually-valid positive items wrap past
// math.MaxInt64 into a small (still positive) value that slips through
// NewMoney's `<= 0` guard, yielding a wrong reserved/displayed total. Fold a
// sum through AddCents so any wrap is caught at the boundary. The check is
// symmetric so it is also safe for any future signed (e.g. credit) line.
func AddCents(a, b int64) (int64, error) {
	if (b > 0 && a > math.MaxInt64-b) || (b < 0 && a < math.MinInt64-b) {
		return 0, NewValidationError("amount", "item amount sum overflows int64")
	}
	return a + b, nil
}

// SumCents folds the given amounts through AddCents, returning the total or the
// first overflow as a validation error. The empty sum is zero.
func SumCents(amounts ...int64) (int64, error) {
	var sum int64
	for _, a := range amounts {
		next, err := AddCents(sum, a)
		if err != nil {
			return 0, err
		}
		sum = next
	}
	return sum, nil
}

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
