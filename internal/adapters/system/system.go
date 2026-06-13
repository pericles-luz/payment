// Package system provides small adapters for the Clock and IDProvider ports
// backed by the host (wall clock and a crypto-random, non-sequential id).
package system

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// Clock implements ports.Clock using the wall clock in UTC.
type Clock struct{}

// Now returns the current UTC time.
func (Clock) Now() time.Time { return time.Now().UTC() }

// IDProvider implements ports.IDProvider with a 128-bit crypto-random id,
// rendered as hex. Non-sequential by construction (anti-enumeration, threat H5).
type IDProvider struct{}

// randRead is the entropy source, indirected for testability.
var randRead = rand.Read

// NewID returns a new random identifier. It panics only if the system CSPRNG
// fails, which is an unrecoverable condition.
func (IDProvider) NewID() string {
	var b [16]byte
	if _, err := randRead(b[:]); err != nil {
		panic("system: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
