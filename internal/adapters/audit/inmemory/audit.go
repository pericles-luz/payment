// Package inmemory is an append-only, concurrency-safe implementation of the
// ports.AuditLog port. It backs the foundation and tests; a persisted adapter
// (Postgres/append-only table) is a drop-in replacement with the same contract.
// Entries are immutable (audit.Entry has no setters) and the log never exposes
// its backing slice directly, so a recorded action cannot be altered or removed.
package inmemory

import (
	"context"
	"sync"

	"github.com/ia-dev-sindireceita/payment/internal/domain/audit"
	"github.com/ia-dev-sindireceita/payment/internal/ports"
)

// Log is an in-memory append-only audit trail.
type Log struct {
	mu      sync.RWMutex
	entries []audit.Entry
}

var _ ports.AuditLog = (*Log)(nil)

// NewLog returns an empty audit log.
func NewLog() *Log { return &Log{} }

// Append records an audit entry. It is append-only: entries are never updated or
// removed.
func (l *Log) Append(_ context.Context, e audit.Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, e)
	return nil
}

// Entries returns a copy of the recorded entries in append order. A copy is
// returned so callers can never mutate the underlying trail.
func (l *Log) Entries() []audit.Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]audit.Entry, len(l.entries))
	copy(out, l.entries)
	return out
}

// Len returns the number of recorded entries.
func (l *Log) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.entries)
}
