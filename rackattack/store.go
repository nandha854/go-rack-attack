package rackattack

import (
	"context"
	"time"
)

// Result describes the outcome of a throttle check against the store.
type Result struct {
	// Limited reports whether this request exceeded the configured limit.
	Limited bool
	// Limit is the configured maximum for the matched rule.
	Limit int
	// Remaining is the number of requests still permitted in the current
	// window. Zero when Limited is true.
	Remaining int
	// RetryAfter is how long the caller should wait before the window has
	// room again. Only meaningful when Limited is true.
	RetryAfter time.Duration
}

// Store is the persistence backend for throttling and ban tracking. A Store
// must be safe for concurrent use; all methods are called on the request hot
// path from multiple goroutines.
type Store interface {
	// Throttle records a hit against key within a sliding window of period and
	// reports whether the caller is now over limit.
	Throttle(ctx context.Context, key string, limit int, period time.Duration) (Result, error)

	// Strike records an offense against key. Once maxRetry offenses accumulate
	// within findTime, key is banned for banTime. It returns true when key is
	// currently banned (either because this call triggered the ban or because a
	// ban was already in effect).
	Strike(ctx context.Context, key string, maxRetry int, findTime, banTime time.Duration) (bool, error)

	// Banned reports whether key is currently banned, without recording an
	// offense.
	Banned(ctx context.Context, key string) (bool, error)
}
