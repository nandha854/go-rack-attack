package rackattack

import (
	"context"
	"math"
	"net/http"
	"strconv"
)

// reasonContextKey is the type used to stash the deny Decision in the request
// context so a custom denied-handler can inspect it.
type reasonContextKey struct{}

// DecisionFromContext returns the Decision that caused a request to be denied,
// for use inside a handler registered via WithDeniedHandler. The second return
// value is false if no decision is present.
func DecisionFromContext(req *http.Request) (Decision, bool) {
	d, ok := req.Context().Value(reasonContextKey{}).(Decision)
	return d, ok
}

// Middleware wraps next with request filtering. Allowed requests pass through;
// denied requests are handled by the configured denied-handler (default:
// 403 for blocklist/ban, 429 with Retry-After for throttle). On a store error,
// behavior follows the fail-open/fail-closed policy.
func (ra *RedisRackAttack) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		decision, err := ra.Check(req)
		if err != nil {
			if ra.onError != nil {
				ra.onError(req, err)
			}
			if ra.failClosed {
				http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
				return
			}
			next.ServeHTTP(w, req)
			return
		}

		if decision.Allowed {
			next.ServeHTTP(w, req)
			return
		}

		req = req.WithContext(context.WithValue(req.Context(), reasonContextKey{}, decision))
		ra.onDenied(w, req)
	})
}

// defaultDeniedHandler writes a sensible default response based on the deny
// reason. Throttle denials include RateLimit-* and Retry-After headers.
func defaultDeniedHandler(w http.ResponseWriter, req *http.Request) {
	decision, ok := DecisionFromContext(req)
	if !ok {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	switch decision.Reason {
	case ReasonThrottled:
		setRateLimitHeaders(w, decision.Throttle)
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
	default:
		// Blocklisted or banned.
		http.Error(w, "Forbidden", http.StatusForbidden)
	}
}

// setRateLimitHeaders emits the de-facto RateLimit-* headers and Retry-After.
func setRateLimitHeaders(w http.ResponseWriter, res Result) {
	h := w.Header()
	h.Set("RateLimit-Limit", strconv.Itoa(res.Limit))
	h.Set("RateLimit-Remaining", strconv.Itoa(res.Remaining))
	if res.RetryAfter > 0 {
		seconds := max(int(math.Ceil(res.RetryAfter.Seconds())), 1)
		h.Set("Retry-After", strconv.Itoa(seconds))
		h.Set("RateLimit-Reset", strconv.Itoa(seconds))
	}
}
