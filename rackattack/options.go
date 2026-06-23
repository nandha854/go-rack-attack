package rackattack

import (
	"errors"
	"net"
	"net/http"
)

var (
	errNilStore = errors.New("rackattack: store must not be nil")
)

// Option configures a RedisRackAttack at construction time.
type Option func(*RedisRackAttack) error

// WithTrustedProxies enables X-Forwarded-For parsing, but only for requests
// whose immediate peer falls within one of the given CIDR ranges. The client
// IP is taken as the right-most address in the forwarded chain that is not
// itself a trusted proxy. Without this option, forwarding headers are ignored
// and the connection peer is always used.
func WithTrustedProxies(cidrs ...string) Option {
	return func(ra *RedisRackAttack) error {
		nets := make([]*net.IPNet, 0, len(cidrs))
		for _, c := range cidrs {
			_, n, err := net.ParseCIDR(c)
			if err != nil {
				return err
			}
			nets = append(nets, n)
		}
		ra.clientIP = trustedProxyClientIP(nets)
		return nil
	}
}

// WithClientIPFunc overrides client IP resolution entirely. Use this for
// environments where the IP comes from a known-good header set by your own
// infrastructure (e.g. a cloud load balancer's True-Client-IP). You are
// responsible for the trust model when using this.
func WithClientIPFunc(fn ClientIPFunc) Option {
	return func(ra *RedisRackAttack) error {
		if fn == nil {
			return errors.New("rackattack: client IP func must not be nil")
		}
		ra.clientIP = fn
		return nil
	}
}

// WithDeniedHandler sets the response written by Middleware when a request is
// denied. The default writes 403 for blocklist/ban and 429 (with Retry-After)
// for throttle.
func WithDeniedHandler(h http.HandlerFunc) Option {
	return func(ra *RedisRackAttack) error {
		ra.onDenied = h
		return nil
	}
}

// WithErrorHandler registers a callback invoked when the store returns an
// error during Middleware evaluation. It does not affect the allow/deny
// outcome (see WithFailClosed) but lets you log or emit metrics.
func WithErrorHandler(fn func(*http.Request, error)) Option {
	return func(ra *RedisRackAttack) error {
		ra.onError = fn
		return nil
	}
}

// WithFailClosed makes store errors deny the request (503). The default is
// fail-open: if the backing store is unavailable, requests are allowed through
// so a Redis outage does not take down the whole service.
func WithFailClosed() Option {
	return func(ra *RedisRackAttack) error {
		ra.failClosed = true
		return nil
	}
}
