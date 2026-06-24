# go-rack-attack

[![Go Reference](https://pkg.go.dev/badge/github.com/nandha854/go-rack-attack.svg)](https://pkg.go.dev/github.com/nandha854/go-rack-attack)
[![CI](https://github.com/nandha854/go-rack-attack/actions/workflows/ci.yml/badge.svg)](https://github.com/nandha854/go-rack-attack/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE.txt)

A Go port of Ruby's [**Rack::Attack**](https://github.com/rack/rack-attack): request-filtering
middleware that protects HTTP services from abusive traffic. It layers four
policies — **safelist**, **blocklist**, **Fail2Ban**, and **throttling** — over
a pluggable store, with a Redis backend included.

---

## Why this and not a plain rate limiter?

Most Go rate limiters (`ulule/limiter`, `throttled`, `redis_rate`) do throttling
only. `go-rack-attack` brings Rack::Attack's full **request-filtering** model to
Go in one package:

- **Layered policy** evaluated in precedence order: safelist → blocklist → Fail2Ban → throttle.
- **Fail2Ban / Allow2Ban** — automatically ban clients that repeatedly misbehave (e.g. failed logins).
- **Safe-by-default client IP** — `X-Forwarded-For` is trusted *only* when the request arrives through a proxy you declare trusted, closing the most common rate-limit-bypass hole.
- **CIDR** safelisting and blocklisting.
- **Atomic Redis operations** via Lua — sliding-window limiter and ban engine, no INCR/EXPIRE races.
- **Drop-in `http.Handler` middleware** with `429` + `Retry-After` / `RateLimit-*` headers.
- **Concurrency-safe** — rules and lists can be updated while serving (`go test -race` clean).

---

## Installation

```bash
go get github.com/nandha854/go-rack-attack
```

Requires Go 1.23+ and a Redis 3.2+ server (for the bundled `RedisStore`).

---

## Quick start

```go
package main

import (
	"log"
	"net/http"
	"time"

	"github.com/nandha854/go-rack-attack/rackattack"
	"github.com/redis/go-redis/v9"
)

func main() {
	client := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	store := rackattack.NewRedisStore(client, "rackattack:")

	ra, err := rackattack.New(store,
		// Honor X-Forwarded-For only from your load balancer's subnet.
		rackattack.WithTrustedProxies("10.0.0.0/8"),
	)
	if err != nil {
		log.Fatal(err)
	}

	ra.SafelistIP("127.0.0.1")
	ra.BlocklistCIDR("192.0.2.0/24")

	ra.Throttle(rackattack.ThrottleRule{
		PathPattern: "/api/*",
		Method:      "POST",
		Key:         "api:%{ip}",
		Limit:       100,
		Period:      time.Hour,
	})

	ra.Fail2Ban(rackattack.Fail2BanRule{
		Name:        "login",
		PathPattern: "/login",
		Method:      "POST",
		MaxRetry:    5,
		FindTime:    time.Minute,
		BanTime:     time.Hour,
		// Count an offense whenever the wrapped handler signals a failed login.
		Trigger: func(r *http.Request) bool {
			return r.Header.Get("X-Login-Failed") == "1"
		},
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("Hello, World!"))
	})

	// Wrap your handler — denied requests never reach it.
	log.Fatal(http.ListenAndServe(":8080", ra.Middleware(mux)))
}
```

---

## The client-IP trust model (read this)

Rate limiting and IP blocking are only as trustworthy as the IP you key on.
`X-Forwarded-For` is an arbitrary, client-supplied header — trusting it blindly
lets anyone spoof a safelisted IP or evade per-IP limits.

`go-rack-attack` defaults to the **connection peer** (`req.RemoteAddr`) and
ignores forwarding headers. Enable header parsing only when you terminate TLS
behind a proxy you control:

```go
// X-Forwarded-For is honored only when the peer is inside one of these ranges.
// The client IP is the right-most address in the chain that is NOT a trusted
// proxy.
rackattack.New(store, rackattack.WithTrustedProxies("10.0.0.0/8", "172.16.0.0/12"))
```

For platforms that set a verified header (e.g. a cloud LB's `True-Client-IP`),
override resolution entirely — you own the trust decision here:

```go
rackattack.New(store, rackattack.WithClientIPFunc(func(r *http.Request) string {
	return r.Header.Get("True-Client-IP")
}))
```

---

## Policies

### Throttling

A `ThrottleRule` rate-limits matching requests using a **sliding-window log**
(no boundary bursts). The `Key` template supports `%{ip}` and `%{path}`.

| Field | Meaning |
|---|---|
| `PathPattern` | Path glob. `""` = all. `"/api/*"` matches the subtree. `"/api/v*/x"` uses `path.Match` semantics. |
| `Method` | HTTP method, case-insensitive. `""` = all. |
| `Key` | Redis key template, e.g. `"login:%{ip}"`. |
| `Limit` | Max requests per window. |
| `Period` | Window length. |

### Safelist / Blocklist

```go
ra.SafelistIP("203.0.113.9")
ra.SafelistCIDR("10.0.0.0/8")
ra.BlocklistIP("198.51.100.4")
ra.BlocklistCIDR("192.0.2.0/24")
```

Safelist matches short-circuit everything else.

### Fail2Ban

Count offenses per client; after `MaxRetry` offenses within `FindTime`, the
client is banned for `BanTime`. `Trigger` decides what counts as an offense
(nil = every matching request, useful for known-bad paths).

---

## Using `Check` directly

If you don't want the bundled middleware, call `Check` and act on the
`Decision` yourself:

```go
d, err := ra.Check(r)
if err != nil {
	// store unavailable — default policy is fail-open
}
if !d.Allowed {
	switch d.Reason {
	case rackattack.ReasonThrottled:
		http.Error(w, "slow down", http.StatusTooManyRequests)
	default:
		http.Error(w, "forbidden", http.StatusForbidden)
	}
	return
}
```

The legacy `IsThrottled(req) (bool, error)` helper is retained as a thin wrapper
over `Check`.

---

## Options

| Option | Effect |
|---|---|
| `WithTrustedProxies(cidrs...)` | Honor `X-Forwarded-For` only behind these proxy ranges. |
| `WithClientIPFunc(fn)` | Fully custom client-IP resolution. |
| `WithDeniedHandler(h)` | Custom response for denied requests. |
| `WithErrorHandler(fn)` | Callback on store errors (logging/metrics). |
| `WithFailClosed()` | Deny (503) on store errors instead of failing open. |

---

## Custom stores

Implement the `Store` interface (`Throttle`, `Strike`, `Banned`) to back the
filter with something other than Redis (in-memory, Memcached, etc.).

---

## License

Distributed under the MIT License. See [LICENSE](./LICENSE.txt).

## Acknowledgements

Inspired by [Rack::Attack](https://github.com/rack/rack-attack) and built on
[go-redis](https://github.com/redis/go-redis).
