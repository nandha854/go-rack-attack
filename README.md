# Go Rack::Attack

A Go implementation of the **Rack::Attack** gem, designed to protect your HTTP services from abusive requests. This library provides **rate limiting**, **IP safelisting/blocklisting**, and **request throttling** with Redis-backed storage.

---

## Features

- **Rate Limiting**: Throttle requests by IP, endpoint, or custom keys.
- **IP Safelisting/Blocklisting**: Allow or block specific IPs or CIDR ranges.
- **Redis Backend**: Scalable and distributed rate limiting using Redis.
- **Middleware Support**: Works with `net/http`, `chi`, `gin`, and `echo`.
- **Custom Rules**: Define URL-specific or global rate limits.
- **Path Pattern Matching**: Supports wildcard patterns for paths.
- **HTTP Method Filtering**: Apply rules based on HTTP methods.

---

## Installation

```bash
go get github.com/nandha854/go-rack-attack
```

---

## Usage

### Basic Setup

```go
package main

import (
	"net/http"
	"time"
	"github.com/nandha854/go-rack-attack/rackattack"
	"github.com/redis/go-redis/v9"
)

func main() {
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	ra := rackattack.New(client)

	// Add a throttle rule
	ra.AddThrottleRule(rackattack.ThrottleRule{
		PathPattern: "/api/*",
		Method:      "POST",
		Key:         "ratelimit:%{ip}:%{path}",
		Limit:       100,
		Period:      time.Hour,
	})

	// Safelist IPs
	ra.SafelistIP("127.0.0.1")

	// Block IPs or CIDR ranges
	ra.BlocklistIP("10.0.0.1")
	ra.BlocklistCIDR("10.0.0.0/24")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		isThrottled, err := ra.IsThrottled(r)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if isThrottled {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		w.Write([]byte("Hello, World!"))
	})

	http.ListenAndServe(":8080", nil)
}
```

