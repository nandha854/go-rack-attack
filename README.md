# Go Rack::Attack

A Go implementation of the **Rack::Attack** gem, designed to protect your HTTP services from abusive requests. This library provides **rate limiting**, **IP safelisting/blocklisting**, and **request throttling** with Redis-backed storage.

---

## Features

- **Rate Limiting**: Throttle requests by IP, endpoint, or custom keys.
- **IP Safelisting/Blocklisting**: Allow or block specific IPs or CIDR ranges.
- **Redis Backend**: Scalable and distributed rate limiting using Redis.
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

## Throttle Rules

Define rate-limiting rules using the `AddThrottleRule` method. Each rule specifies:

- **PathPattern**: The URL path to match (supports wildcards like `/api/*`) and leave it as blank for applying the rule to all requests.
- **Method**: The HTTP method to apply the rule to (e.g., GET, POST) or leave it as blank for applying rule for all requests.
- **Key**: The Redis key template (e.g., `ratelimit:%{ip}:%{path}`).
- **Limit**: The maximum number of requests allowed.
- **Period**: The time window for the limit (e.g., `1 * time.Minute`).

### Example

```go
ra.AddThrottleRule(rackattack.ThrottleRule{
    PathPattern: "/login",
    Method:      "POST",
    Key:         "ratelimit:%{ip}:login",
    Limit:       5,
    Period:      1 * time.Minute,
})
```


## IP Management

### Safelist IPs

Allow specific IPs to bypass throttling:

```go
ra.SafelistIP("127.0.0.1")
```
### Blocklist IPs

Block specific IPs:

```go
ra.BlocklistIP("10.0.0.1")
```
### Blocklist IPs

Block specific IPs:

```go
ra.BlocklistIP("10.0.0.1")
```


## Acknowledgements

This project is inspired by and borrows concepts from the following:

- **[Rack::Attack](https://github.com/kickstarter/rack-attack)**: for the core rate-limiting logic and features.
- **[go-redis](https://github.com/go-redis/redis)**: for Redis client integration.

## Code of Conduct

This project adheres to the [Contributor Covenant](https://www.contributor-covenant.org/).


## License

Distributed under the MIT License. See [LICENSE](./LICENSE) for details.
