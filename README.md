# Go Rack::Attack

A Go implementation of the **Rack::Attack** gem, designed to protect your HTTP services from abusive requests. This library provides **rate limiting**, **IP safelisting/blocklisting**, and **request throttling** with Redis-backed storage. It supports middleware for popular Go frameworks like `net/http`, `chi`, `gin`, and `echo`.

---

## Features

- **Rate Limiting**: Throttle requests by IP, endpoint, or custom keys.
- **IP Safelisting/Blocklisting**: Allow or block specific IPs or CIDR ranges.
- **Redis Backend**: Scalable and distributed rate limiting using Redis.
- **Middleware Support**: Works with `net/http`, `chi`, `gin`, and `echo`.
- **Custom Rules**: Define URL-specific or global rate limits.

---

## Installation

```bash
go get github.com/nandha854/go-rack-attack

