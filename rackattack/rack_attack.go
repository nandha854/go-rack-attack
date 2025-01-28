// Package rackattack provides a Redis-based rate limiting and IP blocking system.
//
// RedisRackAttack implements rate limiting functionality using Redis as a backend store.
// It supports:
// - IP-based throttling with configurable rules
// - IP safelisting and blocklisting
// - CIDR block filtering
// - Path pattern matching
// - HTTP method filtering
//
// Rate limiting rules can be configured using ThrottleRule structs that specify:
// - Path patterns (with wildcard support)
// - HTTP methods to match
// - Rate limit key templates
// - Request limits within time periods
//
// Example usage:
//
//	client := redis.NewClient(&redis.Options{...})
//	ra := rackattack.New(client)
//
//	// Add a throttle rule
//	ra.AddThrottleRule(ThrottleRule{
//	    PathPattern: "/api/*",
//	    Method:      "POST",
//	    Key:         "ratelimit:%{ip}:%{path}",
//	    Limit:       100,
//	    Period:      time.Hour,
//	})
//
//	// Safelist IPs
//	ra.SafelistIP("127.0.0.1")
//
//	// Block IPs or CIDR ranges
//	ra.BlocklistIP("10.0.0.1")
//	ra.BlocklistCIDR("10.0.0.0/24")
//
//	// Check if request is throttled
//	isThrottled, err := ra.IsThrottled(request)
package rackattack

import (
	"context"
	"net"
	"net/http"
	"path"
	"strings"
	"time"
    "github.com/redis/go-redis/v9"
)


// ThrottleRule represents a rate limiting rule for a specific path and HTTP method.
type ThrottleRule struct {
	PathPattern string
	Method	  	string
	Key         string
	Limit       int
	Period      time.Duration
}

// RedisRackAttack provides rate limiting and IP blocking functionality using Redis.
type RedisRackAttack struct {
	redisClient    *redis.Client
	throttleRules  []ThrottleRule
	safelistIPs    map[string]bool
	blocklistIPs   map[string]bool
	blocklistCIDRs []*net.IPNet
}

// New creates a new RedisRackAttack instance with the provided Redis client. 
func New(redisClient *redis.Client) *RedisRackAttack {
	return &RedisRackAttack{
		redisClient:    redisClient,
		safelistIPs:    make(map[string]bool),
		blocklistIPs:   make(map[string]bool),
		blocklistCIDRs: make([]*net.IPNet, 0),
	}
}

// matchesPath checks if the request path matches the rule's path pattern (with wildcard support).
func (r *ThrottleRule) matchesPath(reqPath string) bool {
	cleanPath := path.Clean(reqPath)
	
	if r.PathPattern == "" {
		return true
	}

	if strings.Contains(r.PathPattern, "*") {
		pattern := strings.TrimSuffix(r.PathPattern, "/*")
		return strings.HasPrefix(cleanPath+"/", pattern+"/")
	}

	return cleanPath == path.Clean(r.PathPattern)
}

//  clientIP extracts the client IP address from the request.
func (ra *RedisRackAttack) clientIP(req *http.Request) string {
	// Check for X-Forwarded-For header to handle reverse proxies
	if ip := req.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}

	// Fallback to remote address
	ip, _, _ := net.SplitHostPort(req.RemoteAddr)
	return ip
}

// safelistIP adds an IP address to the safelist to bypass rate limiting.
func (ra *RedisRackAttack) SafelistIP(ip string) {
	ra.safelistIPs[ip] = true
}

// blocklistIP adds an IP address to the blocklist to deny access
func (ra *RedisRackAttack) BlocklistIP(ip string) {
	ra.blocklistIPs[ip] = true
}

// BlocklistCIDR adds a CIDR range to the blocklist to deny access to address subnets.
func (ra *RedisRackAttack) BlocklistCIDR(cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	ra.blocklistCIDRs = append(ra.blocklistCIDRs, ipNet)
	return nil
}

// To add a throttle rule to the RedisRackAttack instance.
func (ra *RedisRackAttack) AddThrottleRule(rule ThrottleRule) {
	ra.throttleRules = append(ra.throttleRules, rule)
}

// IsBlocked checks if an IP address is blocked by the blocklist or CIDR ranges
func (ra *RedisRackAttack) IsBlocked(ip string) bool {
	if _, exists := ra.blocklistIPs[ip]; exists {
		return true
	}

	// Check if IP is in any blocklist CIDR range
	parsedIP := net.ParseIP(ip)
	for _, cidr := range ra.blocklistCIDRs {
		if cidr.Contains(parsedIP) {
			return true
		}
	}
	return false
}


// IsThrottled checks if a request is throttled based on the configured rules.
func (ra *RedisRackAttack) IsThrottled(req *http.Request) (bool, error) {
	ctx := context.Background()
	ip := ra.clientIP(req)
	reqPath := req.URL.Path

	if ra.safelistIPs[ip] {
		return false, nil
	}

	if ra.IsBlocked(ip) {
		return true, nil
	}

	// Check each throttle rule for the request path and method
	for _, rule := range ra.throttleRules {
		if !(rule.matchesPath(reqPath) && req.Method == rule.Method) {
			continue
		}

		key := strings.NewReplacer(
			"%{ip}", ip,
			"%{path}", reqPath,
		).Replace(rule.Key)

		count, err := ra.redisClient.Incr(ctx, key).Result()
		if err != nil {
			return false, err
		}

		if count == 1 {
			ra.redisClient.Expire(ctx, key, rule.Period)
		}

		if int(count) > rule.Limit {
			return true, nil
		}
	}

	return false, nil
}