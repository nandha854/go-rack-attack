// Package rackattack is a request-filtering middleware for Go HTTP servers,
// modeled on Ruby's Rack::Attack. It layers four policies, evaluated in
// precedence order on every request:
//
//  1. Safelist  — always allow (IPs and CIDR ranges).
//  2. Blocklist — always deny (IPs and CIDR ranges).
//  3. Fail2Ban  — deny clients that have accumulated too many offenses.
//  4. Throttle  — rate-limit by configurable per-rule keys.
//
// Storage is pluggable via the Store interface; a Redis-backed implementation
// (RedisStore) ships in this package and uses atomic Lua scripts for a
// sliding-window limiter and a ban engine.
//
// Client IP resolution defaults to the connection peer (req.RemoteAddr).
// X-Forwarded-For is honored only when the peer is a configured trusted proxy
// (see WithTrustedProxies); this prevents header spoofing from bypassing the
// safelist/blocklist.
//
// Example:
//
//	store := rackattack.NewRedisStore(redisClient, "rackattack:")
//	ra, err := rackattack.New(store,
//		rackattack.WithTrustedProxies("10.0.0.0/8"),
//	)
//	if err != nil { log.Fatal(err) }
//
//	ra.SafelistIP("127.0.0.1")
//	ra.BlocklistCIDR("192.0.2.0/24")
//	ra.Throttle(rackattack.ThrottleRule{
//		PathPattern: "/api/*", Method: "POST",
//		Key: "api:%{ip}", Limit: 100, Period: time.Hour,
//	})
//	ra.Fail2Ban(rackattack.Fail2BanRule{
//		PathPattern: "/login", Method: "POST",
//		Name: "login", MaxRetry: 5, FindTime: time.Minute, BanTime: time.Hour,
//		Trigger: func(r *http.Request) bool { return false }, // set per app
//	})
//
//	http.ListenAndServe(":8080", ra.Middleware(myHandler))
package rackattack

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// ReasonKind enumerates why a request was denied.
type ReasonKind int

const (
	// ReasonNone means the request was allowed.
	ReasonNone ReasonKind = iota
	// ReasonSafelisted means the request matched the safelist and bypassed all
	// other checks.
	ReasonSafelisted
	// ReasonBlocklisted means the client IP is on the blocklist.
	ReasonBlocklisted
	// ReasonBanned means the client tripped a Fail2Ban rule.
	ReasonBanned
	// ReasonThrottled means the client exceeded a throttle rule's limit.
	ReasonThrottled
)

// Decision is the outcome of evaluating a request.
type Decision struct {
	// Allowed reports whether the request should proceed.
	Allowed bool
	// Reason explains the decision.
	Reason ReasonKind
	// RuleName is the matched throttle/ban rule's identifier, when applicable.
	RuleName string
	// Throttle carries rate-limit details when Reason is ReasonThrottled.
	Throttle Result
}

// ThrottleRule is a rate-limiting rule for matching requests.
type ThrottleRule struct {
	// PathPattern matches the request path; supports glob wildcards (see
	// path.Match semantics, extended so a trailing "/*" matches any subtree).
	// Empty matches every path.
	PathPattern string
	// Method matches the HTTP method. Empty matches every method.
	Method string
	// Key is the throttle key template. %{ip} and %{path} are expanded.
	Key string
	// Limit is the maximum number of requests allowed within Period.
	Limit int
	// Period is the sliding window length.
	Period time.Duration
}

// Fail2BanRule bans a client after it triggers too many offenses. An offense
// is counted on any matching request for which Trigger returns true.
type Fail2BanRule struct {
	// Name uniquely identifies the rule and namespaces its counters.
	Name string
	// PathPattern and Method scope which requests the rule inspects (same
	// semantics as ThrottleRule). Empty fields match everything.
	PathPattern string
	Method      string
	// Trigger reports whether a matching request counts as an offense. If nil,
	// every matching request is an offense (useful for known-bad paths).
	Trigger func(*http.Request) bool
	// MaxRetry offenses within FindTime trigger a ban lasting BanTime.
	MaxRetry int
	FindTime time.Duration
	BanTime  time.Duration
}

// RedisRackAttack is the request filter. It is safe for concurrent use,
// including dynamic updates to the safelist, blocklist, and rule sets while
// requests are being served.
type RedisRackAttack struct {
	store      Store
	clientIP   ClientIPFunc
	onDenied   http.HandlerFunc
	onError    func(*http.Request, error)
	failClosed bool

	mu            sync.RWMutex
	safelistIPs   map[string]struct{}
	blocklistIPs  map[string]struct{}
	safelistNets  []*net.IPNet
	blocklistNets []*net.IPNet
	throttleRules []ThrottleRule
	fail2banRules []Fail2BanRule
}

// New creates a RedisRackAttack backed by the given Store. By default the
// client IP is the connection peer and store errors fail open (requests are
// allowed). Use options to change this.
func New(store Store, opts ...Option) (*RedisRackAttack, error) {
	if store == nil {
		return nil, errNilStore
	}
	ra := &RedisRackAttack{
		store:        store,
		clientIP:     directClientIP,
		safelistIPs:  make(map[string]struct{}),
		blocklistIPs: make(map[string]struct{}),
	}
	for _, opt := range opts {
		if err := opt(ra); err != nil {
			return nil, err
		}
	}
	if ra.onDenied == nil {
		ra.onDenied = defaultDeniedHandler
	}
	return ra, nil
}

// SafelistIP adds an exact IP to the safelist.
func (ra *RedisRackAttack) SafelistIP(ip string) {
	ra.mu.Lock()
	defer ra.mu.Unlock()
	ra.safelistIPs = withKey(ra.safelistIPs, ip)
}

// SafelistCIDR adds a CIDR range to the safelist.
func (ra *RedisRackAttack) SafelistCIDR(cidr string) error {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	ra.mu.Lock()
	defer ra.mu.Unlock()
	ra.safelistNets = append(ra.safelistNets, n)
	return nil
}

// BlocklistIP adds an exact IP to the blocklist.
func (ra *RedisRackAttack) BlocklistIP(ip string) {
	ra.mu.Lock()
	defer ra.mu.Unlock()
	ra.blocklistIPs = withKey(ra.blocklistIPs, ip)
}

// BlocklistCIDR adds a CIDR range to the blocklist.
func (ra *RedisRackAttack) BlocklistCIDR(cidr string) error {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	ra.mu.Lock()
	defer ra.mu.Unlock()
	ra.blocklistNets = append(ra.blocklistNets, n)
	return nil
}

// Throttle registers a throttle rule.
func (ra *RedisRackAttack) Throttle(rule ThrottleRule) {
	ra.mu.Lock()
	defer ra.mu.Unlock()
	// Copy-on-write so concurrent readers iterate a stable slice.
	rules := make([]ThrottleRule, len(ra.throttleRules), len(ra.throttleRules)+1)
	copy(rules, ra.throttleRules)
	ra.throttleRules = append(rules, rule)
}

// Fail2Ban registers a Fail2Ban rule.
func (ra *RedisRackAttack) Fail2Ban(rule Fail2BanRule) {
	ra.mu.Lock()
	defer ra.mu.Unlock()
	rules := make([]Fail2BanRule, len(ra.fail2banRules), len(ra.fail2banRules)+1)
	copy(rules, ra.fail2banRules)
	ra.fail2banRules = append(rules, rule)
}

// Check evaluates the request against all policies and returns a Decision. It
// does not write any response; use Middleware for that.
func (ra *RedisRackAttack) Check(req *http.Request) (Decision, error) {
	ctx := req.Context()
	ip := ra.clientIP(req)
	reqPath := req.URL.Path

	ra.mu.RLock()
	safelistIPs := ra.safelistIPs
	blocklistIPs := ra.blocklistIPs
	safelistNets := ra.safelistNets
	blocklistNets := ra.blocklistNets
	throttleRules := ra.throttleRules
	fail2banRules := ra.fail2banRules
	ra.mu.RUnlock()

	// 1. Safelist wins outright.
	if ip != "" {
		if _, ok := safelistIPs[ip]; ok || ipInNets(ip, safelistNets) {
			return Decision{Allowed: true, Reason: ReasonSafelisted}, nil
		}
	}

	// 2. Blocklist.
	if ip != "" {
		if _, ok := blocklistIPs[ip]; ok || ipInNets(ip, blocklistNets) {
			return Decision{Allowed: false, Reason: ReasonBlocklisted}, nil
		}
	}

	// 3. Fail2Ban.
	for _, rule := range fail2banRules {
		if !matchPath(rule.PathPattern, reqPath) || !matchMethod(rule.Method, req.Method) {
			continue
		}
		banKey := rule.Name + ":" + ip
		offended := rule.Trigger == nil || rule.Trigger(req)
		var banned bool
		var err error
		if offended {
			banned, err = ra.store.Strike(ctx, banKey, rule.MaxRetry, rule.FindTime, rule.BanTime)
		} else {
			banned, err = ra.store.Banned(ctx, banKey)
		}
		if err != nil {
			return Decision{}, err
		}
		if banned {
			return Decision{Allowed: false, Reason: ReasonBanned, RuleName: rule.Name}, nil
		}
	}

	// 4. Throttle. Evaluate every matching rule so each window is counted, and
	// remember the rule that leaves the least headroom so the caller can emit
	// accurate RateLimit-* headers even when the request is allowed.
	allowed := Decision{Allowed: true, Reason: ReasonNone}
	haveThrottle := false
	for _, rule := range throttleRules {
		if !matchPath(rule.PathPattern, reqPath) || !matchMethod(rule.Method, req.Method) {
			continue
		}
		key := expandKey(rule.Key, ip, reqPath)
		res, err := ra.store.Throttle(ctx, key, rule.Limit, rule.Period)
		if err != nil {
			return Decision{}, err
		}
		if res.Limited {
			return Decision{
				Allowed:  false,
				Reason:   ReasonThrottled,
				RuleName: rule.Key,
				Throttle: res,
			}, nil
		}
		if !haveThrottle || res.Remaining < allowed.Throttle.Remaining {
			allowed.RuleName = rule.Key
			allowed.Throttle = res
			haveThrottle = true
		}
	}

	return allowed, nil
}

// IsThrottled reports whether the request should be denied. It is a
// convenience wrapper over Check that preserves the original boolean-style API.
// A true result means "deny" for any reason (blocklist, ban, or throttle).
//
// On a store error, the returned bool follows the configured fail-open or
// fail-closed policy (default: fail open, returns false).
func (ra *RedisRackAttack) IsThrottled(req *http.Request) (bool, error) {
	decision, err := ra.Check(req)
	if err != nil {
		return ra.failClosed, err
	}
	return !decision.Allowed, nil
}
