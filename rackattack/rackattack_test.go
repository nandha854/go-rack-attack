package rackattack_test

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nandha854/go-rack-attack/rackattack"
)

func setup(t *testing.T) (*rackattack.RedisRackAttack, *miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := rackattack.NewRedisStore(client, "test:")
	ra, err := rackattack.New(store)
	require.NoError(t, err)
	return ra, mr, client
}

func req(method, target, remoteAddr string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.RemoteAddr = remoteAddr
	return r
}

func TestSafelistWinsOverBlocklist(t *testing.T) {
	ra, _, _ := setup(t)
	ra.SafelistIP("1.2.3.4")
	ra.BlocklistIP("1.2.3.4")

	d, err := ra.Check(req("GET", "/", "1.2.3.4:1111"))
	require.NoError(t, err)
	assert.True(t, d.Allowed)
	assert.Equal(t, rackattack.ReasonSafelisted, d.Reason)
}

func TestBlocklistIPAndCIDR(t *testing.T) {
	ra, _, _ := setup(t)
	ra.BlocklistIP("10.0.0.1")
	require.NoError(t, ra.BlocklistCIDR("172.16.0.0/24"))

	d, _ := ra.Check(req("GET", "/", "10.0.0.1:1"))
	assert.False(t, d.Allowed)
	assert.Equal(t, rackattack.ReasonBlocklisted, d.Reason)

	d, _ = ra.Check(req("GET", "/", "172.16.0.55:1"))
	assert.False(t, d.Allowed)

	d, _ = ra.Check(req("GET", "/", "172.16.1.55:1"))
	assert.True(t, d.Allowed)
}

func TestSafelistCIDR(t *testing.T) {
	ra, _, _ := setup(t)
	require.NoError(t, ra.SafelistCIDR("192.168.0.0/16"))
	d, _ := ra.Check(req("GET", "/", "192.168.5.5:1"))
	assert.True(t, d.Allowed)
	assert.Equal(t, rackattack.ReasonSafelisted, d.Reason)
}

func TestThrottleSlidingWindow(t *testing.T) {
	ra, mr, _ := setup(t)
	ra.Throttle(rackattack.ThrottleRule{
		Key:    "rl:%{ip}",
		Limit:  2,
		Period: time.Minute,
	})
	r := req("GET", "/", "9.9.9.9:1")

	d, _ := ra.Check(r)
	assert.True(t, d.Allowed)
	assert.Equal(t, 1, d.Throttle.Remaining)

	d, _ = ra.Check(r)
	assert.True(t, d.Allowed)
	assert.Equal(t, 0, d.Throttle.Remaining)

	d, _ = ra.Check(r)
	assert.False(t, d.Allowed)
	assert.Equal(t, rackattack.ReasonThrottled, d.Reason)
	assert.Greater(t, d.Throttle.RetryAfter, time.Duration(0))

	// Advance past the window; requests should be allowed again.
	mr.FastForward(2 * time.Minute)
	d, _ = ra.Check(r)
	assert.True(t, d.Allowed)
}

func TestXForwardedForIgnoredByDefault(t *testing.T) {
	ra, _, _ := setup(t)
	ra.SafelistIP("1.1.1.1")

	// Attacker connects directly (peer 5.5.5.5) and spoofs a safelisted IP.
	r := req("GET", "/", "5.5.5.5:1234")
	r.Header.Set("X-Forwarded-For", "1.1.1.1")

	d, err := ra.Check(r)
	require.NoError(t, err)
	// Spoof must NOT grant safelist; peer 5.5.5.5 is used instead.
	assert.NotEqual(t, rackattack.ReasonSafelisted, d.Reason)
}

func TestTrustedProxyHonorsXFF(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := rackattack.NewRedisStore(client, "test:")
	ra, err := rackattack.New(store, rackattack.WithTrustedProxies("10.0.0.0/8"))
	require.NoError(t, err)
	ra.BlocklistIP("203.0.113.7")

	// Request arrives via trusted proxy 10.1.1.1; real client in XFF.
	r := req("GET", "/", "10.1.1.1:1234")
	r.Header.Set("X-Forwarded-For", "203.0.113.7, 10.1.1.1")

	d, _ := ra.Check(r)
	assert.False(t, d.Allowed)
	assert.Equal(t, rackattack.ReasonBlocklisted, d.Reason)
}

func TestTrustedProxySpoofFromUntrustedPeer(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := rackattack.NewRedisStore(client, "test:")
	ra, err := rackattack.New(store, rackattack.WithTrustedProxies("10.0.0.0/8"))
	require.NoError(t, err)
	ra.SafelistIP("1.1.1.1")

	// Peer 8.8.8.8 is NOT a trusted proxy, so its XFF is ignored.
	r := req("GET", "/", "8.8.8.8:1234")
	r.Header.Set("X-Forwarded-For", "1.1.1.1")

	d, _ := ra.Check(r)
	assert.NotEqual(t, rackattack.ReasonSafelisted, d.Reason)
}

func TestFail2BanBansAfterMaxRetry(t *testing.T) {
	ra, _, _ := setup(t)
	ra.Fail2Ban(rackattack.Fail2BanRule{
		Name:        "login",
		PathPattern: "/login",
		Method:      "POST",
		MaxRetry:    3,
		FindTime:    time.Minute,
		BanTime:     time.Hour,
		Trigger:     func(_ *http.Request) bool { return true }, // every hit is an offense
	})

	r := req("POST", "/login", "4.4.4.4:1")

	// First 2 offenses: allowed.
	for i := 0; i < 2; i++ {
		d, err := ra.Check(r)
		require.NoError(t, err)
		assert.True(t, d.Allowed, "offense %d should be allowed", i+1)
	}
	// 3rd offense trips the ban.
	d, _ := ra.Check(r)
	assert.False(t, d.Allowed)
	assert.Equal(t, rackattack.ReasonBanned, d.Reason)

	// A different path is still banned because the ban is per-IP for the rule.
	d, _ = ra.Check(req("POST", "/login", "4.4.4.4:1"))
	assert.False(t, d.Allowed)
}

func TestFail2BanTriggerFalseDoesNotBan(t *testing.T) {
	ra, _, _ := setup(t)
	ra.Fail2Ban(rackattack.Fail2BanRule{
		Name:     "probe",
		MaxRetry: 1,
		FindTime: time.Minute,
		BanTime:  time.Hour,
		Trigger:  func(_ *http.Request) bool { return false }, // never an offense
	})
	for i := 0; i < 5; i++ {
		d, _ := ra.Check(req("GET", "/x", "7.7.7.7:1"))
		assert.True(t, d.Allowed)
	}
}

func TestWildcardMatching(t *testing.T) {
	ra, _, _ := setup(t)
	ra.Throttle(rackattack.ThrottleRule{
		PathPattern: "/api/*",
		Key:         "k:%{path}",
		Limit:       1,
		Period:      time.Minute,
	})

	// Under subtree: first allowed, second throttled.
	d, _ := ra.Check(req("GET", "/api/v1/users", "2.2.2.2:1"))
	assert.True(t, d.Allowed)
	d, _ = ra.Check(req("GET", "/api/v1/users", "2.2.2.2:1"))
	assert.False(t, d.Allowed)

	// Outside subtree: never throttled.
	d, _ = ra.Check(req("GET", "/dashboard", "2.2.2.2:1"))
	assert.True(t, d.Allowed)
}

func TestMiddlewareThrottleResponse(t *testing.T) {
	ra, _, _ := setup(t)
	ra.Throttle(rackattack.ThrottleRule{Key: "m:%{ip}", Limit: 1, Period: time.Minute})

	called := 0
	h := ra.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	}))

	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, req("GET", "/", "3.3.3.3:1"))
	assert.Equal(t, http.StatusOK, rec1.Code)

	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req("GET", "/", "3.3.3.3:1"))
	assert.Equal(t, http.StatusTooManyRequests, rec2.Code)
	assert.NotEmpty(t, rec2.Header().Get("Retry-After"))
	assert.Equal(t, "1", rec2.Header().Get("RateLimit-Limit"))
	assert.Equal(t, 1, called)
}

func TestMiddlewareBlocklistResponse(t *testing.T) {
	ra, _, _ := setup(t)
	ra.BlocklistIP("6.6.6.6")
	h := ra.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler should not be reached")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req("GET", "/", "6.6.6.6:1"))
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestFailOpenOnStoreError(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := rackattack.NewRedisStore(client, "test:")
	ra, err := rackattack.New(store)
	require.NoError(t, err)
	ra.Throttle(rackattack.ThrottleRule{Key: "f:%{ip}", Limit: 1, Period: time.Minute})

	mr.Close() // store now errors

	throttled, err := ra.IsThrottled(req("GET", "/", "1.2.3.4:1"))
	assert.Error(t, err)
	assert.False(t, throttled) // fail open
}

func TestConcurrentMutationAndCheck(t *testing.T) {
	ra, _, _ := setup(t)
	ra.Throttle(rackattack.ThrottleRule{Key: "c:%{ip}", Limit: 1000000, Period: time.Minute})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			ra.SafelistIP("1.1.1.1")
			ra.BlocklistIP("2.2.2.2")
			ra.Throttle(rackattack.ThrottleRule{Key: "x", Limit: 5, Period: time.Minute})
		}()
		go func() {
			defer wg.Done()
			_, _ = ra.Check(req("GET", "/api/x", "9.8.7.6:1"))
		}()
	}
	wg.Wait()
}

func TestEmptyRemoteAddrNotBlocklisted(t *testing.T) {
	ra, _, _ := setup(t)
	require.NoError(t, ra.BlocklistCIDR("0.0.0.0/0")) // would block everything parseable
	// A request with no resolvable IP should not panic and should not be
	// treated as a blocklisted IP (empty IP is unknown, not "all zeros").
	d, err := ra.Check(req("GET", "/", "garbage-no-port"))
	require.NoError(t, err)
	assert.NotEqual(t, rackattack.ReasonBlocklisted, d.Reason)
}
