package rackattack_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/redis/go-redis/v9"
	"github.com/nandha854/go-rack-attack/rackattack"
)

func setupTest(t *testing.T) (*rackattack.RedisRackAttack, *miniredis.Miniredis) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return rackattack.New(client), mr
}

func TestSafelistedIP(t *testing.T) {
	ra, _ := setupTest(t)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.100:1234"

	ra.SafelistIP("192.168.1.100")
	throttled, _ := ra.IsThrottled(req)
	assert.False(t, throttled)
}

func TestBlocklistedIP(t *testing.T) {
	ra, _ := setupTest(t)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"

	ra.BlocklistIP("10.0.0.1")
	throttled, _ := ra.IsThrottled(req)
	assert.True(t, throttled)
}

func TestCIDRBlock(t *testing.T) {
	ra, _ := setupTest(t)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "172.16.0.5:1234"

	ra.BlocklistCIDR("172.16.0.0/24")
	throttled, _ := ra.IsThrottled(req)
	assert.True(t, throttled)
}

func TestPathMatching(t *testing.T) {
	ra, mr := setupTest(t)
	ra.AddThrottleRule(rackattack.ThrottleRule{
		PathPattern: "/api/*",
		Key:         "throttle:%{ip}:%{path}",
		Limit:       2,
		Period:      time.Minute,
	})

	// Test matching path
	req := httptest.NewRequest("GET", "/api/users", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	throttled, _ := ra.IsThrottled(req)
	assert.False(t, throttled)

	// Test non-matching path
	req = httptest.NewRequest("GET", "/dashboard", nil)
	throttled, _ = ra.IsThrottled(req)
	assert.False(t, throttled)

	// Force expiration for clean tests
	mr.FastForward(time.Hour)
}

func TestThrottleLimit(t *testing.T) {
	ra, mr := setupTest(t)
	ra.AddThrottleRule(rackattack.ThrottleRule{
		Key:    "throttle:test:%{ip}",
		Limit:  2,
		Period: time.Minute,
	})

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.5:1234"

	// First 2 requests allowed
	assert.False(t, mustThrottle(ra, req))
	assert.False(t, mustThrottle(ra, req))
	
	// Third request throttled
	assert.True(t, mustThrottle(ra, req))

	// Fast-forward to reset
	mr.FastForward(time.Hour)
	assert.False(t, mustThrottle(ra, req))
}

func mustThrottle(ra *rackattack.RedisRackAttack, req *http.Request) bool {
	throttled, _ := ra.IsThrottled(req)
	return throttled
}