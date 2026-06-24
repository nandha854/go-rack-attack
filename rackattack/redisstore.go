package rackattack

import (
	"context"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// throttleScript implements a sliding-window-log limiter atomically.
//
// KEYS[1] = throttle key
// ARGV[1] = window in milliseconds
// ARGV[2] = limit
// ARGV[3] = current time in milliseconds
// ARGV[4] = a unique member for this request (time-suffixed)
//
// It trims entries older than (now - window), counts what remains, and only
// records the new hit when under limit. The key is given a TTL equal to the
// window so idle keys self-evict. Returns {count, limited(0|1), oldestMs}.
var throttleScript = redis.NewScript(`
local key    = KEYS[1]
local window = tonumber(ARGV[1])
local limit  = tonumber(ARGV[2])
local now    = tonumber(ARGV[3])
local member = ARGV[4]

redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local count = redis.call('ZCARD', key)

if count >= limit then
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  local oldestMs = now
  if oldest[2] then oldestMs = tonumber(oldest[2]) end
  return {count, 1, oldestMs}
end

redis.call('ZADD', key, now, member)
redis.call('PEXPIRE', key, window)
return {count + 1, 0, now}
`)

// strikeScript implements Fail2Ban atomically.
//
// KEYS[1] = ban key, KEYS[2] = strike-counter key
// ARGV[1] = maxRetry, ARGV[2] = findTime ms, ARGV[3] = banTime ms
//
// If a ban is already set, it returns 1 immediately. Otherwise it increments
// the offense counter (setting findTime TTL on first offense). When offenses
// reach maxRetry it sets the ban with banTime TTL and clears the counter.
// Returns 1 when banned after this call, else 0.
var strikeScript = redis.NewScript(`
local banKey    = KEYS[1]
local countKey  = KEYS[2]
local maxRetry  = tonumber(ARGV[1])
local findTime  = tonumber(ARGV[2])
local banTime   = tonumber(ARGV[3])

if redis.call('EXISTS', banKey) == 1 then
  return 1
end

local count = redis.call('INCR', countKey)
if count == 1 then
  redis.call('PEXPIRE', countKey, findTime)
end

if count >= maxRetry then
  redis.call('SET', banKey, 1, 'PX', banTime)
  redis.call('DEL', countKey)
  return 1
end

return 0
`)

// RedisStore is a Redis-backed Store. It uses server-side Lua scripts so that
// each throttle or strike decision is a single atomic round-trip.
type RedisStore struct {
	client    redis.Cmdable
	keyPrefix string
	now       func() time.Time
	seq       atomic.Uint64
}

// NewRedisStore wraps a go-redis client as a Store. keyPrefix is prepended to
// every key (pass "" for none); a trailing separator is recommended, e.g.
// "rackattack:".
func NewRedisStore(client redis.Cmdable, keyPrefix string) *RedisStore {
	return &RedisStore{client: client, keyPrefix: keyPrefix, now: time.Now}
}

func (s *RedisStore) k(key string) string {
	return s.keyPrefix + key
}

// Throttle implements Store.
func (s *RedisStore) Throttle(ctx context.Context, key string, limit int, period time.Duration) (Result, error) {
	nowMs := s.now().UnixMilli()
	windowMs := period.Milliseconds()
	// The sorted-set member must be unique per request so that two hits in the
	// same millisecond both count. A per-store atomic counter guarantees this
	// without relying on clock resolution.
	member := strconv.FormatInt(nowMs, 10) + "-" + strconv.FormatUint(s.seq.Add(1), 10)

	res, err := throttleScript.Run(ctx, s.client, []string{s.k(key)},
		windowMs, limit, nowMs, member).Result()
	if err != nil {
		return Result{}, err
	}

	vals, ok := res.([]any)
	if !ok || len(vals) < 3 {
		return Result{}, errMalformedScriptReply
	}
	count := toInt(vals[0])
	limited := toInt(vals[1]) == 1
	oldestMs := toInt64(vals[2])

	result := Result{
		Limit:     limit,
		Limited:   limited,
		Remaining: max(limit-count, 0),
	}
	if limited {
		result.Remaining = 0
		// The window frees a slot once the oldest entry ages out.
		elapsed := nowMs - oldestMs
		retry := max(windowMs-elapsed, 0)
		result.RetryAfter = time.Duration(retry) * time.Millisecond
	}
	return result, nil
}

// Strike implements Store.
func (s *RedisStore) Strike(ctx context.Context, key string, maxRetry int, findTime, banTime time.Duration) (bool, error) {
	banned, err := strikeScript.Run(ctx, s.client,
		[]string{s.k("ban:" + key), s.k("strike:" + key)},
		maxRetry, findTime.Milliseconds(), banTime.Milliseconds()).Int()
	if err != nil {
		return false, err
	}
	return banned == 1, nil
}

// Banned implements Store.
func (s *RedisStore) Banned(ctx context.Context, key string) (bool, error) {
	n, err := s.client.Exists(ctx, s.k("ban:"+key)).Result()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}
