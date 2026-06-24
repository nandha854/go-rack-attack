package rackattack

import "errors"

// errMalformedScriptReply indicates the Lua throttle script returned a reply
// shape the client did not expect. It signals a version/wiring bug rather than
// a runtime condition.
var errMalformedScriptReply = errors.New("rackattack: malformed throttle script reply")

// toInt coerces a Redis reply element (which arrives as int64) to int.
func toInt(v any) int {
	if n, ok := v.(int64); ok {
		return int(n)
	}
	return 0
}

// toInt64 coerces a Redis reply element to int64.
func toInt64(v any) int64 {
	if n, ok := v.(int64); ok {
		return n
	}
	return 0
}

// withKey returns a copy of m with key added. Copy-on-write keeps the map safe
// for concurrent readers that captured the previous map under the read lock.
func withKey(m map[string]struct{}, key string) map[string]struct{} {
	next := make(map[string]struct{}, len(m)+1)
	for k := range m {
		next[k] = struct{}{}
	}
	next[key] = struct{}{}
	return next
}
