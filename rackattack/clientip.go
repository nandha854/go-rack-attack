package rackattack

import (
	"net"
	"net/http"
	"strings"
)

// ClientIPFunc derives the client IP address from a request. Implementations
// must return the IP as a plain string (no port). Returning an empty string
// signals that the IP could not be determined; callers treat such requests as
// un-safelisted and un-blocklisted but still subject to throttling under the
// empty key.
type ClientIPFunc func(req *http.Request) string

// directClientIP returns the IP of the immediate peer (req.RemoteAddr),
// ignoring any forwarding headers. This is the safe default: forwarding
// headers are attacker-controlled unless the request demonstrably arrived
// through a proxy you operate.
func directClientIP(req *http.Request) string {
	return remoteAddrIP(req.RemoteAddr)
}

// remoteAddrIP extracts the host portion of an address that may or may not
// carry a port. It tolerates bare IPs (no port), which can occur with
// synthetic requests and some non-TCP listeners.
func remoteAddrIP(remoteAddr string) string {
	if remoteAddr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// No port present (or malformed). Treat the whole value as the host
		// when it parses as an IP, otherwise give up.
		if net.ParseIP(remoteAddr) != nil {
			return remoteAddr
		}
		return ""
	}
	return host
}

// trustedProxyClientIP builds a ClientIPFunc that trusts X-Forwarded-For only
// when the immediate peer is within one of the trusted proxy networks. It then
// walks the forwarded chain from right (closest hop) to left, returning the
// first address that is NOT itself a trusted proxy — i.e. the real client as
// seen by the outermost proxy you control.
//
// If the peer is not trusted, the forwarding header is ignored entirely and
// the peer address is used. This prevents a direct client from spoofing
// X-Forwarded-For to impersonate a safelisted IP.
func trustedProxyClientIP(trusted []*net.IPNet) ClientIPFunc {
	return func(req *http.Request) string {
		peer := remoteAddrIP(req.RemoteAddr)
		if peer == "" || !ipInNets(peer, trusted) {
			return peer
		}

		xff := req.Header.Get("X-Forwarded-For")
		if xff == "" {
			return peer
		}

		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			candidate := strings.TrimSpace(parts[i])
			if candidate == "" {
				continue
			}
			ip := net.ParseIP(candidate)
			if ip == nil {
				// Garbage entry in the chain; the upstream is suspect, stop
				// trusting further-left hops and return what we have.
				return candidate
			}
			if ipInNets(candidate, trusted) {
				// This hop is one of our proxies; keep walking left.
				continue
			}
			return candidate
		}

		// Every hop in the chain was a trusted proxy (unusual); fall back to
		// the peer.
		return peer
	}
}

// ipInNets reports whether the given IP string falls within any of the
// provided networks.
func ipInNets(ip string, nets []*net.IPNet) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range nets {
		if n != nil && n.Contains(parsed) {
			return true
		}
	}
	return false
}
