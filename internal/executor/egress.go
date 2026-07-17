package executor

import (
	"fmt"
	"net"
	"strings"
)

// EgressPolicy decides whether the agent may connect to a resolved IP. The
// agent is an SSRF engine by design; this is the containment layer that runs
// on the address actually dialed (post-DNS), so DNS rebinding cannot bypass it.
//
// Evaluation order for a candidate IP:
//  1. If it matches an always-blocked range (cloud metadata, link-local), deny.
//  2. If it is private/loopback/ULA and not explicitly allowed, deny.
//  3. Otherwise allow.
type EgressPolicy struct {
	// AllowPrivate permits RFC1918 / ULA / loopback targets globally. Even when
	// true, the always-blocked ranges below remain blocked.
	AllowPrivate bool
	// Allow is an operator allowlist of CIDRs that override the private check
	// (e.g. a specific internal subnet under test).
	Allow []*net.IPNet
	// Block is an operator-supplied denylist, evaluated before everything else.
	Block []*net.IPNet
}

// alwaysBlocked are ranges denied regardless of AllowPrivate: cloud metadata,
// link-local, and the unspecified address. These are the classic SSRF pivots.
var alwaysBlocked = mustCIDRs(
	"169.254.169.254/32", // AWS/GCP/Azure/DO/etc. IMDS
	"fd00:ec2::254/128",  // AWS IMDSv6
	"169.254.0.0/16",     // link-local v4 (covers most metadata + APIPA)
	"fe80::/10",          // link-local v6
	"::/128",             // unspecified v6
	"0.0.0.0/32",         // unspecified v4
)

// Allowed reports whether ip may be dialed, with a reason when it may not.
func (p EgressPolicy) Allowed(ip net.IP) (bool, string) {
	for _, n := range alwaysBlocked {
		if n.Contains(ip) {
			return false, fmt.Sprintf("target %s is in an always-blocked range (%s)", ip, n)
		}
	}
	for _, n := range p.Block {
		if n.Contains(ip) {
			return false, fmt.Sprintf("target %s is in a blocked range (%s)", ip, n)
		}
	}
	for _, n := range p.Allow {
		if n.Contains(ip) {
			return true, ""
		}
	}
	if p.AllowPrivate {
		return true, ""
	}
	if isPrivate(ip) {
		return false, fmt.Sprintf("target %s is a private/loopback address; not in the egress allowlist", ip)
	}
	return true, ""
}

func isPrivate(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsUnspecified()
}

// ParseCIDRs parses a comma/space-separated list of CIDRs (bare IPs are treated
// as /32 or /128).
func ParseCIDRs(list string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, tok := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		if tok == "" {
			continue
		}
		if !strings.Contains(tok, "/") {
			if ip := net.ParseIP(tok); ip != nil {
				if ip.To4() != nil {
					tok += "/32"
				} else {
					tok += "/128"
				}
			}
		}
		_, n, err := net.ParseCIDR(tok)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", tok, err)
		}
		out = append(out, n)
	}
	return out, nil
}

func mustCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("executor: bad built-in CIDR " + c + ": " + err.Error())
		}
		out = append(out, n)
	}
	return out
}
