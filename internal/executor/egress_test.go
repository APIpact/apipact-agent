package executor

import (
	"context"
	"net"
	"testing"

	"github.com/APIpact/apipact-agent/internal/protocol"
)

func TestEgressPolicyTable(t *testing.T) {
	allowSubnet, _ := ParseCIDRs("10.1.2.0/24")

	cases := []struct {
		name    string
		policy  EgressPolicy
		ip      string
		allowed bool
	}{
		{"metadata always blocked", EgressPolicy{AllowPrivate: true}, "169.254.169.254", false},
		{"ipv6 metadata blocked", EgressPolicy{AllowPrivate: true}, "fd00:ec2::254", false},
		{"loopback blocked by default", EgressPolicy{}, "127.0.0.1", false},
		{"rfc1918 blocked by default", EgressPolicy{}, "10.0.0.5", false},
		{"rfc1918 allowed when AllowPrivate", EgressPolicy{AllowPrivate: true}, "10.0.0.5", true},
		{"public allowed", EgressPolicy{}, "93.184.216.34", true},
		{"allowlisted subnet permitted", EgressPolicy{Allow: allowSubnet}, "10.1.2.9", true},
		{"non-allowlisted private still blocked", EgressPolicy{Allow: allowSubnet}, "10.9.9.9", false},
		{"link-local blocked", EgressPolicy{}, "169.254.1.1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("bad test ip %q", tc.ip)
			}
			got, reason := tc.policy.Allowed(ip)
			if got != tc.allowed {
				t.Errorf("Allowed(%s)=%v reason=%q, want %v", tc.ip, got, reason, tc.allowed)
			}
		})
	}
}

func TestParseCIDRs(t *testing.T) {
	nets, err := ParseCIDRs("10.0.0.0/8, 192.168.1.5 192.168.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 3 {
		t.Fatalf("expected 3 nets, got %d", len(nets))
	}
	// The bare IP became a /32.
	if ones, _ := nets[1].Mask.Size(); ones != 32 {
		t.Errorf("expected /32 for bare IP, got /%d", ones)
	}
	if _, err := ParseCIDRs("not-a-cidr"); err == nil {
		t.Error("expected error for bad CIDR")
	}
}

// TestGuardedDialBlocksMetadata verifies the dialer refuses a metadata target
// before connecting, and that the engine classifies it as "blocked".
func TestGuardedDialBlocksLoopback(t *testing.T) {
	eng := New(EgressPolicy{}, nil) // private/loopback blocked
	res := eng.Execute(context.Background(), protocol.RequestSpec{
		Method:   "GET",
		URL:      "http://127.0.0.1:9/anything",
		Timeouts: protocol.Timeouts{TotalMs: 2000},
	})
	if res.Error == nil || res.Error.Kind != protocol.ErrKindBlocked {
		t.Errorf("expected blocked error, got %+v", res.Error)
	}
}
