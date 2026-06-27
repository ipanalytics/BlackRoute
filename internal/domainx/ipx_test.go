package domainx

import "testing"

func TestNormalizePublicIPRejectsReservedRanges(t *testing.T) {
	for _, ip := range []string{
		"0.0.0.2",
		"192.0.2.1",
		"198.18.0.1",
		"198.51.100.1",
		"203.0.113.1",
		"247.16.181.135",
		"100::",
		"2001:db8::1",
		"2002:1bfe:6024::1bfe:6024",
	} {
		if got, _ := NormalizePublicIP(ip); got != "" {
			t.Fatalf("NormalizePublicIP(%q) = %q, want empty", ip, got)
		}
	}
}

func TestNormalizePublicCIDRRejectsReservedRanges(t *testing.T) {
	for _, cidr := range []string{
		"192.0.2.0/24",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"2001:db8::/32",
		"2002::/16",
	} {
		if got := NormalizePublicCIDR(cidr); got != "" {
			t.Fatalf("NormalizePublicCIDR(%q) = %q, want empty", cidr, got)
		}
	}
}
