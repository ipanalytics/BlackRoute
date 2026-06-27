// Package domainx provides shared IP/CIDR utilities used across the pipeline.
package domainx

import (
	"net/netip"
	"strings"
)

var reservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
}

// IsPublicIP returns true iff ip is a globally-routable unicast address.
// Filters: loopback, link-local, multicast, unspecified, RFC1918 private,
// CGNAT (100.64.0.0/10), and IPv4 link-local (169.254/16).
func IsPublicIP(ip netip.Addr) bool {
	if !ip.IsValid() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsPrivate() ||
		!ip.IsGlobalUnicast() || isReservedPrefix(ip) {
		return false
	}
	if ip.Is4() {
		b := ip.As4()
		// CGNAT 100.64.0.0/10
		if b[0] == 100 && (b[1]&0xC0) == 64 {
			return false
		}
		// link-local 169.254.0.0/16
		if b[0] == 169 && b[1] == 254 {
			return false
		}
	}
	return true
}

func isReservedPrefix(ip netip.Addr) bool {
	for _, prefix := range reservedPrefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// NormalizeIP returns the canonical string form of an IP and its version.
func NormalizeIP(raw string) (string, int) {
	ip, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return "", 0
	}
	ip = ip.Unmap()
	if ip.Is4() {
		return ip.String(), 4
	}
	return ip.String(), 6
}

// NormalizePublicIP returns a canonical public IP. Private, reserved, local,
// multicast, and unspecified addresses are ignored by design.
func NormalizePublicIP(raw string) (string, int) {
	ip, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return "", 0
	}
	ip = ip.Unmap()
	if !IsPublicIP(ip) {
		return "", 0
	}
	if ip.Is4() {
		return ip.String(), 4
	}
	return ip.String(), 6
}

// NormalizeCIDR canonicalizes a CIDR (1.2.3.4/24 → 1.2.3.0/24).
func NormalizeCIDR(raw string) (string, int) {
	p, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		return "", 0
	}
	p = p.Masked()
	if p.Addr().Is4() {
		return p.String(), 4
	}
	return p.String(), 6
}

// MinV4PrefixBits / MinV6PrefixBits guard against catastrophically wide blocks.
const (
	MinV4PrefixBits = 8
	MinV6PrefixBits = 16
)

func NormalizePublicCIDR(cidr string) string {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return ""
	}
	p = p.Masked()
	isV4 := p.Addr().Is4()

	if isV4 && p.Bits() < MinV4PrefixBits {
		return ""
	}
	if !isV4 && p.Bits() < MinV6PrefixBits {
		return ""
	}
	if !IsPublicIP(p.Addr()) {
		return ""
	}
	return p.String()
}
