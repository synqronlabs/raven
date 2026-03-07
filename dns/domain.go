package dns

import (
	"net"
	"strings"

	"golang.org/x/net/idna"
)

// IsValidSMTPHostname validates a hostname for SMTP HELO/EHLO commands.
// A hostname may be a domain name or an address literal.
func IsValidSMTPHostname(hostname string) bool {
	if hostname == "" {
		return false
	}

	if hostname[0] == '[' {
		return isValidAddressLiteral(hostname)
	}

	return IsValidDomain(hostname)
}

func isValidAddressLiteral(literal string) bool {
	if len(literal) < 3 || literal[len(literal)-1] != ']' {
		return false
	}

	inner := literal[1 : len(literal)-1]

	if len(inner) > 5 && (inner[:5] == "IPv6:" || inner[:5] == "ipv6:" || inner[:5] == "IPV6:") {
		ipStr := inner[5:]
		ip := net.ParseIP(ipStr)
		return ip != nil && ip.To4() == nil
	}

	ip := net.ParseIP(inner)
	return ip != nil && ip.To4() != nil
}

// IsValidDomain validates a domain name according to RFC 5321, RFC 1035,
// and RFC 5891 (IDNA). Supports internationalized domain names.
func IsValidDomain(domain string) bool {
	if domain == "" {
		return false
	}

	if domain[len(domain)-1] == '.' {
		domain = domain[:len(domain)-1]
	}

	if domain == "" {
		return false
	}

	if ip := net.ParseIP(domain); ip != nil {
		return false
	}

	ascii, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return false
	}

	if len(ascii) > 253 {
		return false
	}

	if strings.Contains(ascii, "..") || strings.HasPrefix(ascii, ".") {
		return false
	}

	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
	}

	return true
}
