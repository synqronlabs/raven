package utils

import (
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/oklog/ulid/v2"
	"golang.org/x/net/idna"
)

// GetIPFromAddr extracts the IP address from a net.Addr
func GetIPFromAddr(addr net.Addr) (net.IP, error) {
	if addr == nil {
		return nil, fmt.Errorf("address is nil")
	}

	var ip net.IP
	switch a := addr.(type) {
	case *net.TCPAddr:
		ip = a.IP
	case *net.UDPAddr:
		ip = a.IP
	case *net.IPAddr:
		ip = a.IP
	default:
		// Try to parse from string representation
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			// Maybe it's just an IP without port
			host = addr.String()
		}
		ip = net.ParseIP(host)
		if ip == nil {
			return nil, fmt.Errorf("unable to extract IP from address: %v", addr)
		}
	}
	return ip, nil
}

// ContainsNonASCII checks if a string contains non-ASCII characters.
func ContainsNonASCII(s string) bool {
	for _, v := range s {
		if v >= utf8.RuneSelf {
			return true
		}
	}
	return false
}

type fastEntropy struct{}

func (fastEntropy) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(rand.Uint32())
	}
	return len(p), nil
}

var entropy = ulid.Monotonic(fastEntropy{}, 0)

// GenerateID creates a unique identifier using ULID.
func GenerateID() string {
	return ulid.MustNew(ulid.Timestamp(time.Now()), entropy).String()
}

// IsValidSMTPHostname validates a hostname for SMTP HELO/EHLO commands.
// According to RFC 5321, the hostname can be either:
// - A valid domain name (e.g., "mail.example.com")
// - An address literal (e.g., "[192.168.1.1]" or "[IPv6:2001:db8::1]")
func IsValidSMTPHostname(hostname string) bool {
	if hostname == "" {
		return false
	}

	// Check for address literal (RFC 5321 section 4.1.3)
	if hostname[0] == '[' {
		return isValidAddressLiteral(hostname)
	}

	// Otherwise, validate as domain name
	return IsValidDomain(hostname)
}

// isValidAddressLiteral validates an address literal like [192.168.1.1] or [IPv6:2001:db8::1].
func isValidAddressLiteral(literal string) bool {
	if len(literal) < 3 || literal[len(literal)-1] != ']' {
		return false
	}

	inner := literal[1 : len(literal)-1]

	// Check for IPv6 prefix (case-insensitive)
	if len(inner) > 5 && (inner[:5] == "IPv6:" || inner[:5] == "ipv6:" || inner[:5] == "IPV6:") {
		ipStr := inner[5:]
		ip := net.ParseIP(ipStr)
		return ip != nil && ip.To4() == nil // Must be IPv6
	}

	// Otherwise treat as IPv4
	ip := net.ParseIP(inner)
	return ip != nil && ip.To4() != nil // Must be IPv4
}

// IsValidDomain validates a domain name according to RFC 5321, RFC 1035, and RFC 5891 (IDNA).
// Supports internationalized domain names (IDN) with Unicode characters.
func IsValidDomain(domain string) bool {
	if domain == "" {
		return false
	}

	// Remove trailing dot if present (FQDN form)
	if domain[len(domain)-1] == '.' {
		domain = domain[:len(domain)-1]
	}

	if domain == "" {
		return false
	}

	// Reject bare IP addresses - they must use address literal format
	if ip := net.ParseIP(domain); ip != nil {
		return false
	}

	// Use IDNA profile for validation (converts to ASCII/Punycode)
	// This handles both ASCII domains and internationalized domain names
	ascii, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return false
	}

	// RFC 1035: max 253 characters for full domain name (in ASCII form)
	if len(ascii) > 253 {
		return false
	}

	// Verify no empty labels (e.g., "example..com")
	if strings.Contains(ascii, "..") || strings.HasPrefix(ascii, ".") {
		return false
	}

	// Verify each label is at most 63 characters (RFC 1035)
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
	}

	return true
}
