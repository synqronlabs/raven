package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"unicode/utf8"
)

func GetIPFromAddr(addr net.Addr) (net.IP, error) {
	if addr == nil {
		return nil, fmt.Errorf("address is nil")
	}

	// Extract IP from the address
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

// ContainsNonASCII checks if a string contains any non-ASCII characters (bytes > 127).
// This works for both string validation (addresses, headers) and message content validation.
func ContainsNonASCII(s string) bool {
	for _, v := range s {
		if v >= utf8.RuneSelf {
			return true
		}
	}
	return false
}

// GenerateID creates a unique identifier using random bytes.
func GenerateID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
