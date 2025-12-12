package utils

import (
	"fmt"
	"math/rand/v2"
	"net"
	"time"
	"unicode/utf8"

	"github.com/oklog/ulid/v2"
)

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
