package utils

import (
	"fmt"
	"net"
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
