package dns

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/synqronlabs/raven/utils"
)

// ReverseDNSLookup performs a reverse DNS lookup for the given network address.
// It extracts the IP address from the net.Addr and queries for PTR records.
// Returns the first PTR record found, or an error if the lookup fails.
func ReverseDNSLookup(addr net.Addr) (string, error) {
	if addr == nil {
		return "", fmt.Errorf("address is nil")
	}

	// Extract IP from the address
	ip, err := utils.GetIPFromAddr(addr)
	if err != nil {
		return "", err
	}

	// Create reverse DNS query name (arpa format)
	arpa, err := dns.ReverseAddr(ip.String())
	if err != nil {
		return "", fmt.Errorf("failed to create reverse address: %w", err)
	}

	// Create DNS message
	msg := new(dns.Msg)
	msg.SetQuestion(arpa, dns.TypePTR)
	msg.RecursionDesired = true

	// Use default DNS resolver (typically from /etc/resolv.conf)
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return "", fmt.Errorf("failed to read DNS config: %w", err)
	}

	client := new(dns.Client)
	var lastErr error

	// Try each nameserver
	for _, server := range config.Servers {
		r, _, err := client.Exchange(msg, net.JoinHostPort(server, config.Port))
		if err != nil {
			lastErr = err
			continue
		}

		if r.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("DNS query failed with rcode: %s", dns.RcodeToString[r.Rcode])
			continue
		}

		// Extract PTR record
		for _, ans := range r.Answer {
			if ptr, ok := ans.(*dns.PTR); ok {
				// Remove trailing dot from PTR record
				return strings.TrimSuffix(ptr.Ptr, "."), nil
			}
		}
	}

	if lastErr != nil {
		return "", fmt.Errorf("reverse DNS lookup failed: %w", lastErr)
	}

	return "", fmt.Errorf("no PTR records found for %s", ip.String())
}
