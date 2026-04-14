// Package dns provides DNS resolution utilities for email authentication.
//
// This package is designed to be used by SPF, DKIM, DMARC, and other email authentication
// mechanisms that require DNS lookups with optional DNSSEC awareness.
//
// In DNSSEC mode, DNSResolver acts as a stub resolver and trusts a validating recursive
// resolver such as Unbound. It sets the DO bit on queries, treats the AD bit as authenticated
// status, and classifies explicit RFC 8914 EDE "DNSSEC Bogus" responses as ErrDNSBogus. It does
// not perform local DNSSEC chain validation.
//
// The package provides two resolver implementations:
//   - DNSResolver: Uses github.com/miekg/dns with a validating recursive resolver
//   - StdResolver: Uses the standard library net package (no DNSSEC status)
//
// Basic Usage:
//
//	resolver := dns.NewResolver(dns.ResolverConfig{
//	    Nameservers: []string{"127.0.0.1:53"}, // Local validating resolver, e.g. Unbound
//	    DNSSEC:      true,
//	})
//
//	result, err := resolver.LookupTXT(ctx, "example.com")
//	if err != nil {
//	    // Handle error
//	}
//	for _, txt := range result.Records {
//	    fmt.Println(txt)
//	}
//	if result.Authentic {
//	    // Response was authenticated by the validating resolver
//	}
package dns

import (
	"context"
	"errors"
	"net"
)

// DNS lookup errors.
var (
	// ErrDNSTimeout indicates a DNS query timed out.
	ErrDNSTimeout = errors.New("dns: query timeout")

	// ErrDNSNotFound indicates no records were found (NXDOMAIN or empty answer).
	ErrDNSNotFound = errors.New("dns: no records found")

	// ErrDNSServFail indicates a server failure (SERVFAIL).
	ErrDNSServFail = errors.New("dns: server failure")

	// ErrDNSRefused indicates the query was refused.
	ErrDNSRefused = errors.New("dns: query refused")

	// ErrDNSBogus indicates the validating recursive resolver reported DNSSEC Bogus.
	ErrDNSBogus = errors.New("dns: validating resolver reported DNSSEC bogus")

	// ErrDNSNoNameservers indicates no nameservers are configured.
	ErrDNSNoNameservers = errors.New("dns: no nameservers configured")
)

// Result wraps DNS lookup results with validating-resolver DNSSEC status.
type Result[T any] struct {
	// Records contains the DNS records returned by the query.
	Records []T

	// Authentic indicates whether a trusted validating recursive resolver marked the
	// response as authenticated via the AD bit. This is only meaningful when using a
	// resolver configured for DNSSEC.
	Authentic bool
}

// Resolver defines the interface for DNS lookups used by email authentication.
// Implementations should handle timeouts, retries, and error classification.
type Resolver interface {
	// LookupTXT returns TXT records for the given domain.
	// Multiple TXT records are returned as separate strings.
	// Character strings within a single TXT record are concatenated per RFC 7208.
	LookupTXT(ctx context.Context, domain string) (Result[string], error)

	// LookupIP returns A and AAAA records for the given domain.
	// Both IPv4 and IPv6 addresses are returned in a single result.
	LookupIP(ctx context.Context, domain string) (Result[net.IP], error)

	// LookupMX returns MX records for the given domain, sorted by preference.
	LookupMX(ctx context.Context, domain string) (Result[*net.MX], error)

	// LookupAddr performs a reverse DNS lookup for the given IP address.
	LookupAddr(ctx context.Context, ip net.IP) (Result[string], error)
}

// IsNotFound returns true if the error indicates no records were found.
// This includes NXDOMAIN responses and empty answer sections.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrDNSNotFound)
}

// IsTimeout returns true if the error indicates a DNS timeout.
func IsTimeout(err error) bool {
	return errors.Is(err, ErrDNSTimeout)
}

// IsServFail returns true if the error indicates a server failure.
func IsServFail(err error) bool {
	return errors.Is(err, ErrDNSServFail)
}

// IsTemporary returns true if the error is potentially temporary and
// the lookup could be retried later. This includes timeouts and server failures.
func IsTemporary(err error) bool {
	return IsTimeout(err) || IsServFail(err)
}
