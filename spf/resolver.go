package spf

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/synqronlabs/raven/dns"
)

// DNS-related errors. These are re-exported from the dns package for convenience.
var (
	ErrDNSTimeout   = dns.ErrDNSTimeout
	ErrDNSError     = errors.New("spf: DNS query error")
	ErrDNSNotFound  = dns.ErrDNSNotFound
	ErrDNSSECFailed = dns.ErrDNSBogus
)

// Result contains information about a DNS lookup result.
type Result struct {
	// Authentic indicates if the DNS response was DNSSEC-validated.
	Authentic bool
}

// Resolver is the interface for DNS lookups required by SPF verification.
// This interface is specific to SPF needs and differs slightly from dns.Resolver.
type Resolver interface {
	// LookupTXT retrieves TXT records for the given domain.
	LookupTXT(ctx context.Context, name string) ([]string, Result, error)

	// LookupIP retrieves A and/or AAAA records for the given domain.
	// network can be "ip", "ip4", or "ip6".
	LookupIP(ctx context.Context, network, host string) ([]net.IP, Result, error)

	// LookupMX retrieves MX records for the given domain.
	LookupMX(ctx context.Context, name string) ([]*net.MX, Result, error)

	// LookupAddr performs a reverse DNS lookup.
	LookupAddr(ctx context.Context, addr string) ([]string, Result, error)
}

// ResolverConfig contains configuration for the DNS resolver.
// This is an alias to dns.ResolverConfig for convenience.
type ResolverConfig = dns.ResolverConfig

// DNSResolver implements the Resolver interface using github.com/miekg/dns.
// It wraps dns.DNSResolver to provide the SPF-specific Resolver interface.
type DNSResolver struct {
	r *dns.DNSResolver
}

// NewResolver creates a new DNS resolver with DNSSEC support.
// This is a convenience function that wraps dns.NewResolver.
func NewResolver(config ResolverConfig) *DNSResolver {
	return &DNSResolver{r: dns.NewResolver(config)}
}

// NewResolverWithDefaults creates a new DNS resolver with sensible defaults.
// It uses system nameservers and enables DNSSEC validation.
func NewResolverWithDefaults() *DNSResolver {
	return NewResolver(ResolverConfig{
		DNSSEC:  true,
		Timeout: 5 * time.Second,
		Retries: 2,
	})
}

// LookupTXT retrieves TXT records for the given domain.
func (r *DNSResolver) LookupTXT(ctx context.Context, name string) ([]string, Result, error) {
	result, err := r.r.LookupTXT(ctx, name)
	if err != nil {
		return nil, Result{Authentic: result.Authentic}, err
	}
	return result.Records, Result{Authentic: result.Authentic}, nil
}

// LookupIP retrieves A and/or AAAA records for the given domain.
func (r *DNSResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, Result, error) {
	// The dns package always fetches both A and AAAA, so we filter here
	result, err := r.r.LookupIP(ctx, host)
	if err != nil {
		return nil, Result{Authentic: result.Authentic}, err
	}

	// Filter by network type if needed
	if network == "ip" {
		return result.Records, Result{Authentic: result.Authentic}, nil
	}

	var filtered []net.IP
	for _, ip := range result.Records {
		if network == "ip4" && ip.To4() != nil {
			filtered = append(filtered, ip)
		} else if network == "ip6" && ip.To4() == nil {
			filtered = append(filtered, ip)
		}
	}

	if len(filtered) == 0 {
		return nil, Result{Authentic: result.Authentic}, ErrDNSNotFound
	}
	return filtered, Result{Authentic: result.Authentic}, nil
}

// LookupMX retrieves MX records for the given domain.
func (r *DNSResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, Result, error) {
	result, err := r.r.LookupMX(ctx, name)
	if err != nil {
		return nil, Result{Authentic: result.Authentic}, err
	}
	return result.Records, Result{Authentic: result.Authentic}, nil
}

// LookupAddr performs a reverse DNS lookup.
func (r *DNSResolver) LookupAddr(ctx context.Context, addr string) ([]string, Result, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, Result{}, errors.New("spf: invalid IP address")
	}
	result, err := r.r.LookupAddr(ctx, ip)
	if err != nil {
		return nil, Result{Authentic: result.Authentic}, err
	}
	return result.Records, Result{Authentic: result.Authentic}, nil
}

// StdResolver wraps the standard library net.Resolver to implement Resolver.
// This is useful when DNSSEC validation is not required.
type StdResolver struct {
	r *dns.StdResolver
}

// NewStdResolver creates a resolver using the standard library.
func NewStdResolver() *StdResolver {
	return &StdResolver{r: dns.NewStdResolver()}
}

// LookupTXT retrieves TXT records using the standard library.
func (r *StdResolver) LookupTXT(ctx context.Context, name string) ([]string, Result, error) {
	result, err := r.r.LookupTXT(ctx, name)
	if err != nil {
		return nil, Result{}, err
	}
	return result.Records, Result{Authentic: false}, nil
}

// LookupIP retrieves A and/or AAAA records using the standard library.
func (r *StdResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, Result, error) {
	// The dns package always fetches both, filter here
	result, err := r.r.LookupIP(ctx, host)
	if err != nil {
		return nil, Result{}, err
	}

	if network == "ip" {
		return result.Records, Result{Authentic: false}, nil
	}

	var filtered []net.IP
	for _, ip := range result.Records {
		if network == "ip4" && ip.To4() != nil {
			filtered = append(filtered, ip)
		} else if network == "ip6" && ip.To4() == nil {
			filtered = append(filtered, ip)
		}
	}

	if len(filtered) == 0 {
		return nil, Result{}, ErrDNSNotFound
	}
	return filtered, Result{Authentic: false}, nil
}

// LookupMX retrieves MX records using the standard library.
func (r *StdResolver) LookupMX(ctx context.Context, name string) ([]*net.MX, Result, error) {
	result, err := r.r.LookupMX(ctx, name)
	if err != nil {
		return nil, Result{}, err
	}
	return result.Records, Result{Authentic: false}, nil
}

// LookupAddr performs a reverse DNS lookup using the standard library.
func (r *StdResolver) LookupAddr(ctx context.Context, addr string) ([]string, Result, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, Result{}, errors.New("spf: invalid IP address")
	}
	result, err := r.r.LookupAddr(ctx, ip)
	if err != nil {
		return nil, Result{}, err
	}
	return result.Records, Result{Authentic: false}, nil
}
