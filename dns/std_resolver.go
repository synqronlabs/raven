package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

// StdResolver implements the Resolver interface using the standard library net package.
// This resolver does not support DNSSEC validation (Authentic will always be false).
// Use DNSResolver for DNSSEC support.
type StdResolver struct {
	resolver *net.Resolver
}

// NewStdResolver creates a resolver using the standard library.
// This is useful when DNSSEC validation is not required.
func NewStdResolver() *StdResolver {
	return &StdResolver{
		resolver: net.DefaultResolver,
	}
}

// NewStdResolverWithDialer creates a resolver using a custom dialer.
// This allows configuring custom DNS servers while using the stdlib interface.
func NewStdResolverWithDialer(dial func(ctx context.Context, network, address string) (net.Conn, error)) *StdResolver {
	return &StdResolver{
		resolver: &net.Resolver{
			PreferGo: true,
			Dial:     dial,
		},
	}
}

// LookupTXT retrieves TXT records using the standard library.
func (r *StdResolver) LookupTXT(ctx context.Context, name string) (Result[string], error) {
	// Strip trailing dot for stdlib compatibility
	name = strings.TrimSuffix(name, ".")

	records, err := r.resolver.LookupTXT(ctx, name)
	if err != nil {
		return Result[string]{}, convertError(err)
	}

	if len(records) == 0 {
		return Result[string]{}, ErrDNSNotFound
	}

	return Result[string]{Records: records, Authentic: false}, nil
}

// LookupIP retrieves A and AAAA records using the standard library.
func (r *StdResolver) LookupIP(ctx context.Context, domain string) (Result[net.IP], error) {
	// Strip trailing dot for stdlib compatibility
	domain = strings.TrimSuffix(domain, ".")

	ips, err := r.resolver.LookupIP(ctx, "ip", domain)
	if err != nil {
		return Result[net.IP]{}, convertError(err)
	}

	if len(ips) == 0 {
		return Result[net.IP]{}, ErrDNSNotFound
	}

	return Result[net.IP]{Records: ips, Authentic: false}, nil
}

// LookupMX retrieves MX records using the standard library.
func (r *StdResolver) LookupMX(ctx context.Context, name string) (Result[*net.MX], error) {
	// Strip trailing dot for stdlib compatibility
	name = strings.TrimSuffix(name, ".")

	records, err := r.resolver.LookupMX(ctx, name)
	if err != nil {
		return Result[*net.MX]{}, convertError(err)
	}

	if len(records) == 0 {
		return Result[*net.MX]{}, ErrDNSNotFound
	}

	return Result[*net.MX]{Records: records, Authentic: false}, nil
}

// LookupAddr performs a reverse DNS lookup using the standard library.
func (r *StdResolver) LookupAddr(ctx context.Context, ip net.IP) (Result[string], error) {
	if ip == nil {
		return Result[string]{}, fmt.Errorf("dns: nil IP address")
	}

	names, err := r.resolver.LookupAddr(ctx, ip.String())
	if err != nil {
		return Result[string]{}, convertError(err)
	}

	if len(names) == 0 {
		return Result[string]{}, ErrDNSNotFound
	}

	// Ensure names are absolute (with trailing dot)
	for i, name := range names {
		if !strings.HasSuffix(name, ".") {
			names[i] = name + "."
		}
	}

	return Result[string]{Records: names, Authentic: false}, nil
}

// convertError converts standard library DNS errors to package errors.
func convertError(err error) error {
	if err == nil {
		return nil
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return ErrDNSNotFound
		}
		if dnsErr.IsTimeout {
			return ErrDNSTimeout
		}
		if dnsErr.IsTemporary {
			return ErrDNSServFail
		}
	}

	return fmt.Errorf("dns lookup failed: %w", err)
}
