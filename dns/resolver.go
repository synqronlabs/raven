package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
)

// ResolverConfig contains configuration for the DNS resolver.
type ResolverConfig struct {
	// Nameservers is a list of DNS servers to query (e.g., "8.8.8.8:53").
	// If empty, system resolvers from /etc/resolv.conf are used,
	// falling back to public DNS (8.8.8.8, 1.1.1.1).
	Nameservers []string

	// DNSSEC enables DNSSEC validation for queries.
	// Requires DNSSEC-validating upstream resolvers.
	// When enabled, the Authentic field in Result indicates validation status.
	DNSSEC bool

	// Timeout is the timeout for individual DNS queries. Default is 5 seconds.
	Timeout time.Duration

	// Retries is the number of retries for failed queries. Default is 2.
	Retries int
}

// DNSResolver implements the Resolver interface using github.com/miekg/dns.
// It provides DNSSEC validation support and configurable query behavior.
type DNSResolver struct {
	config ResolverConfig
	client *mdns.Client
}

// NewResolver creates a new DNS resolver with optional DNSSEC support.
func NewResolver(config ResolverConfig) *DNSResolver {
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second
	}
	if config.Retries == 0 {
		config.Retries = 2
	}
	if len(config.Nameservers) == 0 {
		config.Nameservers = getSystemNameservers()
	}

	return &DNSResolver{
		config: config,
		client: &mdns.Client{
			Timeout: config.Timeout,
		},
	}
}

// getSystemNameservers tries to get system DNS servers from resolv.conf.
func getSystemNameservers() []string {
	config, err := mdns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(config.Servers) == 0 {
		// Fallback to common public DNS servers
		return []string{"8.8.8.8:53", "1.1.1.1:53"}
	}

	servers := make([]string, 0, len(config.Servers))
	for _, s := range config.Servers {
		if !strings.Contains(s, ":") {
			s = s + ":53"
		}
		servers = append(servers, s)
	}
	return servers
}

// ensureAbsolute ensures the domain name ends with a dot (FQDN format).
func ensureAbsolute(name string) string {
	if !strings.HasSuffix(name, ".") {
		return name + "."
	}
	return name
}

// query performs a DNS query with retries and DNSSEC checking.
func (r *DNSResolver) query(ctx context.Context, name string, qtype uint16) (*mdns.Msg, bool, error) {
	m := new(mdns.Msg)
	m.SetQuestion(ensureAbsolute(name), qtype)
	m.RecursionDesired = true

	// Set DNSSEC OK bit if DNSSEC is enabled
	if r.config.DNSSEC {
		m.SetEdns0(4096, true) // Enable EDNS0 with DO bit
	}

	var lastErr error
	authentic := false

	for i := 0; i <= r.config.Retries; i++ {
		for _, server := range r.config.Nameservers {
			// Check context cancellation
			select {
			case <-ctx.Done():
				return nil, false, ctx.Err()
			default:
			}

			resp, _, err := r.client.ExchangeContext(ctx, m, server)
			if err != nil {
				lastErr = fmt.Errorf("dns query failed: %w", err)
				continue
			}

			// Check for DNSSEC authentication
			if r.config.DNSSEC && resp.AuthenticatedData {
				authentic = true
			}

			// Check response code
			switch resp.Rcode {
			case mdns.RcodeSuccess:
				return resp, authentic, nil
			case mdns.RcodeNameError: // NXDOMAIN
				return nil, authentic, ErrDNSNotFound
			case mdns.RcodeServerFailure:
				// SERVFAIL might indicate DNSSEC validation failure
				if r.config.DNSSEC {
					lastErr = ErrDNSBogus
				} else {
					lastErr = ErrDNSServFail
				}
				continue
			case mdns.RcodeRefused:
				lastErr = ErrDNSRefused
				continue
			default:
				lastErr = fmt.Errorf("dns: unexpected rcode %d", resp.Rcode)
				continue
			}
		}
	}

	if lastErr != nil {
		return nil, false, lastErr
	}
	return nil, false, ErrDNSServFail
}

// LookupTXT retrieves TXT records for the given domain.
func (r *DNSResolver) LookupTXT(ctx context.Context, name string) (Result[string], error) {
	resp, authentic, err := r.query(ctx, name, mdns.TypeTXT)
	if err != nil {
		return Result[string]{Authentic: authentic}, err
	}

	var records []string
	for _, rr := range resp.Answer {
		if txt, ok := rr.(*mdns.TXT); ok {
			// TXT records may be split into multiple character strings, join them
			// per RFC 7208 Section 3.3
			records = append(records, strings.Join(txt.Txt, ""))
		}
	}

	if len(records) == 0 {
		return Result[string]{Authentic: authentic}, ErrDNSNotFound
	}

	return Result[string]{Records: records, Authentic: authentic}, nil
}

// LookupIP retrieves A and/or AAAA records for the given domain.
func (r *DNSResolver) LookupIP(ctx context.Context, domain string) (Result[net.IP], error) {
	var ips []net.IP
	authentic := true
	var lastErr error

	// Query A records
	resp, auth, err := r.query(ctx, domain, mdns.TypeA)
	if err != nil && err != ErrDNSNotFound {
		lastErr = err
	} else {
		authentic = authentic && auth
		if resp != nil {
			for _, rr := range resp.Answer {
				if a, ok := rr.(*mdns.A); ok {
					ips = append(ips, a.A)
				}
			}
		}
	}

	// Query AAAA records
	resp, auth, err = r.query(ctx, domain, mdns.TypeAAAA)
	if err != nil && err != ErrDNSNotFound {
		if lastErr == nil {
			lastErr = err
		}
	} else {
		authentic = authentic && auth
		if resp != nil {
			for _, rr := range resp.Answer {
				if aaaa, ok := rr.(*mdns.AAAA); ok {
					ips = append(ips, aaaa.AAAA)
				}
			}
		}
	}

	if len(ips) == 0 {
		if lastErr != nil {
			return Result[net.IP]{Authentic: authentic}, lastErr
		}
		return Result[net.IP]{Authentic: authentic}, ErrDNSNotFound
	}

	return Result[net.IP]{Records: ips, Authentic: authentic}, nil
}

// LookupMX retrieves MX records for the given domain.
func (r *DNSResolver) LookupMX(ctx context.Context, name string) (Result[*net.MX], error) {
	resp, authentic, err := r.query(ctx, name, mdns.TypeMX)
	if err != nil {
		return Result[*net.MX]{Authentic: authentic}, err
	}

	var records []*net.MX
	for _, rr := range resp.Answer {
		if mx, ok := rr.(*mdns.MX); ok {
			records = append(records, &net.MX{
				Host: mx.Mx,
				Pref: mx.Preference,
			})
		}
	}

	if len(records) == 0 {
		return Result[*net.MX]{Authentic: authentic}, ErrDNSNotFound
	}

	return Result[*net.MX]{Records: records, Authentic: authentic}, nil
}

// LookupAddr performs a reverse DNS lookup for the given IP address.
func (r *DNSResolver) LookupAddr(ctx context.Context, ip net.IP) (Result[string], error) {
	if ip == nil {
		return Result[string]{}, fmt.Errorf("dns: nil IP address")
	}

	// Generate reverse DNS name (e.g., 1.0.168.192.in-addr.arpa.)
	arpa, err := mdns.ReverseAddr(ip.String())
	if err != nil {
		return Result[string]{}, fmt.Errorf("dns: invalid IP for reverse lookup: %w", err)
	}

	resp, authentic, err := r.query(ctx, arpa, mdns.TypePTR)
	if err != nil {
		return Result[string]{Authentic: authentic}, err
	}

	var names []string
	for _, rr := range resp.Answer {
		if ptr, ok := rr.(*mdns.PTR); ok {
			names = append(names, ptr.Ptr)
		}
	}

	if len(names) == 0 {
		return Result[string]{Authentic: authentic}, ErrDNSNotFound
	}

	return Result[string]{Records: names, Authentic: authentic}, nil
}

// Config returns the resolver's current configuration.
func (r *DNSResolver) Config() ResolverConfig {
	return r.config
}
