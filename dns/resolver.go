package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
)

// ResolverConfig contains configuration for the DNS resolver.
type ResolverConfig struct {
	// Nameservers is a list of DNS servers to query (e.g., "127.0.0.1:53").
	// If empty, system resolvers from /etc/resolv.conf are used. If none are found,
	// lookups fail with ErrDNSNoNameservers.
	Nameservers []string

	// DNSSEC enables trusting DNSSEC status from validating recursive resolvers.
	// When enabled, the resolver sets the DO bit on queries, trusts the AD bit on
	// responses, and maps explicit RFC 8914 EDE DNSSEC Bogus responses to ErrDNSBogus.
	// It does not perform local DNSSEC chain validation.
	DNSSEC bool

	// Timeout is the timeout for individual DNS queries. Default is 5 seconds.
	Timeout time.Duration

	// Retries is the number of retries for failed queries. Default is 2.
	Retries int
}

// DNSResolver implements the Resolver interface using github.com/miekg/dns.
// It acts as a stub resolver and can trust a validating recursive resolver for
// DNSSEC status.
type DNSResolver struct {
	config ResolverConfig
	client *mdns.Client
}

// NewResolver creates a new DNS resolver with optional validating-recursive-resolver
// DNSSEC support.
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

// getSystemNameservers returns DNS servers from resolv.conf.
func getSystemNameservers() []string {
	config, err := mdns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(config.Servers) == 0 {
		return nil
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

func classifyQueryError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(ErrDNSTimeout, err)
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return errors.Join(ErrDNSTimeout, err)
	}

	return err
}

func dnssecBogusError(resp *mdns.Msg) error {
	if resp == nil {
		return nil
	}

	opt := resp.IsEdns0()
	if opt == nil {
		return nil
	}

	for _, option := range opt.Option {
		ede, ok := option.(*mdns.EDNS0_EDE)
		if !ok || ede.InfoCode != mdns.ExtendedErrorCodeDNSBogus {
			continue
		}
		if ede.ExtraText == "" {
			return ErrDNSBogus
		}
		return fmt.Errorf("%w: %s", ErrDNSBogus, ede.ExtraText)
	}

	return nil
}

// query performs a DNS query with retries and validating-recursive-resolver DNSSEC checks.
func (r *DNSResolver) query(ctx context.Context, name string, qtype uint16) (*mdns.Msg, bool, error) {
	absName := ensureAbsolute(name)
	if len(r.config.Nameservers) == 0 {
		return nil, false, fmt.Errorf("query for %q has no nameservers configured: %w", absName, ErrDNSNoNameservers)
	}

	m := new(mdns.Msg)
	m.SetQuestion(absName, qtype)
	m.RecursionDesired = true

	// Set the DO bit when trusting a validating recursive resolver for DNSSEC status.
	if r.config.DNSSEC {
		m.SetEdns0(4096, true)
	}

	var lastErr error
	authentic := false

	for i := 0; i <= r.config.Retries; i++ {
		for _, server := range r.config.Nameservers {
			// Check context cancellation
			select {
			case <-ctx.Done():
				return nil, false, fmt.Errorf("dns query canceled for %q: %w", absName, classifyQueryError(ctx.Err()))
			default:
			}

			resp, _, err := r.client.ExchangeContext(ctx, m, server)
			if err != nil {
				lastErr = fmt.Errorf("querying DNS server %s for %q (type=%d): %w", server, absName, qtype, classifyQueryError(err))
				continue
			}

			// Trust AD when a validating recursive resolver authenticated the response.
			if r.config.DNSSEC && resp.AuthenticatedData {
				authentic = true
			}

			// Check response code
			switch resp.Rcode {
			case mdns.RcodeSuccess:
				return resp, authentic, nil
			case mdns.RcodeNameError: // NXDOMAIN
				return nil, authentic, fmt.Errorf("query for %q returned NXDOMAIN: %w", absName, ErrDNSNotFound)
			case mdns.RcodeServerFailure:
				if r.config.DNSSEC {
					if bogusErr := dnssecBogusError(resp); bogusErr != nil {
						lastErr = fmt.Errorf("query for %q returned SERVFAIL with explicit DNSSEC failure: %w", absName, bogusErr)
						continue
					}
				}
				lastErr = fmt.Errorf("query for %q returned SERVFAIL: %w", absName, ErrDNSServFail)
				continue
			case mdns.RcodeRefused:
				lastErr = fmt.Errorf("query for %q was refused: %w", absName, ErrDNSRefused)
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
		return Result[string]{Authentic: authentic}, fmt.Errorf("resolving TXT records for %q: %w", name, err)
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
		return Result[string]{Authentic: authentic}, fmt.Errorf("%w: no TXT records for %q", ErrDNSNotFound, name)
	}

	return Result[string]{Records: records, Authentic: authentic}, nil
}

// LookupCNAME retrieves CNAME records for the given domain.
func (r *DNSResolver) LookupCNAME(ctx context.Context, name string) (Result[string], error) {
	resp, authentic, err := r.query(ctx, name, mdns.TypeCNAME)
	if err != nil {
		return Result[string]{Authentic: authentic}, fmt.Errorf("resolving CNAME records for %q: %w", name, err)
	}

	var records []string
	for _, rr := range resp.Answer {
		if cname, ok := rr.(*mdns.CNAME); ok {
			records = append(records, ensureAbsolute(cname.Target))
		}
	}

	if len(records) == 0 {
		return Result[string]{Authentic: authentic}, fmt.Errorf("%w: no CNAME records for %q", ErrDNSNotFound, name)
	}

	return Result[string]{Records: records, Authentic: authentic}, nil
}

// LookupIP retrieves A and/or AAAA records for the given domain.
func (r *DNSResolver) LookupIP(ctx context.Context, domain string) (Result[net.IP], error) {
	var ips []net.IP
	authentic := r.config.DNSSEC
	var lastErr error

	// Query A records
	resp, auth, err := r.query(ctx, domain, mdns.TypeA)
	if err != nil {
		if !errors.Is(err, ErrDNSNotFound) {
			lastErr = fmt.Errorf("resolving A records for %q: %w", domain, err)
		} else {
			authentic = authentic && auth
		}
	} else {
		authentic = authentic && auth
		for _, rr := range resp.Answer {
			if a, ok := rr.(*mdns.A); ok {
				ips = append(ips, a.A)
			}
		}
	}

	// Query AAAA records
	resp, auth, err = r.query(ctx, domain, mdns.TypeAAAA)
	if err != nil {
		if !errors.Is(err, ErrDNSNotFound) {
			if lastErr == nil {
				lastErr = fmt.Errorf("resolving AAAA records for %q: %w", domain, err)
			}
		} else {
			authentic = authentic && auth
		}
	} else {
		authentic = authentic && auth
		for _, rr := range resp.Answer {
			if aaaa, ok := rr.(*mdns.AAAA); ok {
				ips = append(ips, aaaa.AAAA)
			}
		}
	}

	if len(ips) == 0 {
		if lastErr != nil {
			return Result[net.IP]{Authentic: authentic}, lastErr
		}
		return Result[net.IP]{Authentic: authentic}, fmt.Errorf("%w: no A or AAAA records for %q", ErrDNSNotFound, domain)
	}

	return Result[net.IP]{Records: ips, Authentic: authentic}, nil
}

// LookupMX retrieves MX records for the given domain.
func (r *DNSResolver) LookupMX(ctx context.Context, name string) (Result[*net.MX], error) {
	resp, authentic, err := r.query(ctx, name, mdns.TypeMX)
	if err != nil {
		return Result[*net.MX]{Authentic: authentic}, fmt.Errorf("resolving MX records for %q: %w", name, err)
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
		return Result[*net.MX]{Authentic: authentic}, fmt.Errorf("%w: no MX records for %q", ErrDNSNotFound, name)
	}

	sort.Slice(records, func(i, j int) bool {
		if records[i].Pref == records[j].Pref {
			return records[i].Host < records[j].Host
		}
		return records[i].Pref < records[j].Pref
	})

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
		return Result[string]{Authentic: authentic}, fmt.Errorf("resolving PTR records for %q: %w", ip.String(), err)
	}

	var names []string
	for _, rr := range resp.Answer {
		if ptr, ok := rr.(*mdns.PTR); ok {
			names = append(names, ptr.Ptr)
		}
	}

	if len(names) == 0 {
		return Result[string]{Authentic: authentic}, fmt.Errorf("%w: no PTR records for %q", ErrDNSNotFound, ip.String())
	}

	return Result[string]{Records: names, Authentic: authentic}, nil
}

// Config returns the resolver's current configuration.
func (r *DNSResolver) Config() ResolverConfig {
	return r.config
}
