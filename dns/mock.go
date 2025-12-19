package dns

import (
	"context"
	"net"
	"slices"
)

// MockResolver is a Resolver used for testing.
// Set DNS records in the fields, which map FQDNs (with trailing dot) to values.
type MockResolver struct {
	PTR  map[string][]string
	A    map[string][]string
	AAAA map[string][]string
	TXT  map[string][]string
	MX   map[string][]*net.MX

	// Fail contains records that will return a temporary error (SERVFAIL).
	// Format: "type name", e.g. "txt example.com." where type is lowercase.
	Fail []string

	// AllAuthentic sets the default value for Authentic in responses.
	// Overridden by Authentic and Inauthentic lists.
	AllAuthentic bool

	// Authentic contains records that will have Authentic=true.
	// Format: "type name", e.g. "txt example.com."
	Authentic []string

	// Inauthentic contains records that will have Authentic=false.
	// Format: "type name", e.g. "txt example.com."
	Inauthentic []string
}

var _ Resolver = MockResolver{}

// mockReq represents a mock DNS request.
type mockReq struct {
	Type string // E.g. "txt", "a", "aaaa", "mx", "ptr"
	Name string // FQDN with trailing dot
}

func (mr mockReq) String() string {
	return mr.Type + " " + mr.Name
}

// ensureFQDN ensures the name ends with a dot.
func ensureFQDN(name string) string {
	if len(name) == 0 || name[len(name)-1] != '.' {
		return name + "."
	}
	return name
}

// result checks for failures and returns the authentication status.
func (r MockResolver) result(ctx context.Context, mr mockReq) (Result[string], error) {
	result := Result[string]{Authentic: r.AllAuthentic}

	if err := ctx.Err(); err != nil {
		return result, err
	}

	// Check for configured failures
	if slices.Contains(r.Fail, mr.String()) {
		return result, ErrDNSServFail
	}

	// Update authentic status
	if slices.Contains(r.Authentic, mr.String()) {
		result.Authentic = true
	}
	if slices.Contains(r.Inauthentic, mr.String()) {
		result.Authentic = false
	}

	return result, nil
}

// LookupTXT returns TXT records for the given domain.
func (r MockResolver) LookupTXT(ctx context.Context, name string) (Result[string], error) {
	fqdn := ensureFQDN(name)
	mr := mockReq{"txt", fqdn}

	result, err := r.result(ctx, mr)
	if err != nil {
		return result, err
	}

	records, ok := r.TXT[fqdn]
	if !ok || len(records) == 0 {
		return result, ErrDNSNotFound
	}

	result.Records = records
	return result, nil
}

// LookupIP returns A and AAAA records for the given domain.
func (r MockResolver) LookupIP(ctx context.Context, domain string) (Result[net.IP], error) {
	fqdn := ensureFQDN(domain)

	authentic := r.AllAuthentic

	// Check for A record failures
	mrA := mockReq{"a", fqdn}
	if slices.Contains(r.Fail, mrA.String()) {
		return Result[net.IP]{Authentic: authentic}, ErrDNSServFail
	}
	if slices.Contains(r.Authentic, mrA.String()) {
		authentic = true
	}
	if slices.Contains(r.Inauthentic, mrA.String()) {
		authentic = false
	}

	// Check for AAAA record failures
	mrAAAA := mockReq{"aaaa", fqdn}
	if slices.Contains(r.Fail, mrAAAA.String()) {
		return Result[net.IP]{Authentic: authentic}, ErrDNSServFail
	}
	if slices.Contains(r.Authentic, mrAAAA.String()) {
		authentic = true
	}
	if slices.Contains(r.Inauthentic, mrAAAA.String()) {
		authentic = false
	}

	var ips []net.IP

	// Get A records
	for _, ip := range r.A[fqdn] {
		ips = append(ips, net.ParseIP(ip))
	}

	// Get AAAA records
	for _, ip := range r.AAAA[fqdn] {
		ips = append(ips, net.ParseIP(ip))
	}

	if len(ips) == 0 {
		return Result[net.IP]{Authentic: authentic}, ErrDNSNotFound
	}

	return Result[net.IP]{Records: ips, Authentic: authentic}, nil
}

// LookupMX returns MX records for the given domain.
func (r MockResolver) LookupMX(ctx context.Context, name string) (Result[*net.MX], error) {
	fqdn := ensureFQDN(name)
	mr := mockReq{"mx", fqdn}

	authentic := r.AllAuthentic
	if slices.Contains(r.Fail, mr.String()) {
		return Result[*net.MX]{Authentic: authentic}, ErrDNSServFail
	}
	if slices.Contains(r.Authentic, mr.String()) {
		authentic = true
	}
	if slices.Contains(r.Inauthentic, mr.String()) {
		authentic = false
	}

	records, ok := r.MX[fqdn]
	if !ok || len(records) == 0 {
		return Result[*net.MX]{Authentic: authentic}, ErrDNSNotFound
	}

	return Result[*net.MX]{Records: records, Authentic: authentic}, nil
}

// LookupAddr performs a reverse DNS lookup.
func (r MockResolver) LookupAddr(ctx context.Context, ip net.IP) (Result[string], error) {
	ipStr := ip.String()
	mr := mockReq{"ptr", ipStr}

	authentic := r.AllAuthentic
	if slices.Contains(r.Fail, mr.String()) {
		return Result[string]{Authentic: authentic}, ErrDNSServFail
	}
	if slices.Contains(r.Authentic, mr.String()) {
		authentic = true
	}
	if slices.Contains(r.Inauthentic, mr.String()) {
		authentic = false
	}

	records, ok := r.PTR[ipStr]
	if !ok || len(records) == 0 {
		return Result[string]{Authentic: authentic}, ErrDNSNotFound
	}

	return Result[string]{Records: records, Authentic: authentic}, nil
}
