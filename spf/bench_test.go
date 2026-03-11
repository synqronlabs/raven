package spf

import (
	"context"
	"net"
	"testing"
)

// benchSPFResolver is a map-backed implementation of the spf.Resolver interface
// used for benchmarks so that DNS latency is not measured.
type benchSPFResolver struct {
	txt map[string][]string
	a   map[string][]net.IP
	mx  map[string][]*net.MX
}

func (r *benchSPFResolver) LookupTXT(_ context.Context, name string) ([]string, Result, error) {
	recs, ok := r.txt[name]
	if !ok {
		return nil, Result{}, ErrDNSNotFound
	}
	return recs, Result{}, nil
}

func (r *benchSPFResolver) LookupIP(_ context.Context, network, host string) ([]net.IP, Result, error) {
	var ips []net.IP
	if network == "ip" || network == "ip4" {
		ips = append(ips, r.a[host]...)
	}
	if len(ips) == 0 {
		return nil, Result{}, ErrDNSNotFound
	}
	return ips, Result{}, nil
}

func (r *benchSPFResolver) LookupMX(_ context.Context, name string) ([]*net.MX, Result, error) {
	recs, ok := r.mx[name]
	if !ok {
		return nil, Result{}, ErrDNSNotFound
	}
	return recs, Result{}, nil
}

func (*benchSPFResolver) LookupAddr(_ context.Context, _ string) ([]string, Result, error) {
	return nil, Result{}, ErrDNSNotFound
}

// newBenchResolver builds a resolver that serves a realistic SPF policy tree:
//
//	example.com  ->  v=spf1 include:_spf.example.com ip4:198.51.100.0/24 -all
//	_spf.example.com -> v=spf1 ip4:192.0.2.0/24 a:mail.example.com -all
//	mail.example.com  A  192.0.2.1
func newBenchResolver() *benchSPFResolver {
	return &benchSPFResolver{
		txt: map[string][]string{
			"example.com.":      {"v=spf1 include:_spf.example.com ip4:198.51.100.0/24 -all"},
			"_spf.example.com.": {"v=spf1 ip4:192.0.2.0/24 a:mail.example.com -all"},
		},
		a: map[string][]net.IP{
			"mail.example.com.": {net.ParseIP("192.0.2.1")},
		},
		mx: map[string][]*net.MX{},
	}
}

// BenchmarkVerifyPass measures Verify for a passing sender (ip4 mechanism hit inside an include).
func BenchmarkVerifyPass(b *testing.B) {
	resolver := newBenchResolver()
	ctx := context.Background()
	args := Args{
		RemoteIP:       net.ParseIP("192.0.2.1"),
		MailFromDomain: "example.com",
		MailFromLocal:  "user",
	}

	b.ResetTimer()
	for b.Loop() {
		received, _, _, _, err := Verify(ctx, resolver, args)
		if err != nil {
			b.Fatalf("Verify: %v", err)
		}
		if received.Result != StatusPass {
			b.Fatalf("expected pass, got %s", received.Result)
		}
	}
}

// BenchmarkVerifyFail measures Verify for a failing sender (-all).
func BenchmarkVerifyFail(b *testing.B) {
	resolver := newBenchResolver()
	ctx := context.Background()
	args := Args{
		RemoteIP:       net.ParseIP("10.0.0.1"),
		MailFromDomain: "example.com",
		MailFromLocal:  "user",
	}

	b.ResetTimer()
	for b.Loop() {
		received, _, _, _, _ := Verify(ctx, resolver, args)
		if received.Result != StatusFail {
			b.Fatalf("expected fail, got %s", received.Result)
		}
	}
}

// BenchmarkParseRecordSimple measures ParseRecord for a simple ip4 + -all policy.
func BenchmarkParseRecordSimple(b *testing.B) {
	const record = "v=spf1 ip4:192.0.2.0/24 -all"
	for b.Loop() {
		if _, _, err := ParseRecord(record); err != nil {
			b.Fatalf("ParseRecord: %v", err)
		}
	}
}

// BenchmarkParseRecordComplex measures ParseRecord for a realistic multi-mechanism policy.
func BenchmarkParseRecordComplex(b *testing.B) {
	const record = "v=spf1 mx a:mail1.example.com a:mail2.example.com ip4:192.0.2.0/24 ip6:2001:db8::/32 include:_spf.example.com ~all"
	for b.Loop() {
		if _, _, err := ParseRecord(record); err != nil {
			b.Fatalf("ParseRecord: %v", err)
		}
	}
}

// BenchmarkReceivedHeader measures generation of the Received-SPF header.
func BenchmarkReceivedHeader(b *testing.B) {
	r := Received{
		Result:       StatusPass,
		Comment:      "example.com: designates 192.0.2.1 as permitted sender",
		ClientIP:     net.ParseIP("192.0.2.1"),
		EnvelopeFrom: "user@example.com",
		Helo:         "mail.example.com",
		Receiver:     "mx.receiver.net",
		Identity:     "mailfrom",
		Mechanism:    "include",
	}
	b.ResetTimer()
	for b.Loop() {
		_ = r.Header()
	}
}
