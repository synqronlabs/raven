package dmarc

import (
	"context"
	"testing"

	"github.com/synqronlabs/raven/dkim"
	"github.com/synqronlabs/raven/dns"
	"github.com/synqronlabs/raven/spf"
)

// newBenchDNSResolver returns a dns.MockResolver pre-populated with a realistic
// DMARC TXT record so that Lookup and Verify benchmarks do not touch the network.
func newBenchDNSResolver(policy string) dns.MockResolver {
	return dns.MockResolver{
		TXT: map[string][]string{
			"_dmarc.example.com.": {"v=DMARC1; p=" + policy + "; adkim=r; aspf=r; pct=100"},
		},
	}
}

// BenchmarkParseRecordSimple measures ParseRecord for a minimal DMARC TXT record.
func BenchmarkParseRecordSimple(b *testing.B) {
	const record = "v=DMARC1; p=none;"
	for b.Loop() {
		if _, _, err := ParseRecord(record, ParseModeStrict); err != nil {
			b.Fatalf("ParseRecord: %v", err)
		}
	}
}

// BenchmarkParseRecordFull measures ParseRecord for a fully-populated DMARC TXT record.
func BenchmarkParseRecordFull(b *testing.B) {
	const record = "v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=s; pct=50; ri=3600;" +
		" rua=mailto:dmarc@example.com,mailto:rua@third.example.net!10m;" +
		" ruf=mailto:forensic@example.com; fo=1:d:s; rf=afrf"
	for b.Loop() {
		if _, _, err := ParseRecord(record, ParseModeStrict); err != nil {
			b.Fatalf("ParseRecord: %v", err)
		}
	}
}

// BenchmarkLookup measures the Lookup path with an in-process mock resolver.
// This measures record parsing plus org-domain logic, not real DNS.
func BenchmarkLookup(b *testing.B) {
	resolver := newBenchDNSResolver("reject")
	ctx := context.Background()

	b.ResetTimer()
	for b.Loop() {
		result, err := Lookup(ctx, resolver, "example.com")
		if err != nil {
			b.Fatalf("Lookup: %v", err)
		}
		if result.Record == nil {
			b.Fatal("expected non-nil record")
		}
	}
}

// BenchmarkVerifyPass measures Verify when SPF and DKIM both pass with aligned domains.
func BenchmarkVerifyPass(b *testing.B) {
	resolver := newBenchDNSResolver("reject")
	ctx := context.Background()
	args := VerifyArgs{
		FromDomain: "example.com",
		SPFResult:  spf.StatusPass,
		SPFDomain:  "example.com",
		DKIMResults: []dkim.Result{
			{
				Status:    dkim.StatusPass,
				Signature: &dkim.Signature{Domain: "example.com", Selector: "bench"},
			},
		},
	}

	b.ResetTimer()
	for b.Loop() {
		_, result := Verify(ctx, resolver, args, false)
		if result.Status != StatusPass {
			b.Fatalf("expected pass, got %s", result.Status)
		}
	}
}

// BenchmarkVerifyFail measures Verify for a message that fails DMARC (no aligned pass).
func BenchmarkVerifyFail(b *testing.B) {
	resolver := newBenchDNSResolver("reject")
	ctx := context.Background()
	args := VerifyArgs{
		FromDomain: "example.com",
		SPFResult:  spf.StatusFail,
		SPFDomain:  "example.com",
		DKIMResults: []dkim.Result{
			{
				Status:    dkim.StatusFail,
				Signature: &dkim.Signature{Domain: "example.com", Selector: "bench"},
			},
		},
	}

	b.ResetTimer()
	for b.Loop() {
		_, result := Verify(ctx, resolver, args, false)
		if result.Status != StatusFail {
			b.Fatalf("expected fail, got %s", result.Status)
		}
	}
}

// BenchmarkOrganizationalDomain measures the public-suffix-based org-domain helper.
func BenchmarkOrganizationalDomain(b *testing.B) {
	domains := []string{
		"example.com",
		"sub.example.com",
		"deep.sub.example.co.uk",
		"mail.lists.example.org",
	}
	b.ResetTimer()
	for b.Loop() {
		for _, d := range domains {
			_ = OrganizationalDomain(d)
		}
	}
}

// BenchmarkDomainsAlignedRelaxed measures the relaxed alignment check.
func BenchmarkDomainsAlignedRelaxed(b *testing.B) {
	for b.Loop() {
		_ = DomainsAligned("sub.example.com", "example.com", AlignRelaxed)
	}
}

// BenchmarkDomainsAlignedStrict measures the strict alignment check.
func BenchmarkDomainsAlignedStrict(b *testing.B) {
	for b.Loop() {
		_ = DomainsAligned("example.com", "example.com", AlignStrict)
	}
}
