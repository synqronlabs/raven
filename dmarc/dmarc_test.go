package dmarc

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/synqronlabs/raven/dkim"
	"github.com/synqronlabs/raven/dns"
	"github.com/synqronlabs/raven/spf"
)

// TestParseBad tests parsing of invalid DMARC records.
// Ported from mox/dmarc/parse_test.go
func TestParseBad(t *testing.T) {
	bad := func(s string) {
		t.Helper()
		_, _, err := ParseRecord(s)
		if err == nil {
			t.Fatalf("got parse success for %q, expected error", s)
		}
	}

	bad("")
	bad("v=")
	bad("v=DMARC12")                                           // "2" leftover
	bad("v=DMARC1")                                            // semicolon required
	bad("v=dmarc1; p=none")                                    // dmarc1 is case-sensitive
	bad("v=DMARC1 p=none")                                     // missing ;
	bad("v=DMARC1;")                                           // missing p, no rua
	bad("v=DMARC1; sp=invalid")                                // invalid sp, no rua
	bad("v=DMARC1; sp=reject; p=reject")                       // p must be directly after v
	bad("v=DMARC1; p=none; p=none")                            // dup
	bad("v=DMARC1; p=none; p=reject")                          // dup
	bad("v=DMARC1;;")                                          // missing tag
	bad("v=DMARC1; adkim=x")                                   // bad value
	bad("v=DMARC1; aspf=123")                                  // bad value
	bad("v=DMARC1; ri=")                                       // missing value
	bad("v=DMARC1; ri=-1")                                     // invalid, must be >= 0
	bad("v=DMARC1; ri=99999999999999999999999999999999999999") // does not fit in int
	bad("v=DMARC1; ri=123bad")                                 // leftover data
	bad("v=DMARC1; ri=bad")                                    // not a number
	bad("v=DMARC1; fo=")
	bad("v=DMARC1; fo=01")
	bad("v=DMARC1; fo=bad")
	bad("v=DMARC1; rf=bad-trailing-dash-")
	bad("v=DMARC1; rf=")
	bad("v=DMARC1; rf=bad.non-alphadigitdash")
	bad("v=DMARC1; p=badvalue")
	bad("v=DMARC1; sp=bad")
	bad("v=DMARC1; pct=110")
	bad("v=DMARC1; pct=bogus")
	bad("v=DMARC1; pct=")
	bad("v=DMARC1; rua=")
	bad("v=DMARC1; rua=bogus")
	bad("v=DMARC1; rua=mailto:dmarc-feedback@example.com!")
	bad("v=DMARC1; rua=mailto:dmarc-feedback@example.com!99999999999999999999999999999999999999999999999")
	bad("v=DMARC1; rua=mailto:dmarc-feedback@example.com!10p")
}

// TestParseValid tests parsing of valid DMARC records.
// Ported from mox/dmarc/parse_test.go
func TestParseValid(t *testing.T) {
	// Return a record with default values, and overrides from r.
	record := func(r Record) Record {
		rr := DefaultRecord
		if r.Policy != "" {
			rr.Policy = r.Policy
		}
		if r.SubdomainPolicy != "" {
			rr.SubdomainPolicy = r.SubdomainPolicy
		}
		if r.AggregateReportAddresses != nil {
			rr.AggregateReportAddresses = r.AggregateReportAddresses
		}
		if r.FailureReportAddresses != nil {
			rr.FailureReportAddresses = r.FailureReportAddresses
		}
		if r.Percentage != 0 {
			rr.Percentage = r.Percentage
		}
		if r.ADKIM != "" {
			rr.ADKIM = r.ADKIM
		}
		if r.ASPF != "" {
			rr.ASPF = r.ASPF
		}
		if r.AggregateReportingInterval != 0 {
			rr.AggregateReportingInterval = r.AggregateReportingInterval
		}
		if r.FailureReportingOptions != nil {
			rr.FailureReportingOptions = r.FailureReportingOptions
		}
		if r.ReportingFormat != nil {
			rr.ReportingFormat = r.ReportingFormat
		}
		return rr
	}

	valid := func(s string, exp Record) {
		t.Helper()

		r, _, err := ParseRecord(s)
		if err != nil {
			t.Fatalf("unexpected error for %q: %s", s, err)
		}
		if !reflect.DeepEqual(*r, exp) {
			t.Fatalf("got:\n%#v\nexpected:\n%#v", *r, exp)
		}
	}

	// RFC 7489 Section 6.6.3 - missing p but rua present -> p=none
	valid("v=DMARC1; rua=mailto:mjl@mox.example", record(Record{
		Policy: PolicyNone,
		AggregateReportAddresses: []URI{
			{Address: "mailto:mjl@mox.example"},
		},
	}))

	// RFC 7489 Section 6.6.3 - invalid sp but rua present -> p=none
	valid("v=DMARC1; p=reject; sp=invalid; rua=mailto:mjl@mox.example", record(Record{
		Policy: PolicyNone,
		AggregateReportAddresses: []URI{
			{Address: "mailto:mjl@mox.example"},
		},
	}))

	valid("v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com", record(Record{
		Policy: PolicyNone,
		AggregateReportAddresses: []URI{
			{Address: "mailto:dmarc-feedback@example.com"},
		},
	}))

	valid("v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com;ruf=mailto:auth-reports@example.com", record(Record{
		Policy: PolicyNone,
		AggregateReportAddresses: []URI{
			{Address: "mailto:dmarc-feedback@example.com"},
		},
		FailureReportAddresses: []URI{
			{Address: "mailto:auth-reports@example.com"},
		},
	}))

	valid("v=DMARC1; p=quarantine; rua=mailto:dmarc-feedback@example.com,mailto:tld-test@thirdparty.example.net!10m; pct=25", record(Record{
		Policy: PolicyQuarantine,
		AggregateReportAddresses: []URI{
			{Address: "mailto:dmarc-feedback@example.com"},
			{Address: "mailto:tld-test@thirdparty.example.net", MaxSize: 10, Unit: "m"},
		},
		Percentage: 25,
	}))

	// Full record with all options - whitespace handling
	valid("V = DMARC1 ; P = reject ;\tSP=none; unknown \t=\t ignored-future-value \t ; adkim=s; aspf=s; rua=mailto:dmarc-feedback@example.com  ,\t\tmailto:tld-test@thirdparty.example.net!10m; RUF=mailto:auth-reports@example.com  ,\t\tmailto:tld-test@thirdparty.example.net!0G; RI = 123; FO = 0:1:d:s ; RF= afrf : other; Pct = 0",
		Record{
			Version:         "DMARC1",
			Policy:          PolicyReject,
			SubdomainPolicy: PolicyNone,
			ADKIM:           AlignStrict,
			ASPF:            AlignStrict,
			AggregateReportAddresses: []URI{
				{Address: "mailto:dmarc-feedback@example.com"},
				{Address: "mailto:tld-test@thirdparty.example.net", MaxSize: 10, Unit: "m"},
			},
			FailureReportAddresses: []URI{
				{Address: "mailto:auth-reports@example.com"},
				{Address: "mailto:tld-test@thirdparty.example.net", MaxSize: 0, Unit: "g"},
			},
			AggregateReportingInterval: 123,
			FailureReportingOptions:    []string{"0", "1", "d", "s"},
			ReportingFormat:            []string{"afrf", "other"},
			Percentage:                 0,
		},
	)
}

func TestParseRecord(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		isDMARC  bool
		wantErr  bool
		validate func(*testing.T, *Record)
	}{
		{
			name:    "basic policy none",
			input:   "v=DMARC1; p=none;",
			isDMARC: true,
			wantErr: false,
			validate: func(t *testing.T, r *Record) {
				if r.Policy != PolicyNone {
					t.Errorf("expected policy none, got %s", r.Policy)
				}
			},
		},
		{
			name:    "basic policy reject",
			input:   "v=DMARC1; p=reject",
			isDMARC: true,
			wantErr: false,
			validate: func(t *testing.T, r *Record) {
				if r.Policy != PolicyReject {
					t.Errorf("expected policy reject, got %s", r.Policy)
				}
			},
		},
		{
			name:    "basic policy quarantine",
			input:   "v=DMARC1; p=quarantine",
			isDMARC: true,
			wantErr: false,
			validate: func(t *testing.T, r *Record) {
				if r.Policy != PolicyQuarantine {
					t.Errorf("expected policy quarantine, got %s", r.Policy)
				}
			},
		},
		{
			name:    "full record",
			input:   "v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=s; pct=50; ri=3600; rua=mailto:dmarc@example.com",
			isDMARC: true,
			wantErr: false,
			validate: func(t *testing.T, r *Record) {
				if r.Policy != PolicyReject {
					t.Errorf("expected policy reject, got %s", r.Policy)
				}
				if r.SubdomainPolicy != PolicyQuarantine {
					t.Errorf("expected subdomain policy quarantine, got %s", r.SubdomainPolicy)
				}
				if r.ADKIM != AlignStrict {
					t.Errorf("expected ADKIM strict, got %s", r.ADKIM)
				}
				if r.ASPF != AlignStrict {
					t.Errorf("expected ASPF strict, got %s", r.ASPF)
				}
				if r.Percentage != 50 {
					t.Errorf("expected percentage 50, got %d", r.Percentage)
				}
				if r.AggregateReportingInterval != 3600 {
					t.Errorf("expected ri 3600, got %d", r.AggregateReportingInterval)
				}
				if len(r.AggregateReportAddresses) != 1 {
					t.Errorf("expected 1 rua address, got %d", len(r.AggregateReportAddresses))
				}
			},
		},
		{
			name:    "multiple rua addresses",
			input:   "v=DMARC1; p=none; rua=mailto:dmarc@example.com,mailto:dmarc2@example.com",
			isDMARC: true,
			wantErr: false,
			validate: func(t *testing.T, r *Record) {
				if len(r.AggregateReportAddresses) != 2 {
					t.Errorf("expected 2 rua addresses, got %d", len(r.AggregateReportAddresses))
				}
			},
		},
		{
			name:    "ruf address",
			input:   "v=DMARC1; p=none; ruf=mailto:forensic@example.com",
			isDMARC: true,
			wantErr: false,
			validate: func(t *testing.T, r *Record) {
				if len(r.FailureReportAddresses) != 1 {
					t.Errorf("expected 1 ruf address, got %d", len(r.FailureReportAddresses))
				}
			},
		},
		{
			name:    "fo options",
			input:   "v=DMARC1; p=none; fo=1:d:s",
			isDMARC: true,
			wantErr: false,
			validate: func(t *testing.T, r *Record) {
				expected := []string{"1", "d", "s"}
				if !reflect.DeepEqual(r.FailureReportingOptions, expected) {
					t.Errorf("expected fo %v, got %v", expected, r.FailureReportingOptions)
				}
			},
		},
		{
			name:    "not a DMARC record",
			input:   "v=spf1 include:example.com -all",
			isDMARC: false,
			wantErr: true, // Now returns error for non-DMARC records
		},
		{
			name:    "malformed - missing p after v",
			input:   "v=DMARC1; sp=none",
			isDMARC: true,
			wantErr: true,
		},
		{
			name:    "malformed - p not first",
			input:   "v=DMARC1; adkim=r; p=none",
			isDMARC: true,
			wantErr: true,
		},
		{
			name:    "invalid pct",
			input:   "v=DMARC1; p=none; pct=150",
			isDMARC: true,
			wantErr: true,
		},
		{
			name:    "case insensitive",
			input:   "v=DMARC1; P=REJECT; ADKIM=S",
			isDMARC: true,
			wantErr: false,
			validate: func(t *testing.T, r *Record) {
				if r.Policy != PolicyReject {
					t.Errorf("expected policy reject, got %s", r.Policy)
				}
			},
		},
		{
			name:    "whitespace handling",
			input:   "v=DMARC1 ; p = none ; adkim = r",
			isDMARC: true,
			wantErr: false,
			validate: func(t *testing.T, r *Record) {
				if r.Policy != PolicyNone {
					t.Errorf("expected policy none, got %s", r.Policy)
				}
			},
		},
		{
			name:    "unknown tag ignored",
			input:   "v=DMARC1; p=none; unknown=value",
			isDMARC: true,
			wantErr: false,
		},
		{
			name:    "uri with size limit",
			input:   "v=DMARC1; p=none; rua=mailto:dmarc@example.com!100k",
			isDMARC: true,
			wantErr: false,
			validate: func(t *testing.T, r *Record) {
				if len(r.AggregateReportAddresses) != 1 {
					t.Fatalf("expected 1 rua address, got %d", len(r.AggregateReportAddresses))
				}
				if r.AggregateReportAddresses[0].MaxSize != 100 {
					t.Errorf("expected max size 100, got %d", r.AggregateReportAddresses[0].MaxSize)
				}
				if r.AggregateReportAddresses[0].Unit != "k" {
					t.Errorf("expected unit k, got %s", r.AggregateReportAddresses[0].Unit)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record, isDMARC, err := ParseRecord(tt.input)

			if isDMARC != tt.isDMARC {
				t.Errorf("isDMARC: got %v, want %v", isDMARC, tt.isDMARC)
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("error: got %v, wantErr %v", err, tt.wantErr)
			}

			if tt.validate != nil && record != nil {
				tt.validate(t, record)
			}
		})
	}
}

func TestRecordString(t *testing.T) {
	tests := []struct {
		name     string
		record   Record
		contains []string
	}{
		{
			name: "basic",
			record: Record{
				Version: "DMARC1",
				Policy:  PolicyReject,
			},
			contains: []string{"v=DMARC1", "p=reject"},
		},
		{
			name: "with subdomain policy",
			record: Record{
				Version:         "DMARC1",
				Policy:          PolicyReject,
				SubdomainPolicy: PolicyNone,
			},
			contains: []string{"v=DMARC1", "p=reject", "sp=none"},
		},
		{
			name: "with alignment",
			record: Record{
				Version: "DMARC1",
				Policy:  PolicyNone,
				ADKIM:   AlignStrict,
				ASPF:    AlignStrict,
			},
			contains: []string{"adkim=s", "aspf=s"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.record.String()
			for _, substr := range tt.contains {
				if !containsSubstring(s, substr) {
					t.Errorf("record string %q does not contain %q", s, substr)
				}
			}
		})
	}
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr) >= 0
}

func findSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func TestOrganizationalDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"example.com", "example.com"},
		{"sub.example.com", "example.com"},
		{"deep.sub.example.com", "example.com"},
		{"example.co.uk", "example.co.uk"},
		{"sub.example.co.uk", "example.co.uk"},
		{"localhost", "localhost"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := OrganizationalDomain(tt.domain)
			if got != tt.want {
				t.Errorf("OrganizationalDomain(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

func TestDomainsAligned(t *testing.T) {
	tests := []struct {
		name      string
		domain1   string
		domain2   string
		alignment Align
		want      bool
	}{
		{"strict exact match", "example.com", "example.com", AlignStrict, true},
		{"strict no match", "sub.example.com", "example.com", AlignStrict, false},
		{"relaxed exact match", "example.com", "example.com", AlignRelaxed, true},
		{"relaxed org domain match", "sub.example.com", "example.com", AlignRelaxed, true},
		{"relaxed both subdomains", "sub1.example.com", "sub2.example.com", AlignRelaxed, true},
		{"relaxed different orgs", "example.com", "other.com", AlignRelaxed, false},
		{"case insensitive", "Example.COM", "example.com", AlignStrict, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DomainsAligned(tt.domain1, tt.domain2, tt.alignment)
			if got != tt.want {
				t.Errorf("DomainsAligned(%q, %q, %q) = %v, want %v",
					tt.domain1, tt.domain2, tt.alignment, got, tt.want)
			}
		})
	}
}

func TestLookup(t *testing.T) {
	resolver := dns.MockResolver{
		TXT: map[string][]string{
			"_dmarc.simple.example.":    {"v=DMARC1; p=none;"},
			"_dmarc.one.example.":       {"v=DMARC1; p=none;", "other"},
			"_dmarc.reject.example.":    {"v=DMARC1; p=reject"},
			"_dmarc.multiple.example.":  {"v=DMARC1; p=none;", "v=DMARC1; p=reject"},
			"_dmarc.malformed.example.": {"v=DMARC1; p=none; bogus;"},
			"_dmarc.example.com.":       {"v=DMARC1; p=none;"},
			"_dmarc.other.example.":     {"other record", "v=DMARC1; p=quarantine"},
		},
		Fail: []string{
			"txt _dmarc.temperror.example.",
		},
	}

	tests := []struct {
		name       string
		domain     string
		wantStatus Status
		wantDomain string
		wantPolicy Policy
		wantErr    error
	}{
		{
			name:       "simple domain",
			domain:     "simple.example",
			wantStatus: StatusNone,
			wantDomain: "simple.example",
			wantPolicy: PolicyNone,
		},
		{
			name:       "one DMARC with other TXT",
			domain:     "one.example",
			wantStatus: StatusNone,
			wantDomain: "one.example",
			wantPolicy: PolicyNone,
		},
		{
			name:       "reject policy",
			domain:     "reject.example",
			wantStatus: StatusNone,
			wantDomain: "reject.example",
			wantPolicy: PolicyReject,
		},
		{
			name:       "subdomain falls back to org",
			domain:     "sub.example.com",
			wantStatus: StatusNone,
			wantDomain: "example.com",
			wantPolicy: PolicyNone,
		},
		{
			name:       "no record",
			domain:     "absent.example",
			wantStatus: StatusNone,
			wantDomain: "absent.example",
			wantErr:    ErrNoRecord,
		},
		{
			name:       "multiple records",
			domain:     "multiple.example",
			wantStatus: StatusNone,
			wantDomain: "multiple.example",
			wantErr:    ErrMultipleRecords,
		},
		{
			name:       "malformed record",
			domain:     "malformed.example",
			wantStatus: StatusPermerror,
			wantDomain: "malformed.example",
			wantErr:    ErrSyntax,
		},
		{
			name:       "DNS failure",
			domain:     "temperror.example",
			wantStatus: StatusTemperror,
			wantDomain: "temperror.example",
			wantErr:    ErrDNS,
		},
		{
			name:       "mixed records - other first",
			domain:     "other.example",
			wantStatus: StatusNone,
			wantDomain: "other.example",
			wantPolicy: PolicyQuarantine,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, domain, record, _, _, err := Lookup(context.Background(), resolver, tt.domain)

			if status != tt.wantStatus {
				t.Errorf("status: got %v, want %v", status, tt.wantStatus)
			}

			if domain != tt.wantDomain {
				t.Errorf("domain: got %q, want %q", domain, tt.wantDomain)
			}

			if tt.wantErr != nil {
				if err == nil || !errors.Is(err, tt.wantErr) {
					t.Errorf("error: got %v, want %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if tt.wantPolicy != "" && record != nil {
				if record.Policy != tt.wantPolicy {
					t.Errorf("policy: got %v, want %v", record.Policy, tt.wantPolicy)
				}
			}
		})
	}
}

func TestVerify(t *testing.T) {
	resolver := dns.MockResolver{
		TXT: map[string][]string{
			"_dmarc.reject.example.":    {"v=DMARC1; p=reject"},
			"_dmarc.none.example.":      {"v=DMARC1; p=none"},
			"_dmarc.strict.example.":    {"v=DMARC1; p=reject; adkim=s; aspf=s"},
			"_dmarc.subnone.example.":   {"v=DMARC1; p=reject; sp=none"},
			"_dmarc.pct0.example.":      {"v=DMARC1; p=reject; pct=0"},
			"_dmarc.example.com.":       {"v=DMARC1; p=reject"},
			"_dmarc.malformed.example.": {"v=DMARC1; bogus"},
		},
		Fail: []string{
			"txt _dmarc.temperror.example.",
		},
	}

	tests := []struct {
		name            string
		fromDomain      string
		spfResult       spf.Status
		spfDomain       string
		dkimResults     []dkim.Result
		wantStatus      Status
		wantReject      bool
		wantAlignedSPF  bool
		wantAlignedDKIM bool
		applyPct        bool
		wantUseResult   bool
	}{
		{
			name:          "reject - no auth",
			fromDomain:    "reject.example",
			spfResult:     spf.StatusNone,
			spfDomain:     "",
			dkimResults:   nil,
			wantStatus:    StatusFail,
			wantReject:    true,
			applyPct:      true,
			wantUseResult: true,
		},
		{
			name:           "reject - SPF pass aligned",
			fromDomain:     "reject.example",
			spfResult:      spf.StatusPass,
			spfDomain:      "reject.example",
			dkimResults:    nil,
			wantStatus:     StatusPass,
			wantReject:     false,
			wantAlignedSPF: true,
			applyPct:       true,
			wantUseResult:  true,
		},
		{
			name:           "reject - SPF pass relaxed aligned",
			fromDomain:     "reject.example",
			spfResult:      spf.StatusPass,
			spfDomain:      "sub.reject.example",
			dkimResults:    nil,
			wantStatus:     StatusPass,
			wantReject:     false,
			wantAlignedSPF: true,
			applyPct:       true,
			wantUseResult:  true,
		},
		{
			name:       "reject - DKIM pass aligned",
			fromDomain: "reject.example",
			spfResult:  spf.StatusFail,
			spfDomain:  "reject.example",
			dkimResults: []dkim.Result{
				{
					Status: dkim.StatusPass,
					Signature: &dkim.Signature{
						Domain: "reject.example",
					},
				},
			},
			wantStatus:      StatusPass,
			wantReject:      false,
			wantAlignedDKIM: true,
			applyPct:        true,
			wantUseResult:   true,
		},
		{
			name:       "reject - DKIM pass relaxed aligned",
			fromDomain: "reject.example",
			spfResult:  spf.StatusNone,
			spfDomain:  "",
			dkimResults: []dkim.Result{
				{
					Status: dkim.StatusPass,
					Signature: &dkim.Signature{
						Domain: "sub.reject.example",
					},
				},
			},
			wantStatus:      StatusPass,
			wantReject:      false,
			wantAlignedDKIM: true,
			applyPct:        true,
			wantUseResult:   true,
		},
		{
			name:           "strict - SPF not aligned",
			fromDomain:     "strict.example",
			spfResult:      spf.StatusPass,
			spfDomain:      "sub.strict.example",
			dkimResults:    nil,
			wantStatus:     StatusFail,
			wantReject:     true,
			wantAlignedSPF: false,
			applyPct:       true,
			wantUseResult:  true,
		},
		{
			name:       "strict - DKIM not aligned",
			fromDomain: "strict.example",
			spfResult:  spf.StatusNone,
			spfDomain:  "",
			dkimResults: []dkim.Result{
				{
					Status: dkim.StatusPass,
					Signature: &dkim.Signature{
						Domain: "sub.strict.example",
					},
				},
			},
			wantStatus:      StatusFail,
			wantReject:      true,
			wantAlignedDKIM: false,
			applyPct:        true,
			wantUseResult:   true,
		},
		{
			name:          "none policy - no reject",
			fromDomain:    "none.example",
			spfResult:     spf.StatusFail,
			spfDomain:     "none.example",
			dkimResults:   nil,
			wantStatus:    StatusFail,
			wantReject:    false,
			applyPct:      true,
			wantUseResult: true,
		},
		{
			name:          "subdomain policy none",
			fromDomain:    "sub.subnone.example",
			spfResult:     spf.StatusFail,
			spfDomain:     "sub.subnone.example",
			dkimResults:   nil,
			wantStatus:    StatusFail,
			wantReject:    false,
			applyPct:      true,
			wantUseResult: true,
		},
		{
			name:          "no record",
			fromDomain:    "absent.example",
			spfResult:     spf.StatusNone,
			spfDomain:     "",
			dkimResults:   nil,
			wantStatus:    StatusNone,
			wantReject:    false,
			applyPct:      true,
			wantUseResult: false,
		},
		{
			name:          "DNS temp error",
			fromDomain:    "temperror.example",
			spfResult:     spf.StatusNone,
			spfDomain:     "",
			dkimResults:   nil,
			wantStatus:    StatusTemperror,
			wantReject:    false,
			applyPct:      true,
			wantUseResult: false,
		},
		{
			name:          "SPF temperror - no reject",
			fromDomain:    "reject.example",
			spfResult:     spf.StatusTemperror,
			spfDomain:     "reject.example",
			dkimResults:   nil,
			wantStatus:    StatusTemperror,
			wantReject:    false,
			applyPct:      true,
			wantUseResult: true,
		},
		{
			name:       "DKIM temperror - no reject",
			fromDomain: "reject.example",
			spfResult:  spf.StatusNone,
			spfDomain:  "",
			dkimResults: []dkim.Result{
				{
					Status: dkim.StatusTemperror,
					Signature: &dkim.Signature{
						Domain: "reject.example",
					},
				},
			},
			wantStatus:    StatusTemperror,
			wantReject:    false,
			applyPct:      true,
			wantUseResult: true,
		},
		{
			name:       "DKIM temperror but SPF pass",
			fromDomain: "reject.example",
			spfResult:  spf.StatusPass,
			spfDomain:  "reject.example",
			dkimResults: []dkim.Result{
				{
					Status: dkim.StatusTemperror,
					Signature: &dkim.Signature{
						Domain: "reject.example",
					},
				},
			},
			wantStatus:     StatusPass,
			wantReject:     false,
			wantAlignedSPF: true,
			applyPct:       true,
			wantUseResult:  true,
		},
		{
			name:       "SPF temperror but DKIM pass",
			fromDomain: "reject.example",
			spfResult:  spf.StatusTemperror,
			spfDomain:  "reject.example",
			dkimResults: []dkim.Result{
				{
					Status: dkim.StatusPass,
					Signature: &dkim.Signature{
						Domain: "reject.example",
					},
				},
			},
			wantStatus:      StatusPass,
			wantReject:      false,
			wantAlignedDKIM: true,
			applyPct:        true,
			wantUseResult:   true,
		},
		{
			name:          "pct=0 - useResult false",
			fromDomain:    "pct0.example",
			spfResult:     spf.StatusFail,
			spfDomain:     "pct0.example",
			dkimResults:   nil,
			wantStatus:    StatusFail,
			wantReject:    true,
			applyPct:      true,
			wantUseResult: false,
		},
		{
			name:       "DKIM domain above org - no pass",
			fromDomain: "example.com",
			spfResult:  spf.StatusNone,
			spfDomain:  "",
			dkimResults: []dkim.Result{
				{
					Status: dkim.StatusPass,
					Signature: &dkim.Signature{
						Domain: "com", // TLD signature should not cause DMARC pass
					},
				},
			},
			wantStatus:      StatusFail,
			wantReject:      true,
			wantAlignedDKIM: false,
			applyPct:        true,
			wantUseResult:   true,
		},
		{
			// mox test: absent.example with SPF pass - useResult should be false
			name:          "absent with SPF pass - no record",
			fromDomain:    "absent.example",
			spfResult:     spf.StatusPass,
			spfDomain:     "absent.example",
			dkimResults:   nil,
			wantStatus:    StatusNone,
			wantReject:    false,
			applyPct:      true,
			wantUseResult: false,
		},
		{
			// mox test: none.example with SPF pass - pass status
			name:           "none policy with SPF pass",
			fromDomain:     "none.example",
			spfResult:      spf.StatusPass,
			spfDomain:      "none.example",
			dkimResults:    nil,
			wantStatus:     StatusPass,
			wantReject:     false,
			wantAlignedSPF: true,
			applyPct:       true,
			wantUseResult:  true,
		},
		{
			// mox test: malformed.example - permerror without reject
			name:          "malformed record - permerror no reject",
			fromDomain:    "malformed.example",
			spfResult:     spf.StatusNone,
			spfDomain:     "",
			dkimResults:   nil,
			wantStatus:    StatusPermerror,
			wantReject:    false,
			applyPct:      true,
			wantUseResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := VerifyArgs{
				FromDomain:  tt.fromDomain,
				SPFResult:   tt.spfResult,
				SPFDomain:   tt.spfDomain,
				DKIMResults: tt.dkimResults,
			}

			useResult, result := Verify(context.Background(), resolver, args, tt.applyPct)

			if result.Status != tt.wantStatus {
				t.Errorf("status: got %v, want %v", result.Status, tt.wantStatus)
			}

			if result.Reject != tt.wantReject {
				t.Errorf("reject: got %v, want %v", result.Reject, tt.wantReject)
			}

			if result.AlignedSPFPass != tt.wantAlignedSPF {
				t.Errorf("alignedSPF: got %v, want %v", result.AlignedSPFPass, tt.wantAlignedSPF)
			}

			if result.AlignedDKIMPass != tt.wantAlignedDKIM {
				t.Errorf("alignedDKIM: got %v, want %v", result.AlignedDKIMPass, tt.wantAlignedDKIM)
			}

			if useResult != tt.wantUseResult {
				t.Errorf("useResult: got %v, want %v", useResult, tt.wantUseResult)
			}
		})
	}
}

func TestExtractFromDomain(t *testing.T) {
	tests := []struct {
		name       string
		fromHeader string
		wantDomain string
		wantErr    error
	}{
		{
			name:       "simple address",
			fromHeader: "user@example.com",
			wantDomain: "example.com",
		},
		{
			name:       "with display name",
			fromHeader: "John Doe <john@example.com>",
			wantDomain: "example.com",
		},
		{
			name:       "quoted display name",
			fromHeader: "\"Doe, John\" <john@example.com>",
			wantDomain: "example.com",
		},
		{
			name:       "uppercase domain",
			fromHeader: "user@EXAMPLE.COM",
			wantDomain: "example.com",
		},
		{
			name:       "empty",
			fromHeader: "",
			wantErr:    ErrNoFromHeader,
		},
		{
			name:       "invalid",
			fromHeader: "not an email",
			wantErr:    ErrInvalidFromHeader,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain, err := ExtractFromDomain(tt.fromHeader)

			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("error: got %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if domain != tt.wantDomain {
				t.Errorf("domain: got %q, want %q", domain, tt.wantDomain)
			}
		})
	}
}

func TestLookupExternalReportsAccepted(t *testing.T) {
	resolver := dns.MockResolver{
		TXT: map[string][]string{
			"example.com._report._dmarc.simple.example.":    {"v=DMARC1"},
			"example.com._report._dmarc.simple2.example.":   {"v=DMARC1;"},
			"example.com._report._dmarc.one.example.":       {"v=DMARC1; p=none;", "other"},
			"example.com._report._dmarc.multiple.example.":  {"v=DMARC1; p=none;", "v=DMARC1"},
			"example.com._report._dmarc.malformed.example.": {"v=DMARC1; p=none; bogus;"},
		},
		Fail: []string{
			"txt example.com._report._dmarc.temperror.example.",
		},
	}

	tests := []struct {
		name        string
		dmarcDomain string
		extDomain   string
		wantAccepts bool
		wantStatus  Status
		wantErr     error
	}{
		{
			name:        "accepts reports",
			dmarcDomain: "example.com",
			extDomain:   "simple.example",
			wantAccepts: true,
			wantStatus:  StatusNone,
		},
		{
			name:        "accepts with semicolon",
			dmarcDomain: "example.com",
			extDomain:   "simple2.example",
			wantAccepts: true,
			wantStatus:  StatusNone,
		},
		{
			name:        "one DMARC with other TXT",
			dmarcDomain: "example.com",
			extDomain:   "one.example",
			wantAccepts: true,
			wantStatus:  StatusNone,
		},
		{
			name:        "no record",
			dmarcDomain: "other.com",
			extDomain:   "simple.example",
			wantAccepts: false,
			wantStatus:  StatusNone,
			wantErr:     ErrNoRecord,
		},
		{
			name:        "absent domain",
			dmarcDomain: "example.com",
			extDomain:   "absent.example",
			wantAccepts: false,
			wantStatus:  StatusNone,
			wantErr:     ErrNoRecord,
		},
		{
			name:        "multiple records allowed",
			dmarcDomain: "example.com",
			extDomain:   "multiple.example",
			wantAccepts: true,
			wantStatus:  StatusNone,
		},
		{
			name:        "malformed record",
			dmarcDomain: "example.com",
			extDomain:   "malformed.example",
			wantAccepts: false,
			wantStatus:  StatusPermerror,
			wantErr:     ErrSyntax,
		},
		{
			name:        "DNS error",
			dmarcDomain: "example.com",
			extDomain:   "temperror.example",
			wantAccepts: false,
			wantStatus:  StatusTemperror,
			wantErr:     ErrDNS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accepts, status, _, _, _, err := LookupExternalReportsAccepted(
				context.Background(), resolver, tt.dmarcDomain, tt.extDomain)

			if accepts != tt.wantAccepts {
				t.Errorf("accepts: got %v, want %v", accepts, tt.wantAccepts)
			}

			if status != tt.wantStatus {
				t.Errorf("status: got %v, want %v", status, tt.wantStatus)
			}

			if tt.wantErr != nil {
				if err == nil || !errors.Is(err, tt.wantErr) {
					t.Errorf("error: got %v, want %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestEffectivePolicy(t *testing.T) {
	tests := []struct {
		name        string
		policy      Policy
		subPolicy   Policy
		isSubdomain bool
		want        Policy
	}{
		{
			name:        "domain - use policy",
			policy:      PolicyReject,
			subPolicy:   PolicyNone,
			isSubdomain: false,
			want:        PolicyReject,
		},
		{
			name:        "subdomain - use sp",
			policy:      PolicyReject,
			subPolicy:   PolicyNone,
			isSubdomain: true,
			want:        PolicyNone,
		},
		{
			name:        "subdomain - no sp, use p",
			policy:      PolicyReject,
			subPolicy:   PolicyEmpty,
			isSubdomain: true,
			want:        PolicyReject,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Record{
				Policy:          tt.policy,
				SubdomainPolicy: tt.subPolicy,
			}
			got := r.EffectivePolicy(tt.isSubdomain)
			if got != tt.want {
				t.Errorf("EffectivePolicy: got %v, want %v", got, tt.want)
			}
		})
	}
}
