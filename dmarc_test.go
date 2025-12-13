package raven

import (
	"maps"
	"net"
	"testing"
)

// dmarcMockDNSResolver creates a mock DNS resolver for DMARC testing.
func dmarcMockDNSResolver(records map[string][]string) func(string) ([]string, error) {
	return func(domain string) ([]string, error) {
		if recs, ok := records[domain]; ok {
			return recs, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: domain, IsNotFound: true}
	}
}

func TestParseDMARCRecord(t *testing.T) {
	tests := []struct {
		name              string
		record            string
		wantErr           bool
		wantPolicy        DMARCPolicy
		wantSubPolicy     DMARCPolicy
		wantDKIMAlignment DMARCAlignment
		wantSPFAlignment  DMARCAlignment
		wantPercent       int
	}{
		{
			name:              "minimal valid record",
			record:            "v=DMARC1; p=none",
			wantErr:           false,
			wantPolicy:        DMARCPolicyNone,
			wantDKIMAlignment: DMARCAlignmentRelaxed, // default
			wantSPFAlignment:  DMARCAlignmentRelaxed, // default
			wantPercent:       100,                   // default
		},
		{
			name:              "quarantine policy",
			record:            "v=DMARC1; p=quarantine",
			wantErr:           false,
			wantPolicy:        DMARCPolicyQuarantine,
			wantDKIMAlignment: DMARCAlignmentRelaxed,
			wantSPFAlignment:  DMARCAlignmentRelaxed,
			wantPercent:       100,
		},
		{
			name:              "reject policy",
			record:            "v=DMARC1; p=reject",
			wantErr:           false,
			wantPolicy:        DMARCPolicyReject,
			wantDKIMAlignment: DMARCAlignmentRelaxed,
			wantSPFAlignment:  DMARCAlignmentRelaxed,
			wantPercent:       100,
		},
		{
			name:              "full record with all tags",
			record:            "v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=s; pct=50; rua=mailto:reports@example.com; ruf=mailto:forensic@example.com; ri=3600; fo=1",
			wantErr:           false,
			wantPolicy:        DMARCPolicyReject,
			wantSubPolicy:     DMARCPolicyQuarantine,
			wantDKIMAlignment: DMARCAlignmentStrict,
			wantSPFAlignment:  DMARCAlignmentStrict,
			wantPercent:       50,
		},
		{
			name:       "missing version",
			record:     "p=none",
			wantErr:    true,
			wantPolicy: "",
		},
		{
			name:       "invalid version",
			record:     "v=DMARC2; p=none",
			wantErr:    true,
			wantPolicy: "",
		},
		{
			name:       "missing policy",
			record:     "v=DMARC1",
			wantErr:    true,
			wantPolicy: "",
		},
		{
			name:              "missing policy but has rua (treated as p=none)",
			record:            "v=DMARC1; rua=mailto:reports@example.com",
			wantErr:           false,
			wantPolicy:        DMARCPolicyNone,
			wantDKIMAlignment: DMARCAlignmentRelaxed,
			wantSPFAlignment:  DMARCAlignmentRelaxed,
			wantPercent:       100,
		},
		{
			name:       "invalid policy value",
			record:     "v=DMARC1; p=invalid",
			wantErr:    true,
			wantPolicy: "",
		},
		{
			name:              "whitespace handling",
			record:            "v=DMARC1 ; p=none ; adkim=r ; aspf=r",
			wantErr:           false,
			wantPolicy:        DMARCPolicyNone,
			wantDKIMAlignment: DMARCAlignmentRelaxed,
			wantSPFAlignment:  DMARCAlignmentRelaxed,
			wantPercent:       100,
		},
		{
			name:              "unknown tags ignored",
			record:            "v=DMARC1; p=none; xyz=unknown; foo=bar",
			wantErr:           false,
			wantPolicy:        DMARCPolicyNone,
			wantDKIMAlignment: DMARCAlignmentRelaxed,
			wantSPFAlignment:  DMARCAlignmentRelaxed,
			wantPercent:       100,
		},
		{
			name:              "multiple rua URIs",
			record:            "v=DMARC1; p=none; rua=mailto:a@example.com,mailto:b@example.com",
			wantErr:           false,
			wantPolicy:        DMARCPolicyNone,
			wantDKIMAlignment: DMARCAlignmentRelaxed,
			wantSPFAlignment:  DMARCAlignmentRelaxed,
			wantPercent:       100,
		},
		{
			name:              "rua with size limit",
			record:            "v=DMARC1; p=none; rua=mailto:reports@example.com!50m",
			wantErr:           false,
			wantPolicy:        DMARCPolicyNone,
			wantDKIMAlignment: DMARCAlignmentRelaxed,
			wantSPFAlignment:  DMARCAlignmentRelaxed,
			wantPercent:       100,
		},
		{
			name:              "pct boundary 0",
			record:            "v=DMARC1; p=reject; pct=0",
			wantErr:           false,
			wantPolicy:        DMARCPolicyReject,
			wantDKIMAlignment: DMARCAlignmentRelaxed,
			wantSPFAlignment:  DMARCAlignmentRelaxed,
			wantPercent:       0,
		},
		{
			name:              "ri value",
			record:            "v=DMARC1; p=none; ri=7200",
			wantErr:           false,
			wantPolicy:        DMARCPolicyNone,
			wantDKIMAlignment: DMARCAlignmentRelaxed,
			wantSPFAlignment:  DMARCAlignmentRelaxed,
			wantPercent:       100,
		},
		{
			name:              "failure reporting options",
			record:            "v=DMARC1; p=none; fo=1:d:s",
			wantErr:           false,
			wantPolicy:        DMARCPolicyNone,
			wantDKIMAlignment: DMARCAlignmentRelaxed,
			wantSPFAlignment:  DMARCAlignmentRelaxed,
			wantPercent:       100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record, err := parseDMARCRecord(tt.record)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDMARCRecord() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			if record.Policy != tt.wantPolicy {
				t.Errorf("Policy = %v, want %v", record.Policy, tt.wantPolicy)
			}
			if record.SubdomainPolicy != tt.wantSubPolicy {
				t.Errorf("SubdomainPolicy = %v, want %v", record.SubdomainPolicy, tt.wantSubPolicy)
			}
			if record.DKIMAlignment != tt.wantDKIMAlignment {
				t.Errorf("DKIMAlignment = %v, want %v", record.DKIMAlignment, tt.wantDKIMAlignment)
			}
			if record.SPFAlignment != tt.wantSPFAlignment {
				t.Errorf("SPFAlignment = %v, want %v", record.SPFAlignment, tt.wantSPFAlignment)
			}
			if record.Percent != tt.wantPercent {
				t.Errorf("Percent = %v, want %v", record.Percent, tt.wantPercent)
			}
		})
	}
}

func TestParseDMARCRecordURIs(t *testing.T) {
	record, err := parseDMARCRecord("v=DMARC1; p=none; rua=mailto:a@example.com,mailto:b@example.com; ruf=mailto:c@example.com!10m")
	if err != nil {
		t.Fatalf("parseDMARCRecord() error = %v", err)
	}

	if len(record.AggregateReportURIs) != 2 {
		t.Errorf("AggregateReportURIs count = %d, want 2", len(record.AggregateReportURIs))
	}
	if len(record.FailureReportURIs) != 1 {
		t.Errorf("FailureReportURIs count = %d, want 1", len(record.FailureReportURIs))
	}
	// Size limit should be stripped
	if record.FailureReportURIs[0] != "mailto:c@example.com" {
		t.Errorf("FailureReportURIs[0] = %s, want mailto:c@example.com", record.FailureReportURIs[0])
	}
}

func TestParseFailureReportingOptions(t *testing.T) {
	tests := []struct {
		value        string
		wantAllFail  bool
		wantAnyFail  bool
		wantDKIMFail bool
		wantSPFFail  bool
	}{
		{"0", true, false, false, false},
		{"1", false, true, false, false},
		{"d", false, false, true, false},
		{"s", false, false, false, true},
		{"0:1", true, true, false, false},
		{"1:d:s", false, true, true, true},
		{"", true, false, false, false}, // default
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			opts := parseFailureReportingOptions(tt.value)
			if opts.ReportOnAllFail != tt.wantAllFail {
				t.Errorf("ReportOnAllFail = %v, want %v", opts.ReportOnAllFail, tt.wantAllFail)
			}
			if opts.ReportOnAnyFail != tt.wantAnyFail {
				t.Errorf("ReportOnAnyFail = %v, want %v", opts.ReportOnAnyFail, tt.wantAnyFail)
			}
			if opts.ReportOnDKIMFail != tt.wantDKIMFail {
				t.Errorf("ReportOnDKIMFail = %v, want %v", opts.ReportOnDKIMFail, tt.wantDKIMFail)
			}
			if opts.ReportOnSPFFail != tt.wantSPFFail {
				t.Errorf("ReportOnSPFFail = %v, want %v", opts.ReportOnSPFFail, tt.wantSPFFail)
			}
		})
	}
}

func TestGetOrganizationalDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		// Simple cases
		{"example.com", "example.com"},
		{"sub.example.com", "example.com"},
		{"deep.sub.example.com", "example.com"},

		// Country code TLDs with second-level
		{"example.co.uk", "example.co.uk"},
		{"sub.example.co.uk", "example.co.uk"},
		{"example.com.au", "example.com.au"},
		{"sub.example.com.au", "example.com.au"},

		// Other gTLDs
		{"example.org", "example.org"},
		{"example.net", "example.net"},
		{"example.info", "example.info"},

		// Japanese domains
		{"example.co.jp", "example.co.jp"},
		{"sub.example.co.jp", "example.co.jp"},

		// Edge cases
		{"com", "com"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := getOrganizationalDomain(tt.domain, isPublicSuffix)
			if got != tt.want {
				t.Errorf("getOrganizationalDomain(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

func TestIsPublicSuffix(t *testing.T) {
	tests := []struct {
		domain string
		want   bool
	}{
		// TLDs
		{"com", true},
		{"org", true},
		{"net", true},
		{"uk", true},
		{"de", true},

		// Second-level suffixes
		{"co.uk", true},
		{"com.au", true},
		{"co.jp", true},
		{"gov.uk", true},

		// Not public suffixes
		{"example.com", false},
		{"google.com", false},
		{"example.co.uk", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := isPublicSuffix(tt.domain)
			if got != tt.want {
				t.Errorf("isPublicSuffix(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestExtractDomainFromHeader(t *testing.T) {
	tests := []struct {
		header string
		want   string
	}{
		{"sender@example.com", "example.com"},
		{"<sender@example.com>", "example.com"},
		{"Sender Name <sender@example.com>", "example.com"},
		{"\"Sender Name\" <sender@example.com>", "example.com"},
		{"sender@sub.example.com", "sub.example.com"},
		{"", ""},
		{"nodomain", ""},
	}

	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			got := extractDomainFromHeader(tt.header)
			if got != tt.want {
				t.Errorf("extractDomainFromHeader(%q) = %q, want %q", tt.header, got, tt.want)
			}
		})
	}
}

func TestLookupDMARCRecord(t *testing.T) {
	tests := []struct {
		name       string
		fromDomain string
		orgDomain  string
		records    map[string][]string
		wantErr    error
		wantOrg    bool
		wantPolicy DMARCPolicy
	}{
		{
			name:       "record at From domain",
			fromDomain: "example.com",
			orgDomain:  "example.com",
			records: map[string][]string{
				"_dmarc.example.com": {"v=DMARC1; p=reject"},
			},
			wantErr:    nil,
			wantOrg:    false,
			wantPolicy: DMARCPolicyReject,
		},
		{
			name:       "record at org domain only",
			fromDomain: "sub.example.com",
			orgDomain:  "example.com",
			records: map[string][]string{
				"_dmarc.example.com": {"v=DMARC1; p=quarantine"},
			},
			wantErr:    nil,
			wantOrg:    true,
			wantPolicy: DMARCPolicyQuarantine,
		},
		{
			name:       "record at both domains prefers From domain",
			fromDomain: "sub.example.com",
			orgDomain:  "example.com",
			records: map[string][]string{
				"_dmarc.sub.example.com": {"v=DMARC1; p=reject"},
				"_dmarc.example.com":     {"v=DMARC1; p=none"},
			},
			wantErr:    nil,
			wantOrg:    false,
			wantPolicy: DMARCPolicyReject,
		},
		{
			name:       "no record found",
			fromDomain: "example.com",
			orgDomain:  "example.com",
			records:    map[string][]string{},
			wantErr:    ErrDMARCNoRecord,
		},
		{
			name:       "multiple records error",
			fromDomain: "example.com",
			orgDomain:  "example.com",
			records: map[string][]string{
				"_dmarc.example.com": {"v=DMARC1; p=none", "v=DMARC1; p=reject"},
			},
			wantErr: ErrDMARCMultipleRecords,
		},
		{
			name:       "non-DMARC records ignored",
			fromDomain: "example.com",
			orgDomain:  "example.com",
			records: map[string][]string{
				"_dmarc.example.com": {"some other record", "v=DMARC1; p=reject"},
			},
			wantErr:    nil,
			wantOrg:    false,
			wantPolicy: DMARCPolicyReject,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := dmarcMockDNSResolver(tt.records)
			record, usedOrg, err := lookupDMARCRecord(tt.fromDomain, tt.orgDomain, resolver)

			if tt.wantErr != nil {
				if err == nil || !containsError(err, tt.wantErr) {
					t.Errorf("lookupDMARCRecord() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("lookupDMARCRecord() unexpected error = %v", err)
				return
			}

			if usedOrg != tt.wantOrg {
				t.Errorf("usedOrg = %v, want %v", usedOrg, tt.wantOrg)
			}

			if record.Policy != tt.wantPolicy {
				t.Errorf("Policy = %v, want %v", record.Policy, tt.wantPolicy)
			}
		})
	}
}

// Helper to check if error chain contains a specific error
func containsError(err, target error) bool {
	for err != nil {
		if err.Error() == target.Error() {
			return true
		}
		// Unwrap if possible
		if unwrapper, ok := err.(interface{ Unwrap() error }); ok {
			err = unwrapper.Unwrap()
		} else {
			break
		}
	}
	return false
}

func TestCheckDKIMAlignment(t *testing.T) {
	tests := []struct {
		name       string
		results    []DKIMResult
		fromDomain string
		orgDomain  string
		alignment  DMARCAlignment
		want       bool
	}{
		{
			name: "strict alignment - exact match",
			results: []DKIMResult{
				{Status: DKIMStatusPass, Domain: "example.com"},
			},
			fromDomain: "example.com",
			orgDomain:  "example.com",
			alignment:  DMARCAlignmentStrict,
			want:       true,
		},
		{
			name: "strict alignment - subdomain fails",
			results: []DKIMResult{
				{Status: DKIMStatusPass, Domain: "sub.example.com"},
			},
			fromDomain: "example.com",
			orgDomain:  "example.com",
			alignment:  DMARCAlignmentStrict,
			want:       false,
		},
		{
			name: "relaxed alignment - subdomain passes",
			results: []DKIMResult{
				{Status: DKIMStatusPass, Domain: "sub.example.com"},
			},
			fromDomain: "sub.example.com",
			orgDomain:  "example.com",
			alignment:  DMARCAlignmentRelaxed,
			want:       true,
		},
		{
			name: "relaxed alignment - org domain matches",
			results: []DKIMResult{
				{Status: DKIMStatusPass, Domain: "example.com"},
			},
			fromDomain: "sub.example.com",
			orgDomain:  "example.com",
			alignment:  DMARCAlignmentRelaxed,
			want:       true,
		},
		{
			name: "no passing DKIM",
			results: []DKIMResult{
				{Status: DKIMStatusFail, Domain: "example.com"},
			},
			fromDomain: "example.com",
			orgDomain:  "example.com",
			alignment:  DMARCAlignmentRelaxed,
			want:       false,
		},
		{
			name: "different domain fails",
			results: []DKIMResult{
				{Status: DKIMStatusPass, Domain: "other.com"},
			},
			fromDomain: "example.com",
			orgDomain:  "example.com",
			alignment:  DMARCAlignmentRelaxed,
			want:       false,
		},
		{
			name:       "no results",
			results:    []DKIMResult{},
			fromDomain: "example.com",
			orgDomain:  "example.com",
			alignment:  DMARCAlignmentRelaxed,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkDKIMAlignment(tt.results, tt.fromDomain, tt.orgDomain, tt.alignment)
			if got != tt.want {
				t.Errorf("checkDKIMAlignment() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckSPFAlignment(t *testing.T) {
	tests := []struct {
		name       string
		result     *SPFCheckResult
		fromDomain string
		orgDomain  string
		alignment  DMARCAlignment
		want       bool
	}{
		{
			name:       "strict alignment - exact match",
			result:     &SPFCheckResult{Result: SPFResultPass, Domain: "example.com"},
			fromDomain: "example.com",
			orgDomain:  "example.com",
			alignment:  DMARCAlignmentStrict,
			want:       true,
		},
		{
			name:       "strict alignment - subdomain fails",
			result:     &SPFCheckResult{Result: SPFResultPass, Domain: "sub.example.com"},
			fromDomain: "example.com",
			orgDomain:  "example.com",
			alignment:  DMARCAlignmentStrict,
			want:       false,
		},
		{
			name:       "relaxed alignment - subdomain passes",
			result:     &SPFCheckResult{Result: SPFResultPass, Domain: "sub.example.com"},
			fromDomain: "sub.example.com",
			orgDomain:  "example.com",
			alignment:  DMARCAlignmentRelaxed,
			want:       true,
		},
		{
			name:       "SPF fail - no alignment",
			result:     &SPFCheckResult{Result: SPFResultFail, Domain: "example.com"},
			fromDomain: "example.com",
			orgDomain:  "example.com",
			alignment:  DMARCAlignmentRelaxed,
			want:       false,
		},
		{
			name:       "nil result",
			result:     nil,
			fromDomain: "example.com",
			orgDomain:  "example.com",
			alignment:  DMARCAlignmentRelaxed,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkSPFAlignment(tt.result, tt.fromDomain, tt.orgDomain, tt.alignment)
			if got != tt.want {
				t.Errorf("checkSPFAlignment() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckDMARC(t *testing.T) {
	// Create a mail with basic headers
	createMail := func(from string) *Mail {
		mail := NewMail()
		mail.AddHeader("From", from)
		mail.AddHeader("Date", "Thu, 12 Dec 2024 10:00:00 +0000")
		mail.AddHeader("Subject", "Test")
		return mail
	}

	tests := []struct {
		name        string
		mail        *Mail
		clientIP    net.IP
		mailFrom    string
		dnsRecords  map[string][]string
		spfRecords  map[string][]string
		wantResult  DMARCResult
		wantPolicy  DMARCPolicy
		wantAligned bool // at least one alignment
	}{
		{
			name:       "no DMARC record - result none",
			mail:       createMail("sender@example.com"),
			clientIP:   net.ParseIP("192.168.1.1"),
			mailFrom:   "sender@example.com",
			dnsRecords: map[string][]string{},
			wantResult: DMARCResultNone,
		},
		{
			name:     "DMARC pass with SPF alignment",
			mail:     createMail("sender@example.com"),
			clientIP: net.ParseIP("192.168.1.1"),
			mailFrom: "sender@example.com",
			dnsRecords: map[string][]string{
				"_dmarc.example.com": {"v=DMARC1; p=reject"},
			},
			spfRecords: map[string][]string{
				"example.com": {"v=spf1 ip4:192.168.1.1 -all"},
			},
			wantResult:  DMARCResultPass,
			wantPolicy:  DMARCPolicyReject,
			wantAligned: true,
		},
		{
			name:     "DMARC fail - no alignment",
			mail:     createMail("sender@example.com"),
			clientIP: net.ParseIP("10.0.0.1"),
			mailFrom: "bounce@other.com", // Different domain
			dnsRecords: map[string][]string{
				"_dmarc.example.com": {"v=DMARC1; p=reject"},
			},
			spfRecords: map[string][]string{
				"other.com": {"v=spf1 ip4:10.0.0.1 -all"},
			},
			wantResult:  DMARCResultFail,
			wantPolicy:  DMARCPolicyReject,
			wantAligned: false,
		},
		{
			name:     "relaxed SPF alignment with subdomain",
			mail:     createMail("sender@example.com"),
			clientIP: net.ParseIP("192.168.1.1"),
			mailFrom: "bounce@sub.example.com",
			dnsRecords: map[string][]string{
				"_dmarc.example.com": {"v=DMARC1; p=reject; aspf=r"},
			},
			spfRecords: map[string][]string{
				"sub.example.com": {"v=spf1 ip4:192.168.1.1 -all"},
			},
			wantResult:  DMARCResultPass,
			wantPolicy:  DMARCPolicyReject,
			wantAligned: true,
		},
		{
			name:     "strict SPF alignment fails with subdomain",
			mail:     createMail("sender@example.com"),
			clientIP: net.ParseIP("192.168.1.1"),
			mailFrom: "bounce@sub.example.com",
			dnsRecords: map[string][]string{
				"_dmarc.example.com": {"v=DMARC1; p=reject; aspf=s"},
			},
			spfRecords: map[string][]string{
				"sub.example.com": {"v=spf1 ip4:192.168.1.1 -all"},
			},
			wantResult:  DMARCResultFail,
			wantPolicy:  DMARCPolicyReject,
			wantAligned: false,
		},
		{
			name:     "subdomain policy used",
			mail:     createMail("sender@sub.example.com"),
			clientIP: net.ParseIP("192.168.1.1"),
			mailFrom: "sender@sub.example.com",
			dnsRecords: map[string][]string{
				"_dmarc.example.com": {"v=DMARC1; p=reject; sp=none"},
			},
			spfRecords: map[string][]string{
				"sub.example.com": {"v=spf1 -all"}, // SPF fail
			},
			wantResult:  DMARCResultFail,
			wantPolicy:  DMARCPolicyNone, // sp=none overrides p=reject
			wantAligned: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Combine DMARC and SPF records
			allRecords := make(map[string][]string)
			maps.Copy(allRecords, tt.dnsRecords)
			maps.Copy(allRecords, tt.spfRecords)

			opts := &DMARCCheckOptions{
				DNSResolver:      dmarcMockDNSResolver(allRecords),
				PublicSuffixList: isPublicSuffix,
				SPFOptions: &SPFCheckOptions{
					DNSResolver: dmarcMockDNSResolver(allRecords),
				},
				DKIMOptions: &DKIMVerifyOptions{
					DNSResolver: dmarcMockDNSResolver(allRecords),
				},
				SkipDKIM: true, // Skip DKIM for these tests (no signatures)
			}

			result := CheckDMARC(tt.mail, tt.clientIP, tt.mailFrom, opts)

			if result.Result != tt.wantResult {
				t.Errorf("CheckDMARC() Result = %v, want %v", result.Result, tt.wantResult)
			}

			if tt.wantResult != DMARCResultNone {
				if result.Policy != tt.wantPolicy {
					t.Errorf("CheckDMARC() Policy = %v, want %v", result.Policy, tt.wantPolicy)
				}
			}

			gotAligned := result.SPFAligned || result.DKIMAligned
			if gotAligned != tt.wantAligned {
				t.Errorf("CheckDMARC() aligned = %v, want %v (SPF=%v, DKIM=%v)",
					gotAligned, tt.wantAligned, result.SPFAligned, result.DKIMAligned)
			}
		})
	}
}

func TestDMARCAuthenticationResultsHeader(t *testing.T) {
	result := &DMARCCheckResult{
		Result: DMARCResultPass,
		Domain: "example.com",
		Policy: DMARCPolicyReject,
		Record: &DMARCRecord{
			Policy: DMARCPolicyReject,
		},
		SPFAligned:  true,
		DKIMAligned: false,
		SPFResult: &SPFCheckResult{
			Result: SPFResultPass,
			Sender: "sender@example.com",
		},
		DKIMResults: []DKIMResult{
			{Status: DKIMStatusPass, Domain: "example.com", Selector: "s1"},
		},
	}

	header := result.AuthenticationResultsHeader("mail.receiver.com")

	// Check that header contains expected parts
	expectedParts := []string{
		"Authentication-Results: mail.receiver.com",
		"dmarc=pass",
		"p=reject",
		"header.from=example.com",
		"spf=pass",
		"smtp.mailfrom=sender@example.com",
		"dkim=pass",
		"header.d=example.com",
		"header.s=s1",
	}

	for _, part := range expectedParts {
		if !dmarcContainsString(header, part) {
			t.Errorf("Header missing expected part: %q\nGot: %s", part, header)
		}
	}
}

func dmarcContainsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && dmarcContainsSubstring(s, substr))
}

func dmarcContainsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestValidateDMARCRegex(t *testing.T) {
	tests := []struct {
		record string
		want   bool
	}{
		{"v=DMARC1; p=none", true},
		{"v=DMARC1;p=none", true},
		{"v=DMARC1", true},
		{"v=DMARC2; p=none", false},
		{"p=none", false},
		{"", false},
		{"v=spf1 -all", false},
	}

	for _, tt := range tests {
		t.Run(tt.record, func(t *testing.T) {
			got := ValidateDMARC.MatchString(tt.record)
			if got != tt.want {
				t.Errorf("ValidateDMARC.MatchString(%q) = %v, want %v", tt.record, got, tt.want)
			}
		})
	}
}

func TestExtractFromDomain(t *testing.T) {
	tests := []struct {
		name    string
		headers Headers
		want    string
		wantErr bool
	}{
		{
			name:    "simple From",
			headers: Headers{{Name: "From", Value: "sender@example.com"}},
			want:    "example.com",
			wantErr: false,
		},
		{
			name:    "From with display name",
			headers: Headers{{Name: "From", Value: "Sender Name <sender@example.com>"}},
			want:    "example.com",
			wantErr: false,
		},
		{
			name:    "From with quoted display name",
			headers: Headers{{Name: "From", Value: "\"Sender, Name\" <sender@example.com>"}},
			want:    "example.com",
			wantErr: false,
		},
		{
			name:    "missing From header",
			headers: Headers{{Name: "To", Value: "recipient@example.com"}},
			want:    "",
			wantErr: true,
		},
		{
			name:    "empty From value",
			headers: Headers{{Name: "From", Value: ""}},
			want:    "",
			wantErr: true,
		},
		{
			name:    "From with uppercase domain",
			headers: Headers{{Name: "From", Value: "sender@EXAMPLE.COM"}},
			want:    "example.com", // Should be lowercased
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mail := &Mail{
				Content: Content{
					Headers: tt.headers,
				},
			}

			got, err := extractFromDomain(mail)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractFromDomain() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("extractFromDomain() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDMARCVerifyOptions(t *testing.T) {
	opts := DefaultDMARCVerifyOptions()

	if !opts.Enabled {
		t.Error("DefaultDMARCVerifyOptions() Enabled should be true")
	}
	if opts.FailAction != DMARCActionReject {
		t.Errorf("DefaultDMARCVerifyOptions() FailAction = %v, want %v", opts.FailAction, DMARCActionReject)
	}
	if opts.QuarantineAction != DMARCActionMark {
		t.Errorf("DefaultDMARCVerifyOptions() QuarantineAction = %v, want %v", opts.QuarantineAction, DMARCActionMark)
	}
	if opts.CheckOptions == nil {
		t.Error("DefaultDMARCVerifyOptions() CheckOptions should not be nil")
	}
}
