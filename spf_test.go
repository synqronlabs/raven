package raven

import (
	"errors"
	"net"
	"testing"
)

// spfMockDNSResolver creates a mock DNS resolver for SPF testing.
func spfMockDNSResolver(records map[string][]string) func(string) ([]string, error) {
	return func(domain string) ([]string, error) {
		if recs, ok := records[domain]; ok {
			return recs, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: domain, IsNotFound: true}
	}
}

// spfMockDNSLookupA creates a mock A record resolver for SPF testing.
func spfMockDNSLookupA(records map[string][]net.IP) func(string) ([]net.IP, error) {
	return func(domain string) ([]net.IP, error) {
		if ips, ok := records[domain]; ok {
			return ips, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: domain, IsNotFound: true}
	}
}

// spfMockDNSLookupMX creates a mock MX record resolver for SPF testing.
func spfMockDNSLookupMX(records map[string][]*net.MX) func(string) ([]*net.MX, error) {
	return func(domain string) ([]*net.MX, error) {
		if mxs, ok := records[domain]; ok {
			return mxs, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: domain, IsNotFound: true}
	}
}

func TestParseSPFRecord(t *testing.T) {
	tests := []struct {
		name      string
		record    string
		wantErr   bool
		mechCount int
		redirect  string
		exp       string
		firstMech SPFMechanismType
		firstQual SPFQualifier
	}{
		{
			name:      "simple all",
			record:    "v=spf1 -all",
			wantErr:   false,
			mechCount: 1,
			firstMech: SPFMechanismAll,
			firstQual: SPFQualifierFail,
		},
		{
			name:      "simple pass all",
			record:    "v=spf1 +all",
			wantErr:   false,
			mechCount: 1,
			firstMech: SPFMechanismAll,
			firstQual: SPFQualifierPass,
		},
		{
			name:      "mx and all",
			record:    "v=spf1 mx -all",
			wantErr:   false,
			mechCount: 2,
			firstMech: SPFMechanismMX,
			firstQual: SPFQualifierPass, // default is +
		},
		{
			name:      "ip4 mechanism",
			record:    "v=spf1 ip4:192.168.1.0/24 -all",
			wantErr:   false,
			mechCount: 2,
			firstMech: SPFMechanismIP4,
		},
		{
			name:      "ip6 mechanism",
			record:    "v=spf1 ip6:2001:db8::/32 -all",
			wantErr:   false,
			mechCount: 2,
			firstMech: SPFMechanismIP6,
		},
		{
			name:      "include mechanism",
			record:    "v=spf1 include:_spf.google.com -all",
			wantErr:   false,
			mechCount: 2,
			firstMech: SPFMechanismInclude,
		},
		{
			name:      "a mechanism with domain",
			record:    "v=spf1 a:mail.example.com -all",
			wantErr:   false,
			mechCount: 2,
			firstMech: SPFMechanismA,
		},
		{
			name:      "redirect modifier",
			record:    "v=spf1 redirect=_spf.example.com",
			wantErr:   false,
			mechCount: 0,
			redirect:  "_spf.example.com",
		},
		{
			name:      "exp modifier",
			record:    "v=spf1 mx -all exp=explain._spf.example.com",
			wantErr:   false,
			mechCount: 2,
			firstMech: SPFMechanismMX,
			exp:       "explain._spf.example.com",
		},
		{
			name:      "exists mechanism",
			record:    "v=spf1 exists:%{i}._spf.example.com -all",
			wantErr:   false,
			mechCount: 2,
			firstMech: SPFMechanismExists,
		},
		{
			name:      "ptr mechanism",
			record:    "v=spf1 ptr -all",
			wantErr:   false,
			mechCount: 2,
			firstMech: SPFMechanismPTR,
		},
		{
			name:      "softfail all",
			record:    "v=spf1 ~all",
			wantErr:   false,
			mechCount: 1,
			firstMech: SPFMechanismAll,
			firstQual: SPFQualifierSoftfail,
		},
		{
			name:      "neutral all",
			record:    "v=spf1 ?all",
			wantErr:   false,
			mechCount: 1,
			firstMech: SPFMechanismAll,
			firstQual: SPFQualifierNeutral,
		},
		{
			name:      "empty record (just version)",
			record:    "v=spf1",
			wantErr:   false,
			mechCount: 0,
		},
		{
			name:      "complex record",
			record:    "v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.0/24 include:_spf.example.com mx a -all",
			wantErr:   false,
			mechCount: 6,
			firstMech: SPFMechanismIP4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record, err := parseSPFRecord(tt.record)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSPFRecord() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			if len(record.Mechanisms) != tt.mechCount {
				t.Errorf("parseSPFRecord() mechanism count = %d, want %d", len(record.Mechanisms), tt.mechCount)
			}

			if tt.mechCount > 0 && record.Mechanisms[0].Type != tt.firstMech {
				t.Errorf("parseSPFRecord() first mechanism = %s, want %s", record.Mechanisms[0].Type, tt.firstMech)
			}

			if tt.firstQual != "" && tt.mechCount > 0 && record.Mechanisms[0].Qualifier != tt.firstQual {
				t.Errorf("parseSPFRecord() first qualifier = %s, want %s", record.Mechanisms[0].Qualifier, tt.firstQual)
			}

			if record.Redirect != tt.redirect {
				t.Errorf("parseSPFRecord() redirect = %s, want %s", record.Redirect, tt.redirect)
			}

			if record.Exp != tt.exp {
				t.Errorf("parseSPFRecord() exp = %s, want %s", record.Exp, tt.exp)
			}
		})
	}
}

func TestParseMechanism(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantType  SPFMechanismType
		wantQual  SPFQualifier
		wantValue string
		wantCIDR  int
		wantErr   bool
	}{
		{
			name:     "all",
			input:    "all",
			wantType: SPFMechanismAll,
			wantQual: SPFQualifierPass,
			wantCIDR: -1,
		},
		{
			name:     "fail all",
			input:    "-all",
			wantType: SPFMechanismAll,
			wantQual: SPFQualifierFail,
			wantCIDR: -1,
		},
		{
			name:      "ip4 with CIDR",
			input:     "ip4:192.168.1.0/24",
			wantType:  SPFMechanismIP4,
			wantQual:  SPFQualifierPass,
			wantValue: "192.168.1.0",
			wantCIDR:  -1, // CIDR is stored in IPNet
		},
		{
			name:      "ip4 single",
			input:     "ip4:192.168.1.1",
			wantType:  SPFMechanismIP4,
			wantQual:  SPFQualifierPass,
			wantValue: "192.168.1.1",
		},
		{
			name:      "include",
			input:     "include:_spf.example.com",
			wantType:  SPFMechanismInclude,
			wantQual:  SPFQualifierPass,
			wantValue: "_spf.example.com",
			wantCIDR:  -1,
		},
		{
			name:     "mx simple",
			input:    "mx",
			wantType: SPFMechanismMX,
			wantQual: SPFQualifierPass,
			wantCIDR: -1,
		},
		{
			name:      "mx with domain",
			input:     "mx:mail.example.com",
			wantType:  SPFMechanismMX,
			wantQual:  SPFQualifierPass,
			wantValue: "mail.example.com",
		},
		{
			name:     "a simple",
			input:    "a",
			wantType: SPFMechanismA,
			wantQual: SPFQualifierPass,
			wantCIDR: -1,
		},
		{
			name:      "exists",
			input:     "exists:%{ir}.sbl.example.org",
			wantType:  SPFMechanismExists,
			wantQual:  SPFQualifierPass,
			wantValue: "%{ir}.sbl.example.org",
		},
		{
			name:    "include missing domain",
			input:   "include",
			wantErr: true,
		},
		{
			name:    "ip4 missing address",
			input:   "ip4",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mech, err := parseMechanism(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseMechanism() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			if mech.Type != tt.wantType {
				t.Errorf("parseMechanism() type = %s, want %s", mech.Type, tt.wantType)
			}

			if mech.Qualifier != tt.wantQual {
				t.Errorf("parseMechanism() qualifier = %s, want %s", mech.Qualifier, tt.wantQual)
			}

			if mech.Value != tt.wantValue {
				t.Errorf("parseMechanism() value = %s, want %s", mech.Value, tt.wantValue)
			}

			if tt.wantCIDR != 0 && mech.CIDR != tt.wantCIDR {
				t.Errorf("parseMechanism() CIDR = %d, want %d", mech.CIDR, tt.wantCIDR)
			}
		})
	}
}

func TestCheckSPF_IP4(t *testing.T) {
	// Set up mock DNS
	dnsRecords := map[string][]string{
		"example.com": {"v=spf1 ip4:192.0.2.0/24 -all"},
	}

	opts := &SPFCheckOptions{
		DNSResolver:    spfMockDNSResolver(dnsRecords),
		MaxDNSLookups:  10,
		MaxVoidLookups: 2,
	}

	tests := []struct {
		name string
		ip   string
		want SPFResult
	}{
		{
			name: "authorized IP",
			ip:   "192.0.2.1",
			want: SPFResultPass,
		},
		{
			name: "unauthorized IP",
			ip:   "192.0.3.1",
			want: SPFResultFail,
		},
		{
			name: "boundary IP in range",
			ip:   "192.0.2.255",
			want: SPFResultPass,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := CheckSPF(ip, "example.com", "user@example.com", opts)
			if result.Result != tt.want {
				t.Errorf("CheckSPF() result = %s, want %s", result.Result, tt.want)
			}
		})
	}
}

func TestCheckSPF_IP6(t *testing.T) {
	dnsRecords := map[string][]string{
		"example.com": {"v=spf1 ip6:2001:db8::/32 -all"},
	}

	opts := &SPFCheckOptions{
		DNSResolver:    spfMockDNSResolver(dnsRecords),
		MaxDNSLookups:  10,
		MaxVoidLookups: 2,
	}

	tests := []struct {
		name string
		ip   string
		want SPFResult
	}{
		{
			name: "authorized IPv6",
			ip:   "2001:db8::1",
			want: SPFResultPass,
		},
		{
			name: "unauthorized IPv6",
			ip:   "2001:db9::1",
			want: SPFResultFail,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := CheckSPF(ip, "example.com", "user@example.com", opts)
			if result.Result != tt.want {
				t.Errorf("CheckSPF() result = %s, want %s", result.Result, tt.want)
			}
		})
	}
}

func TestCheckSPF_AMechanism(t *testing.T) {
	dnsRecords := map[string][]string{
		"example.com": {"v=spf1 a -all"},
	}

	aRecords := map[string][]net.IP{
		"example.com": {net.ParseIP("192.0.2.1")},
	}

	opts := &SPFCheckOptions{
		DNSResolver:    spfMockDNSResolver(dnsRecords),
		DNSLookupA:     spfMockDNSLookupA(aRecords),
		MaxDNSLookups:  10,
		MaxVoidLookups: 2,
	}

	tests := []struct {
		name string
		ip   string
		want SPFResult
	}{
		{
			name: "authorized via A record",
			ip:   "192.0.2.1",
			want: SPFResultPass,
		},
		{
			name: "unauthorized",
			ip:   "192.0.2.2",
			want: SPFResultFail,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := CheckSPF(ip, "example.com", "user@example.com", opts)
			if result.Result != tt.want {
				t.Errorf("CheckSPF() result = %s, want %s", result.Result, tt.want)
			}
		})
	}
}

func TestCheckSPF_MXMechanism(t *testing.T) {
	dnsRecords := map[string][]string{
		"example.com": {"v=spf1 mx -all"},
	}

	mxRecords := map[string][]*net.MX{
		"example.com": {
			{Host: "mx1.example.com", Pref: 10},
			{Host: "mx2.example.com", Pref: 20},
		},
	}

	aRecords := map[string][]net.IP{
		"mx1.example.com": {net.ParseIP("192.0.2.10")},
		"mx2.example.com": {net.ParseIP("192.0.2.20")},
	}

	opts := &SPFCheckOptions{
		DNSResolver:    spfMockDNSResolver(dnsRecords),
		DNSLookupA:     spfMockDNSLookupA(aRecords),
		DNSLookupMX:    spfMockDNSLookupMX(mxRecords),
		MaxDNSLookups:  10,
		MaxVoidLookups: 2,
	}

	tests := []struct {
		name string
		ip   string
		want SPFResult
	}{
		{
			name: "authorized via MX (primary)",
			ip:   "192.0.2.10",
			want: SPFResultPass,
		},
		{
			name: "authorized via MX (secondary)",
			ip:   "192.0.2.20",
			want: SPFResultPass,
		},
		{
			name: "unauthorized",
			ip:   "192.0.2.30",
			want: SPFResultFail,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := CheckSPF(ip, "example.com", "user@example.com", opts)
			if result.Result != tt.want {
				t.Errorf("CheckSPF() result = %s, want %s", result.Result, tt.want)
			}
		})
	}
}

func TestCheckSPF_Include(t *testing.T) {
	dnsRecords := map[string][]string{
		"example.com":      {"v=spf1 include:_spf.example.com -all"},
		"_spf.example.com": {"v=spf1 ip4:192.0.2.0/24 -all"},
	}

	opts := &SPFCheckOptions{
		DNSResolver:    spfMockDNSResolver(dnsRecords),
		MaxDNSLookups:  10,
		MaxVoidLookups: 2,
	}

	tests := []struct {
		name string
		ip   string
		want SPFResult
	}{
		{
			name: "authorized via include",
			ip:   "192.0.2.1",
			want: SPFResultPass,
		},
		{
			name: "unauthorized",
			ip:   "192.0.3.1",
			want: SPFResultFail,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := CheckSPF(ip, "example.com", "user@example.com", opts)
			if result.Result != tt.want {
				t.Errorf("CheckSPF() result = %s, want %s", result.Result, tt.want)
			}
		})
	}
}

func TestCheckSPF_Redirect(t *testing.T) {
	dnsRecords := map[string][]string{
		"example.com":      {"v=spf1 redirect=_spf.example.com"},
		"_spf.example.com": {"v=spf1 ip4:192.0.2.0/24 -all"},
	}

	opts := &SPFCheckOptions{
		DNSResolver:    spfMockDNSResolver(dnsRecords),
		MaxDNSLookups:  10,
		MaxVoidLookups: 2,
	}

	tests := []struct {
		name string
		ip   string
		want SPFResult
	}{
		{
			name: "authorized via redirect",
			ip:   "192.0.2.1",
			want: SPFResultPass,
		},
		{
			name: "unauthorized via redirect",
			ip:   "192.0.3.1",
			want: SPFResultFail,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := CheckSPF(ip, "example.com", "user@example.com", opts)
			if result.Result != tt.want {
				t.Errorf("CheckSPF() result = %s, want %s", result.Result, tt.want)
			}
		})
	}
}

func TestCheckSPF_Qualifiers(t *testing.T) {
	tests := []struct {
		name   string
		record string
		want   SPFResult
	}{
		{
			name:   "pass",
			record: "v=spf1 +all",
			want:   SPFResultPass,
		},
		{
			name:   "fail",
			record: "v=spf1 -all",
			want:   SPFResultFail,
		},
		{
			name:   "softfail",
			record: "v=spf1 ~all",
			want:   SPFResultSoftfail,
		},
		{
			name:   "neutral",
			record: "v=spf1 ?all",
			want:   SPFResultNeutral,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dnsRecords := map[string][]string{
				"example.com": {tt.record},
			}

			opts := &SPFCheckOptions{
				DNSResolver:    spfMockDNSResolver(dnsRecords),
				MaxDNSLookups:  10,
				MaxVoidLookups: 2,
			}

			ip := net.ParseIP("192.0.2.1")
			result := CheckSPF(ip, "example.com", "user@example.com", opts)
			if result.Result != tt.want {
				t.Errorf("CheckSPF() result = %s, want %s", result.Result, tt.want)
			}
		})
	}
}

func TestCheckSPF_NoRecord(t *testing.T) {
	dnsRecords := map[string][]string{
		// No SPF record for example.com
		"example.com": {"some other TXT record"},
	}

	opts := &SPFCheckOptions{
		DNSResolver:    spfMockDNSResolver(dnsRecords),
		MaxDNSLookups:  10,
		MaxVoidLookups: 2,
	}

	ip := net.ParseIP("192.0.2.1")
	result := CheckSPF(ip, "example.com", "user@example.com", opts)
	if result.Result != SPFResultNone {
		t.Errorf("CheckSPF() result = %s, want %s", result.Result, SPFResultNone)
	}
}

func TestCheckSPF_MultipleRecords(t *testing.T) {
	// Multiple SPF records is a permerror per RFC 7208 Section 4.5
	dnsRecords := map[string][]string{
		"example.com": {
			"v=spf1 ip4:192.0.2.0/24 -all",
			"v=spf1 ip4:192.0.3.0/24 -all",
		},
	}

	opts := &SPFCheckOptions{
		DNSResolver:    spfMockDNSResolver(dnsRecords),
		MaxDNSLookups:  10,
		MaxVoidLookups: 2,
	}

	ip := net.ParseIP("192.0.2.1")
	result := CheckSPF(ip, "example.com", "user@example.com", opts)
	if result.Result != SPFResultPermerror {
		t.Errorf("CheckSPF() result = %s, want %s", result.Result, SPFResultPermerror)
	}
}

func TestCheckSPF_DNSLookupLimit(t *testing.T) {
	// Create a chain of includes that exceeds the 10 lookup limit
	dnsRecords := map[string][]string{
		"example.com":     {"v=spf1 include:s1.example.com -all"},
		"s1.example.com":  {"v=spf1 include:s2.example.com -all"},
		"s2.example.com":  {"v=spf1 include:s3.example.com -all"},
		"s3.example.com":  {"v=spf1 include:s4.example.com -all"},
		"s4.example.com":  {"v=spf1 include:s5.example.com -all"},
		"s5.example.com":  {"v=spf1 include:s6.example.com -all"},
		"s6.example.com":  {"v=spf1 include:s7.example.com -all"},
		"s7.example.com":  {"v=spf1 include:s8.example.com -all"},
		"s8.example.com":  {"v=spf1 include:s9.example.com -all"},
		"s9.example.com":  {"v=spf1 include:s10.example.com -all"},
		"s10.example.com": {"v=spf1 include:s11.example.com -all"},
		"s11.example.com": {"v=spf1 -all"},
	}

	opts := &SPFCheckOptions{
		DNSResolver:    spfMockDNSResolver(dnsRecords),
		MaxDNSLookups:  10,
		MaxVoidLookups: 2,
	}

	ip := net.ParseIP("192.0.2.1")
	result := CheckSPF(ip, "example.com", "user@example.com", opts)
	if result.Result != SPFResultPermerror {
		t.Errorf("CheckSPF() result = %s, want %s", result.Result, SPFResultPermerror)
	}
	if !errors.Is(result.Error, ErrSPFTooManyDNSLookups) {
		t.Errorf("CheckSPF() error = %v, want %v", result.Error, ErrSPFTooManyDNSLookups)
	}
}

func TestCheckSPF_InvalidDomain(t *testing.T) {
	opts := DefaultSPFCheckOptions()

	tests := []struct {
		name   string
		domain string
		want   SPFResult
	}{
		{
			name:   "empty domain",
			domain: "",
			want:   SPFResultNone,
		},
		{
			name:   "single label",
			domain: "localhost",
			want:   SPFResultNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP("192.0.2.1")
			result := CheckSPF(ip, tt.domain, "user@"+tt.domain, opts)
			if result.Result != tt.want {
				t.Errorf("CheckSPF() result = %s, want %s", result.Result, tt.want)
			}
		})
	}
}

func TestCheckSPF_DefaultResult(t *testing.T) {
	// No mechanisms match, no redirect - should return neutral
	dnsRecords := map[string][]string{
		"example.com": {"v=spf1 ip4:10.0.0.0/8"},
	}

	opts := &SPFCheckOptions{
		DNSResolver:    spfMockDNSResolver(dnsRecords),
		MaxDNSLookups:  10,
		MaxVoidLookups: 2,
	}

	ip := net.ParseIP("192.0.2.1") // Not in 10.0.0.0/8
	result := CheckSPF(ip, "example.com", "user@example.com", opts)
	if result.Result != SPFResultNeutral {
		t.Errorf("CheckSPF() result = %s, want %s", result.Result, SPFResultNeutral)
	}
}

func TestMacroExpansion(t *testing.T) {
	checker := &spfChecker{
		opts:         DefaultSPFCheckOptions(),
		ip:           net.ParseIP("192.0.2.3"),
		sender:       "user@example.com",
		senderLocal:  "user",
		senderDomain: "example.com",
		heloDomain:   "mail.example.com",
	}

	tests := []struct {
		name   string
		input  string
		domain string
		want   string
	}{
		{
			name:   "sender",
			input:  "%{s}",
			domain: "example.com",
			want:   "user@example.com",
		},
		{
			name:   "local part",
			input:  "%{l}",
			domain: "example.com",
			want:   "user",
		},
		{
			name:   "sender domain",
			input:  "%{o}",
			domain: "example.com",
			want:   "example.com",
		},
		{
			name:   "domain",
			input:  "%{d}",
			domain: "example.com",
			want:   "example.com",
		},
		{
			name:   "ip",
			input:  "%{i}",
			domain: "example.com",
			want:   "192.0.2.3",
		},
		{
			name:   "helo",
			input:  "%{h}",
			domain: "example.com",
			want:   "mail.example.com",
		},
		{
			name:   "ip version",
			input:  "%{v}",
			domain: "example.com",
			want:   "in-addr",
		},
		{
			name:   "literal percent",
			input:  "%%",
			domain: "example.com",
			want:   "%",
		},
		{
			name:   "space",
			input:  "%_",
			domain: "example.com",
			want:   " ",
		},
		{
			name:   "complex",
			input:  "%{ir}.%{v}._spf.%{d}",
			domain: "example.com",
			want:   "3.2.0.192.in-addr._spf.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checker.expandMacros(tt.input, tt.domain)
			if result != tt.want {
				t.Errorf("expandMacros() = %s, want %s", result, tt.want)
			}
		})
	}
}

func TestIPv6MacroExpansion(t *testing.T) {
	checker := &spfChecker{
		opts:         DefaultSPFCheckOptions(),
		ip:           net.ParseIP("2001:db8::cb01"),
		sender:       "user@example.com",
		senderLocal:  "user",
		senderDomain: "example.com",
	}

	// IPv6 %{i} should produce dot-separated nibbles
	result := checker.expandMacros("%{i}", "example.com")
	// 2001:db8::cb01 expanded to nibbles
	expected := "2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.b.0.1"
	if result != expected {
		t.Errorf("expandMacros() IPv6 = %s, want %s", result, expected)
	}

	// %{v} should be "ip6"
	result = checker.expandMacros("%{v}", "example.com")
	if result != "ip6" {
		t.Errorf("expandMacros() version = %s, want ip6", result)
	}
}

func TestIsValidDomain(t *testing.T) {
	tests := []struct {
		domain string
		valid  bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"example.co.uk", true},
		{"", false},
		{"localhost", false}, // single label
		{"example", false},   // single label
		{".example.com", true},
		{"example..com", true},                      // Empty labels are allowed (though unusual)
		{string(make([]byte, 300)) + ".com", false}, // Too long
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			if got := isValidDomain(tt.domain); got != tt.valid {
				t.Errorf("isValidDomain(%s) = %v, want %v", tt.domain, got, tt.valid)
			}
		})
	}
}

func TestParseSender(t *testing.T) {
	tests := []struct {
		sender     string
		wantLocal  string
		wantDomain string
	}{
		{"user@example.com", "user", "example.com"},
		{"<user@example.com>", "user", "example.com"},
		{"user+tag@example.com", "user+tag", "example.com"},
		{"example.com", "", "example.com"},
		{"", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.sender, func(t *testing.T) {
			local, domain := parseSender(tt.sender)
			if local != tt.wantLocal {
				t.Errorf("parseSender() local = %s, want %s", local, tt.wantLocal)
			}
			if domain != tt.wantDomain {
				t.Errorf("parseSender() domain = %s, want %s", domain, tt.wantDomain)
			}
		})
	}
}

func TestSPFCheckResult_ReceivedSPFHeader(t *testing.T) {
	result := &SPFCheckResult{
		Result:    SPFResultPass,
		Domain:    "example.com",
		Sender:    "user@example.com",
		ClientIP:  net.ParseIP("192.0.2.1"),
		Mechanism: "+ip4:192.0.2.0/24",
	}

	header := result.ReceivedSPFHeader()
	if header == "" {
		t.Error("ReceivedSPFHeader() returned empty string")
	}

	// Check that the header contains expected components
	if !containsAll(header, []string{"pass", "192.0.2.1", "example.com"}) {
		t.Errorf("ReceivedSPFHeader() missing expected components: %s", header)
	}
}

func containsAll(s string, substrings []string) bool {
	for _, sub := range substrings {
		if !containsString(s, sub) {
			return false
		}
	}
	return true
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestCheckSPF_Exists(t *testing.T) {
	dnsRecords := map[string][]string{
		"example.com": {"v=spf1 exists:%{i}._spf.example.com -all"},
	}

	aRecords := map[string][]net.IP{
		"192.0.2.1._spf.example.com": {net.ParseIP("127.0.0.1")}, // Any A record makes exists match
	}

	opts := &SPFCheckOptions{
		DNSResolver:    spfMockDNSResolver(dnsRecords),
		DNSLookupA:     spfMockDNSLookupA(aRecords),
		MaxDNSLookups:  10,
		MaxVoidLookups: 2,
	}

	tests := []struct {
		name string
		ip   string
		want SPFResult
	}{
		{
			name: "exists matches",
			ip:   "192.0.2.1",
			want: SPFResultPass,
		},
		{
			name: "exists no match",
			ip:   "192.0.2.2",
			want: SPFResultFail,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := CheckSPF(ip, "example.com", "user@example.com", opts)
			if result.Result != tt.want {
				t.Errorf("CheckSPF() result = %s, want %s", result.Result, tt.want)
			}
		})
	}
}
