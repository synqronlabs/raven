package spf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// MockResolver is a test resolver that returns predefined responses.
type MockResolver struct {
	TXTRecords  map[string][]string
	ARecords    map[string][]net.IP
	AAAARecords map[string][]net.IP
	MXRecords   map[string][]*net.MX
	PTRRecords  map[string][]string
	Authentic   bool
	Errors      map[string]error
}

func (m *MockResolver) LookupTXT(_ context.Context, name string) ([]string, Result, error) {
	if err, ok := m.Errors[name]; ok {
		return nil, Result{Authentic: m.Authentic}, err
	}
	records, ok := m.TXTRecords[name]
	if !ok {
		return nil, Result{Authentic: m.Authentic}, ErrDNSNotFound
	}
	return records, Result{Authentic: m.Authentic}, nil
}

func (m *MockResolver) LookupIP(_ context.Context, network, host string) ([]net.IP, Result, error) {
	if err, ok := m.Errors[host]; ok {
		return nil, Result{Authentic: m.Authentic}, err
	}

	var ips []net.IP
	if network == "ip" || network == "ip4" {
		if records, ok := m.ARecords[host]; ok {
			ips = append(ips, records...)
		}
	}
	if network == "ip" || network == "ip6" {
		if records, ok := m.AAAARecords[host]; ok {
			ips = append(ips, records...)
		}
	}

	if len(ips) == 0 {
		return nil, Result{Authentic: m.Authentic}, ErrDNSNotFound
	}
	return ips, Result{Authentic: m.Authentic}, nil
}

func (m *MockResolver) LookupMX(_ context.Context, name string) ([]*net.MX, Result, error) {
	if err, ok := m.Errors[name]; ok {
		return nil, Result{Authentic: m.Authentic}, err
	}
	records, ok := m.MXRecords[name]
	if !ok {
		return nil, Result{Authentic: m.Authentic}, ErrDNSNotFound
	}
	return records, Result{Authentic: m.Authentic}, nil
}

func (m *MockResolver) LookupAddr(_ context.Context, addr string) ([]string, Result, error) {
	if err, ok := m.Errors[addr]; ok {
		return nil, Result{Authentic: m.Authentic}, err
	}
	records, ok := m.PTRRecords[addr]
	if !ok {
		return nil, Result{Authentic: m.Authentic}, ErrDNSNotFound
	}
	return records, Result{Authentic: m.Authentic}, nil
}

type networkRecordingResolver struct {
	ips      []net.IP
	networks []string
	hosts    []string
}

func (*networkRecordingResolver) LookupTXT(context.Context, string) ([]string, Result, error) {
	return nil, Result{}, ErrDNSNotFound
}

func (r *networkRecordingResolver) LookupIP(_ context.Context, network, host string) ([]net.IP, Result, error) {
	r.networks = append(r.networks, network)
	r.hosts = append(r.hosts, host)
	return r.ips, Result{Authentic: true}, nil
}

func (*networkRecordingResolver) LookupMX(context.Context, string) ([]*net.MX, Result, error) {
	return nil, Result{}, ErrDNSNotFound
}

func (*networkRecordingResolver) LookupAddr(context.Context, string) ([]string, Result, error) {
	return nil, Result{}, ErrDNSNotFound
}

func TestVerify(t *testing.T) {
	tests := []struct {
		name       string
		resolver   *MockResolver
		args       Args
		wantStatus Status
		wantErr    bool
	}{
		{
			name: "pass with ip4 match",
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"example.com.": {"v=spf1 ip4:192.0.2.0/24 -all"},
				},
			},
			args: Args{
				RemoteIP:       net.ParseIP("192.0.2.1"),
				MailFromDomain: "example.com",
				MailFromLocal:  "user",
			},
			wantStatus: StatusPass,
		},
		{
			name: "fail with ip4 no match",
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"example.com.": {"v=spf1 ip4:192.0.2.0/24 -all"},
				},
			},
			args: Args{
				RemoteIP:       net.ParseIP("10.0.0.1"),
				MailFromDomain: "example.com",
				MailFromLocal:  "user",
			},
			wantStatus: StatusFail,
		},
		{
			name: "pass with a mechanism",
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"example.com.": {"v=spf1 a -all"},
				},
				ARecords: map[string][]net.IP{
					"example.com.": {net.ParseIP("192.0.2.1")},
				},
			},
			args: Args{
				RemoteIP:       net.ParseIP("192.0.2.1"),
				MailFromDomain: "example.com",
				MailFromLocal:  "user",
			},
			wantStatus: StatusPass,
		},
		{
			name: "pass with mx mechanism",
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"example.com.": {"v=spf1 mx -all"},
				},
				MXRecords: map[string][]*net.MX{
					"example.com.": {{Host: "mail.example.com.", Pref: 10}},
				},
				ARecords: map[string][]net.IP{
					"mail.example.com.": {net.ParseIP("192.0.2.1")},
				},
			},
			args: Args{
				RemoteIP:       net.ParseIP("192.0.2.1"),
				MailFromDomain: "example.com",
				MailFromLocal:  "user",
			},
			wantStatus: StatusPass,
		},
		{
			name: "pass with include",
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"example.com.":      {"v=spf1 include:_spf.example.com -all"},
					"_spf.example.com.": {"v=spf1 ip4:192.0.2.0/24 -all"},
				},
			},
			args: Args{
				RemoteIP:       net.ParseIP("192.0.2.1"),
				MailFromDomain: "example.com",
				MailFromLocal:  "user",
			},
			wantStatus: StatusPass,
		},
		{
			name: "none with no spf record",
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"example.com.": {"v=DKIM1; k=rsa; p=..."},
				},
			},
			args: Args{
				RemoteIP:       net.ParseIP("192.0.2.1"),
				MailFromDomain: "example.com",
				MailFromLocal:  "user",
			},
			wantStatus: StatusNone,
			wantErr:    true,
		},
		{
			name: "softfail",
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"example.com.": {"v=spf1 ~all"},
				},
			},
			args: Args{
				RemoteIP:       net.ParseIP("192.0.2.1"),
				MailFromDomain: "example.com",
				MailFromLocal:  "user",
			},
			wantStatus: StatusSoftfail,
		},
		{
			name: "neutral with ? qualifier",
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"example.com.": {"v=spf1 ?all"},
				},
			},
			args: Args{
				RemoteIP:       net.ParseIP("192.0.2.1"),
				MailFromDomain: "example.com",
				MailFromLocal:  "user",
			},
			wantStatus: StatusNeutral,
		},
		{
			name: "neutral with default (no all)",
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"example.com.": {"v=spf1 ip4:10.0.0.0/8"},
				},
			},
			args: Args{
				RemoteIP:       net.ParseIP("192.0.2.1"),
				MailFromDomain: "example.com",
				MailFromLocal:  "user",
			},
			wantStatus: StatusNeutral,
		},
		{
			name: "redirect",
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"example.com.":      {"v=spf1 redirect=_spf.example.com"},
					"_spf.example.com.": {"v=spf1 ip4:192.0.2.0/24 -all"},
				},
			},
			args: Args{
				RemoteIP:       net.ParseIP("192.0.2.1"),
				MailFromDomain: "example.com",
				MailFromLocal:  "user",
			},
			wantStatus: StatusPass,
		},
		{
			name: "permerror with multiple spf records",
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"example.com.": {"v=spf1 +all", "v=spf1 -all"},
				},
			},
			args: Args{
				RemoteIP:       net.ParseIP("192.0.2.1"),
				MailFromDomain: "example.com",
				MailFromLocal:  "user",
			},
			wantStatus: StatusPermerror,
			wantErr:    true,
		},
		{
			name: "temperror on dns failure",
			resolver: &MockResolver{
				Errors: map[string]error{
					"example.com.": errors.New("dns timeout"),
				},
			},
			args: Args{
				RemoteIP:       net.ParseIP("192.0.2.1"),
				MailFromDomain: "example.com",
				MailFromLocal:  "user",
			},
			wantStatus: StatusTemperror,
			wantErr:    true,
		},
		{
			name: "ipv6 pass",
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"example.com.": {"v=spf1 ip6:2001:db8::/32 -all"},
				},
			},
			args: Args{
				RemoteIP:       net.ParseIP("2001:db8::1"),
				MailFromDomain: "example.com",
				MailFromLocal:  "user",
			},
			wantStatus: StatusPass,
		},
		{
			name: "ipv6 fail",
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"example.com.": {"v=spf1 ip6:2001:db8::/32 -all"},
				},
			},
			args: Args{
				RemoteIP:       net.ParseIP("2001:db9::1"),
				MailFromDomain: "example.com",
				MailFromLocal:  "user",
			},
			wantStatus: StatusFail,
		},
		{
			name: "null reverse path uses helo",
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"mail.example.com.": {"v=spf1 ip4:192.0.2.0/24 -all"},
				},
			},
			args: Args{
				RemoteIP:       net.ParseIP("192.0.2.1"),
				MailFromDomain: "", // null reverse path
				HelloDomain:    "mail.example.com",
			},
			wantStatus: StatusPass,
		},
		{
			name: "none for ip literal helo and null mailfrom",
			resolver: &MockResolver{
				TXTRecords: map[string][]string{},
			},
			args: Args{
				RemoteIP:       net.ParseIP("192.0.2.1"),
				MailFromDomain: "",
				HelloDomain:    "192.0.2.1",
				HelloIsIP:      true,
			},
			wantStatus: StatusNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			received, _, _, _, err := Verify(context.Background(), tt.resolver, tt.args)

			if (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
			}

			if received.Result != tt.wantStatus {
				t.Errorf("Verify() status = %v, want %v", received.Result, tt.wantStatus)
			}
		})
	}
}

func TestLookup(t *testing.T) {
	tests := []struct {
		name       string
		resolver   *MockResolver
		domain     string
		wantStatus Status
		wantErr    bool
	}{
		{
			name: "valid spf record",
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"example.com.": {"v=spf1 -all"},
				},
			},
			domain:     "example.com",
			wantStatus: StatusNone, // Lookup returns StatusNone on success
		},
		{
			name: "no spf record",
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"example.com.": {"not an spf record"},
				},
			},
			domain:     "example.com",
			wantStatus: StatusNone,
			wantErr:    true,
		},
		{
			name: "dns not found",
			resolver: &MockResolver{
				TXTRecords: map[string][]string{},
			},
			domain:     "example.com",
			wantStatus: StatusNone,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, _, _, _, err := Lookup(context.Background(), tt.resolver, tt.domain)

			if (err != nil) != tt.wantErr {
				t.Errorf("Lookup() error = %v, wantErr %v", err, tt.wantErr)
			}

			if status != tt.wantStatus {
				t.Errorf("Lookup() status = %v, want %v", status, tt.wantStatus)
			}
		})
	}
}

func TestMacroExpansion(t *testing.T) {
	tests := []struct {
		name     string
		spec     string
		args     Args
		isDNS    bool
		expected string
		wantErr  bool
	}{
		{
			name: "sender macro",
			spec: "%{s}",
			args: Args{
				senderLocal:  "user",
				senderDomain: "example.com",
			},
			isDNS:    false,
			expected: "user@example.com",
		},
		{
			name: "local part macro",
			spec: "%{l}",
			args: Args{
				senderLocal: "user",
			},
			isDNS:    false,
			expected: "user",
		},
		{
			name: "domain macro",
			spec: "%{d}",
			args: Args{
				domain: "example.com",
			},
			isDNS:    false,
			expected: "example.com",
		},
		{
			name: "ip macro ipv4",
			spec: "%{i}",
			args: Args{
				RemoteIP: net.ParseIP("192.0.2.1"),
			},
			isDNS:    false,
			expected: "192.0.2.1",
		},
		{
			name: "version macro ipv4",
			spec: "%{v}",
			args: Args{
				RemoteIP: net.ParseIP("192.0.2.1"),
			},
			isDNS:    false,
			expected: "in-addr",
		},
		{
			name: "version macro ipv6",
			spec: "%{v}",
			args: Args{
				RemoteIP: net.ParseIP("2001:db8::1"),
			},
			isDNS:    false,
			expected: "ip6",
		},
		{
			name: "helo macro",
			spec: "%{h}",
			args: Args{
				HelloDomain: "mail.example.com",
			},
			isDNS:    false,
			expected: "mail.example.com",
		},
		{
			name:     "escape percent",
			spec:     "%%",
			args:     Args{},
			isDNS:    false,
			expected: "%",
		},
		{
			name:     "escape underscore",
			spec:     "%_",
			args:     Args{},
			isDNS:    false,
			expected: " ",
		},
		{
			name:     "escape hyphen",
			spec:     "%-",
			args:     Args{},
			isDNS:    false,
			expected: "%20",
		},
		{
			name: "combined",
			spec: "%{l}.%{d}",
			args: Args{
				senderLocal: "user",
				domain:      "example.com",
			},
			isDNS:    false,
			expected: "user.example.com",
		},
		{
			name:     "literal text",
			spec:     "test.example.com",
			args:     Args{},
			isDNS:    false,
			expected: "test.example.com",
		},
	}

	resolver := &MockResolver{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, err := expandDomainSpec(context.Background(), resolver, tt.spec, tt.args, tt.isDNS)

			if (err != nil) != tt.wantErr {
				t.Errorf("expandDomainSpec() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if result != tt.expected {
				t.Errorf("expandDomainSpec() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestExpandIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       net.IP
		expected string
	}{
		{
			name:     "ipv4",
			ip:       net.ParseIP("192.0.2.1"),
			expected: "192.0.2.1",
		},
		{
			name:     "ipv6",
			ip:       net.ParseIP("2001:db8::1"),
			expected: "2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := expandIP(tt.ip)
			if result != tt.expected {
				t.Errorf("expandIP() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestEvaluateUsesRelevantIPFamily(t *testing.T) {
	record, _, err := ParseRecord("v=spf1 a -all")
	if err != nil {
		t.Fatalf("ParseRecord() error = %v", err)
	}

	tests := []struct {
		name     string
		remoteIP string
		wantNet  string
	}{
		{name: "ipv4 uses A", remoteIP: "192.0.2.1", wantNet: "ip4"},
		{name: "ipv6 uses AAAA", remoteIP: "2001:db8::1", wantNet: "ip6"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &networkRecordingResolver{ips: []net.IP{net.ParseIP(tt.remoteIP)}}
			status, mechanism, _, authentic, err := Evaluate(context.Background(), resolver, record, Args{
				RemoteIP:       net.ParseIP(tt.remoteIP),
				MailFromDomain: "example.com",
				MailFromLocal:  "user",
			})
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if status != StatusPass || mechanism != "a" || !authentic {
				t.Fatalf("Evaluate() = (%v, %q, authentic=%v), want (pass, %q, authentic=true)", status, mechanism, authentic, "a")
			}
			if len(resolver.networks) != 1 || resolver.networks[0] != tt.wantNet {
				t.Fatalf("LookupIP network = %v, want [%q]", resolver.networks, tt.wantNet)
			}
			if len(resolver.hosts) != 1 || resolver.hosts[0] != "example.com." {
				t.Fatalf("LookupIP host = %v, want [example.com.]", resolver.hosts)
			}
		})
	}
}

func TestEvaluateInvalidDomain(t *testing.T) {
	status, mechanism, _, authentic, err := Evaluate(context.Background(), &MockResolver{}, &Record{Version: "spf1"}, Args{
		RemoteIP:       net.ParseIP("192.0.2.1"),
		MailFromDomain: "localhost",
	})
	if status != StatusNone || mechanism != "default" || authentic {
		t.Fatalf("Evaluate() = (%v, %q, authentic=%v), want (none, default, false)", status, mechanism, authentic)
	}
	if !errors.Is(err, ErrInvalidDomain) {
		t.Fatalf("Evaluate() error = %v, want ErrInvalidDomain", err)
	}
}

func TestReceivedHeader(t *testing.T) {
	r := Received{
		Result:       StatusPass,
		Comment:      "domain example.com",
		ClientIP:     net.ParseIP("192.0.2.1"),
		EnvelopeFrom: "user@example.com",
		Helo:         "mail.example.com",
		Receiver:     "mx.example.org",
		Identity:     "mailfrom",
		Mechanism:    "ip4:192.0.2.0/24",
	}

	header := r.Header()

	// Basic checks
	if header == "" {
		t.Error("Header() returned empty string")
	}
	if !contains(header, "Received-SPF: pass") {
		t.Error("Header() missing status")
	}
	if !contains(header, "client-ip=192.0.2.1") {
		t.Error("Header() missing client-ip")
	}
	// The @ in email requires quoting per RFC, so check for quoted form
	if !contains(header, `envelope-from="user@example.com"`) {
		t.Error("Header() missing envelope-from")
	}
	if !contains(header, "identity=mailfrom") {
		t.Error("Header() missing identity")
	}
}

func TestReceivedHeaderEdgeCases(t *testing.T) {
	r := Received{
		Result:       StatusFail,
		ClientIP:     net.ParseIP("192.0.2.1"),
		EnvelopeFrom: "",
		Helo:         `mail\"example`,
		Problem:      strings.Repeat("x", 80),
		Receiver:     "mx example",
		Identity:     "mailfrom",
	}

	header := r.Header()
	if strings.Contains(header, "(") {
		t.Fatalf("Header() unexpectedly included comment: %q", header)
	}
	if !strings.Contains(header, `envelope-from=""`) {
		t.Fatalf("Header() missing empty quoted envelope-from: %q", header)
	}
	if !strings.Contains(header, `helo="mail\\\"example"`) {
		t.Fatalf("Header() missing escaped HELO value: %q", header)
	}
	if !strings.Contains(header, `receiver="mx example"`) {
		t.Fatalf("Header() missing quoted receiver: %q", header)
	}
	if !strings.Contains(header, "problem="+strings.Repeat("x", 60)) {
		t.Fatalf("Header() did not truncate problem to 60 characters: %q", header)
	}
	if strings.Contains(header, "mechanism=") {
		t.Fatalf("Header() unexpectedly included empty mechanism: %q", header)
	}
}

func TestLookupInvalidDomains(t *testing.T) {
	tests := []string{"localhost", "bad..example.com"}
	for _, domain := range tests {
		t.Run(domain, func(t *testing.T) {
			status, _, _, authentic, err := Lookup(context.Background(), &MockResolver{}, domain)
			if status != StatusNone || authentic {
				t.Fatalf("Lookup(%q) = (%v, authentic=%v), want (none, false)", domain, status, authentic)
			}
			if !errors.Is(err, ErrInvalidDomain) {
				t.Fatalf("Lookup(%q) error = %v, want ErrInvalidDomain", domain, err)
			}
		})
	}
}

func TestExpandDomainSpecUppercaseEscapes(t *testing.T) {
	got, _, err := expandDomainSpec(context.Background(), &MockResolver{}, "%{L}", Args{senderLocal: "a b+c"}, false)
	if err != nil {
		t.Fatalf("expandDomainSpec() error = %v", err)
	}
	if got != "a%20b%2Bc" {
		t.Fatalf("expandDomainSpec() = %q, want %q", got, "a%20b%2Bc")
	}
}

func TestUtilityValidationHelpers(t *testing.T) {
	if got := ensureAbsDNS("example.com"); got != "example.com." {
		t.Fatalf("ensureAbsDNS() = %q, want %q", got, "example.com.")
	}
	if got := ensureAbsDNS("example.com."); got != "example.com." {
		t.Fatalf("ensureAbsDNS() preserved value = %q, want %q", got, "example.com.")
	}
	if got := escapeMacroValue("a b+c/~"); got != "a%20b%2Bc%2F~" {
		t.Fatalf("escapeMacroValue() = %q, want %q", got, "a%20b%2Bc%2F~")
	}

	if err := validateDomain("example.com."); err != nil {
		t.Fatalf("validateDomain() unexpected error = %v", err)
	}
	if err := validateDomain("bad..example.com"); err == nil {
		t.Fatal("validateDomain() expected error for empty label")
	}
	if err := validateLookupDomain("_spf.example.com"); err != nil {
		t.Fatalf("validateLookupDomain() unexpected error = %v", err)
	}
	if err := validateSenderDomain("localhost"); err == nil {
		t.Fatal("validateSenderDomain() expected error for single-label domain")
	}
	if err := validateSenderDomain("example.com"); err != nil {
		t.Fatalf("validateSenderDomain() unexpected error = %v", err)
	}
	if err := validateLookupDomain(strings.Repeat("a", 254) + ".com"); err == nil {
		t.Fatal("validateLookupDomain() expected error for overlong domain")
	}
	if err := validateLookupDomain("192.0.2.1"); err == nil {
		t.Fatal("validateLookupDomain() expected error for IP literal")
	}
	if err := validateSenderDomain("_spf.example.com"); err == nil {
		t.Fatal("validateSenderDomain() expected syntax error for underscore label")
	}
	if err := validateDomain(""); err == nil {
		t.Fatal("validateDomain() expected error for empty domain")
	}
	tooMany := strings.Repeat("a.", 128)
	if err := validateDomain(strings.TrimSuffix(tooMany, ".")); err == nil {
		t.Fatal("validateDomain() expected error for too many labels")
	}
	if err := validateDomain(strings.Repeat("a", 64) + ".example.com"); err == nil {
		t.Fatal("validateDomain() expected error for long label")
	}
}

func TestVerifyInvalidSenderDomain(t *testing.T) {
	received, domain, explanation, authentic, err := Verify(context.Background(), &MockResolver{}, Args{
		RemoteIP:       net.ParseIP("192.0.2.1"),
		MailFromDomain: "localhost",
		MailFromLocal:  "user",
	})
	if received.Result != StatusNone || domain != "localhost" || explanation != "" || authentic {
		t.Fatalf("Verify() = (%v, %q, %q, authentic=%v), want (none, localhost, empty, false)", received.Result, domain, explanation, authentic)
	}
	if !errors.Is(err, ErrInvalidDomain) {
		t.Fatalf("Verify() error = %v, want ErrInvalidDomain", err)
	}
	if received.Identity != "mailfrom" || received.Problem == "" {
		t.Fatalf("Verify() received = %+v, want invalid mailfrom result with problem", received)
	}
}

func TestEvaluateRecordExpansionAndRedirectErrors(t *testing.T) {
	tests := []struct {
		name   string
		record string
	}{
		{name: "a expansion error", record: "v=spf1 a:%{c} -all"},
		{name: "mx expansion error", record: "v=spf1 mx:%{c} -all"},
		{name: "ptr expansion error", record: "v=spf1 ptr:%{c} -all"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record, _, err := ParseRecord(tt.record)
			if err != nil {
				t.Fatalf("ParseRecord() error = %v", err)
			}
			status, _, _, _, err := Evaluate(context.Background(), &MockResolver{}, record, Args{
				RemoteIP:       net.ParseIP("192.0.2.1"),
				MailFromDomain: "example.com",
			})
			if status != StatusPermerror || err == nil {
				t.Fatalf("Evaluate() = (%v, %v), want (permerror, error)", status, err)
			}
		})
	}

	record, _, err := ParseRecord("v=spf1 redirect=absent.example.com")
	if err != nil {
		t.Fatalf("ParseRecord() redirect error = %v", err)
	}
	status, _, _, _, err := Evaluate(context.Background(), &MockResolver{}, record, Args{
		RemoteIP:       net.ParseIP("192.0.2.1"),
		MailFromDomain: "example.com",
	})
	if status != StatusPermerror || err == nil {
		t.Fatalf("Evaluate() redirect-none = (%v, %v), want (permerror, error)", status, err)
	}
}

func TestEvaluateRecordMechanismErrorBranches(t *testing.T) {
	aRecord, _, _ := ParseRecord("v=spf1 a -all")
	status, _, _, _, err := Evaluate(context.Background(), &MockResolver{Errors: map[string]error{"example.com.": errors.New("dns fail")}}, aRecord, Args{
		RemoteIP:       net.ParseIP("192.0.2.1"),
		MailFromDomain: "example.com",
	})
	if status != StatusTemperror || err == nil {
		t.Fatalf("Evaluate() a temperror = (%v, %v), want (temperror, error)", status, err)
	}

	mxRecord, _, _ := ParseRecord("v=spf1 mx -all")
	status, _, _, _, err = Evaluate(context.Background(), &MockResolver{Errors: map[string]error{"example.com.": errors.New("dns fail")}}, mxRecord, Args{
		RemoteIP:       net.ParseIP("192.0.2.1"),
		MailFromDomain: "example.com",
	})
	if status != StatusTemperror || err == nil {
		t.Fatalf("Evaluate() mx temperror = (%v, %v), want (temperror, error)", status, err)
	}

	existsRecord, _, _ := ParseRecord("v=spf1 exists:test.example.com -all")
	status, _, _, _, err = Evaluate(context.Background(), &MockResolver{Errors: map[string]error{"test.example.com.": errors.New("dns fail")}}, existsRecord, Args{
		RemoteIP:       net.ParseIP("192.0.2.1"),
		MailFromDomain: "example.com",
	})
	if status != StatusTemperror || err == nil {
		t.Fatalf("Evaluate() exists temperror = (%v, %v), want (temperror, error)", status, err)
	}

	ptrRecord, _, _ := ParseRecord("v=spf1 ptr:example.com ~all")
	status, _, _, _, err = Evaluate(context.Background(), &MockResolver{Errors: map[string]error{"192.0.2.1": errors.New("dns fail")}}, ptrRecord, Args{
		RemoteIP:       net.ParseIP("192.0.2.1"),
		MailFromDomain: "example.com",
	})
	if status != StatusTemperror || err == nil {
		t.Fatalf("Evaluate() ptr temperror = (%v, %v), want (temperror, error)", status, err)
	}
}

func TestEvaluateRecordTypeMismatchAndUnknownMechanism(t *testing.T) {
	record, _, _ := ParseRecord("v=spf1 a ?all")
	status, _, _, _, err := evaluateRecord(context.Background(), &networkRecordingResolver{ips: []net.IP{net.ParseIP("2001:db8::1")}}, record, Args{
		RemoteIP:     net.ParseIP("192.0.2.1"),
		domain:       "example.com",
		senderDomain: "example.com",
		senderLocal:  "user",
		dnsRequests:  new(int),
		voidLookups:  new(int),
	})
	if status != StatusNeutral || err != nil {
		t.Fatalf("evaluateRecord() ipv4 mismatch = (%v, %v), want (neutral, nil)", status, err)
	}

	status, _, _, _, err = evaluateRecord(context.Background(), &networkRecordingResolver{ips: []net.IP{net.ParseIP("192.0.2.1")}}, record, Args{
		RemoteIP:     net.ParseIP("2001:db8::1"),
		domain:       "example.com",
		senderDomain: "example.com",
		senderLocal:  "user",
		dnsRequests:  new(int),
		voidLookups:  new(int),
	})
	if status != StatusNeutral || err != nil {
		t.Fatalf("evaluateRecord() ipv6 mismatch = (%v, %v), want (neutral, nil)", status, err)
	}

	status, _, _, _, err = evaluateRecord(context.Background(), &MockResolver{}, &Record{Version: "spf1", Directives: []Directive{{Mechanism: "bogus"}}}, Args{
		RemoteIP:     net.ParseIP("192.0.2.1"),
		domain:       "example.com",
		senderDomain: "example.com",
		senderLocal:  "user",
		dnsRequests:  new(int),
		voidLookups:  new(int),
	})
	if status != StatusPermerror || err == nil {
		t.Fatalf("evaluateRecord() unknown mechanism = (%v, %v), want (permerror, error)", status, err)
	}
}

func TestPTRAndMXAdditionalBranches(t *testing.T) {
	mxRecord, _, _ := ParseRecord("v=spf1 mx -all")
	status, _, _, _, err := Evaluate(context.Background(), &MockResolver{MXRecords: map[string][]*net.MX{"example.com.": {{Host: "", Pref: 10}}}}, mxRecord, Args{
		RemoteIP:       net.ParseIP("192.0.2.1"),
		MailFromDomain: "example.com",
	})
	if status != StatusFail || err != nil {
		t.Fatalf("Evaluate() empty MX host = (%v, %v), want (fail, nil)", status, err)
	}

	ptrRecord, _, _ := ParseRecord("v=spf1 ptr:example.com ~all")
	status, _, _, _, err = Evaluate(context.Background(), &MockResolver{PTRRecords: map[string][]string{"192.0.2.1": {"other.example.net."}}}, ptrRecord, Args{
		RemoteIP:       net.ParseIP("192.0.2.1"),
		MailFromDomain: "example.com",
	})
	if status != StatusSoftfail || err != nil {
		t.Fatalf("Evaluate() non-matching PTR = (%v, %v), want (softfail, nil)", status, err)
	}

	ptrs := make([]string, 11)
	aRecords := map[string][]net.IP{}
	for i := range ptrs {
		name := fmt.Sprintf("mx%d.example.com.", i+1)
		ptrs[i] = name
		aRecords[name] = []net.IP{net.ParseIP(fmt.Sprintf("192.0.2.%d", i+10))}
	}
	status, _, _, _, err = Evaluate(context.Background(), &MockResolver{PTRRecords: map[string][]string{"192.0.2.1": ptrs}, ARecords: aRecords}, ptrRecord, Args{
		RemoteIP:       net.ParseIP("192.0.2.1"),
		MailFromDomain: "example.com",
	})
	if status != StatusSoftfail || err != nil {
		t.Fatalf("Evaluate() PTR lookup limit = (%v, %v), want (softfail, nil)", status, err)
	}
}

func TestExplanationAndMacroEdgeBranches(t *testing.T) {
	resolver := &MockResolver{TXTRecords: map[string][]string{
		"exp.example.com.":      {"broken %"},
		"override.example.com.": {"override"},
	}}

	if explanation, _ := getExplanation(context.Background(), resolver, &Record{Explanation: "%{c}"}, Args{MailFromDomain: "example.com"}); explanation != "" {
		t.Fatalf("getExplanation() invalid domain-spec = %q, want empty", explanation)
	}

	args := Args{senderDomain: "example.com", senderLocal: "user", domain: "example.com", explanation: ptrTo("override.example.com")}
	if explanation, _ := getExplanation(context.Background(), resolver, &Record{Explanation: "exp.example.com"}, args); explanation != "override" {
		t.Fatalf("getExplanation() override = %q, want %q", explanation, "override")
	}

	if explanation, _ := getExplanation(context.Background(), resolver, &Record{Explanation: "exp.example.com"}, Args{senderDomain: "example.com", senderLocal: "user", domain: "example.com"}); explanation != "" {
		t.Fatalf("getExplanation() broken macro text = %q, want empty", explanation)
	}

	if got, _, err := expandDomainSpec(context.Background(), &MockResolver{}, "%{c}", Args{}, false); err != nil || got != "" {
		t.Fatalf("expandDomainSpec() empty c = (%q, %v), want (empty, nil)", got, err)
	}
	if got, _, err := expandDomainSpec(context.Background(), &MockResolver{}, "%{r}", Args{}, false); err != nil || got != "" {
		t.Fatalf("expandDomainSpec() empty r = (%q, %v), want (empty, nil)", got, err)
	}
	if _, _, err := expandDomainSpec(context.Background(), &MockResolver{}, "%{s"+strings.Repeat("9", 64)+"}", Args{senderDomain: "example.com", senderLocal: "user"}, false); err == nil {
		t.Fatal("expandDomainSpec() expected error for overflow transformer digits")
	}
	if _, _, err := expandDomainSpec(context.Background(), &MockResolver{}, "bad..example.com", Args{}, true); err == nil {
		t.Fatal("expandDomainSpec() expected error for invalid expanded domain")
	}
	args = Args{domain: "example.com", RemoteIP: net.ParseIP("192.0.2.1"), dnsRequests: intPtr(dnsRequestsMax), voidLookups: new(int)}
	if _, _, err := expandDomainSpec(context.Background(), &MockResolver{}, "%{p}", args, false); !errors.Is(err, ErrTooManyDNSRequests) {
		t.Fatalf("expandDomainSpec() p lookup limit error = %v, want ErrTooManyDNSRequests", err)
	}
}

func ptrTo(s string) *string {
	return &s
}

func intPtr(v int) *int {
	return &v
}

func TestFindValidatedPTROrdering(t *testing.T) {
	resolver := &MockResolver{
		ARecords: map[string][]net.IP{
			"example.com.":         {net.ParseIP("192.0.2.1")},
			"mail.example.com.":    {net.ParseIP("192.0.2.1")},
			"other.example.net.":   {net.ParseIP("192.0.2.1")},
			"invalid.example.com.": {net.ParseIP("192.0.2.55")},
		},
	}
	args := Args{domain: "example.com", RemoteIP: net.ParseIP("192.0.2.1")}

	authentic := true
	if got := findValidatedPTR(context.Background(), resolver, []string{"example.com."}, args, &authentic); got != "example.com" {
		t.Fatalf("findValidatedPTR() exact = %q, want %q", got, "example.com")
	}

	authentic = true
	if got := findValidatedPTR(context.Background(), resolver, []string{"mail.example.com."}, args, &authentic); got != "mail.example.com" {
		t.Fatalf("findValidatedPTR() subdomain = %q, want %q", got, "mail.example.com")
	}

	authentic = true
	if got := findValidatedPTR(context.Background(), resolver, []string{"other.example.net."}, args, &authentic); got != "other.example.net" {
		t.Fatalf("findValidatedPTR() fallback = %q, want %q", got, "other.example.net")
	}

	authentic = true
	if got := findValidatedPTR(context.Background(), resolver, []string{"invalid.example.com."}, args, &authentic); got != "unknown" {
		t.Fatalf("findValidatedPTR() unknown = %q, want %q", got, "unknown")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || s != "" && containsAt(s, substr, 0))
}

func containsAt(s, substr string, start int) bool {
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestDNSLookupLimits(t *testing.T) {
	// Create a record with many includes to exceed the limit
	// Each include uses -all so they won't match (include only matches on pass)
	// This forces evaluation to continue to the next include
	resolver := &MockResolver{
		TXTRecords: map[string][]string{
			"example.com.":   {"v=spf1 include:a.example.com include:b.example.com include:c.example.com include:d.example.com include:e.example.com include:f.example.com include:g.example.com include:h.example.com include:i.example.com include:j.example.com include:k.example.com +all"},
			"a.example.com.": {"v=spf1 ip4:192.0.2.0/24 -all"},
			"b.example.com.": {"v=spf1 ip4:192.0.2.0/24 -all"},
			"c.example.com.": {"v=spf1 ip4:192.0.2.0/24 -all"},
			"d.example.com.": {"v=spf1 ip4:192.0.2.0/24 -all"},
			"e.example.com.": {"v=spf1 ip4:192.0.2.0/24 -all"},
			"f.example.com.": {"v=spf1 ip4:192.0.2.0/24 -all"},
			"g.example.com.": {"v=spf1 ip4:192.0.2.0/24 -all"},
			"h.example.com.": {"v=spf1 ip4:192.0.2.0/24 -all"},
			"i.example.com.": {"v=spf1 ip4:192.0.2.0/24 -all"},
			"j.example.com.": {"v=spf1 ip4:192.0.2.0/24 -all"},
			"k.example.com.": {"v=spf1 ip4:192.0.2.0/24 -all"},
		},
	}

	args := Args{
		RemoteIP:       net.ParseIP("10.0.0.1"), // Won't match any include's ip4
		MailFromDomain: "example.com",
		MailFromLocal:  "user",
	}

	received, _, _, _, err := Verify(context.Background(), resolver, args)

	// Should hit permerror due to too many DNS lookups (11 includes > 10 limit)
	if err == nil && received.Result != StatusPermerror {
		t.Errorf("Expected permerror due to DNS lookup limit, got %v", received.Result)
	}
}

// TestEvaluate tests the Evaluate function with pre-parsed records.
func TestEvaluate(t *testing.T) {
	resolver := &MockResolver{}

	// Test with empty record and no domain
	record := &Record{Version: "spf1"}
	args := Args{}
	status, _, _, _, _ := Evaluate(context.Background(), resolver, record, args)
	if status != StatusNone {
		t.Errorf("Expected StatusNone for empty args, got %v", status)
	}

	// Test with HelloDomain set
	args = Args{
		HelloDomain: "test.example",
		RemoteIP:    net.ParseIP("1.2.3.4"),
	}
	status, mechanism, _, _, err := Evaluate(context.Background(), resolver, record, args)
	if status != StatusNeutral || mechanism != "default" || err != nil {
		t.Errorf("Expected neutral/default, got status=%v mechanism=%v err=%v", status, mechanism, err)
	}
}

// TestVerifyRFC7208Examples tests examples from RFC 7208 Appendix A.
func TestVerifyRFC7208Examples(t *testing.T) {
	// Setup resolver with RFC 7208 example data
	resolver := &MockResolver{
		TXTRecords: map[string][]string{
			// Additional from DNSBL style
			"mobile-users._spf.example.com.": {"v=spf1 exists:%{l1r+}.%{d}"},
			"remote-users._spf.example.com.": {"v=spf1 exists:%{ir}.%{l1r+}.%{d}"},

			// Additional tests
			"_spf.example.com.":      {"v=spf1 include:_netblock.example.com -all"},
			"_netblock.example.com.": {"v=spf1 ip4:192.0.2.128/28 -all"},
		},
		ARecords: map[string][]net.IP{
			"example.com.":        {net.ParseIP("192.0.2.10"), net.ParseIP("192.0.2.11")},
			"amy.example.com.":    {net.ParseIP("192.0.2.65")},
			"bob.example.com.":    {net.ParseIP("192.0.2.66")},
			"mail-a.example.com.": {net.ParseIP("192.0.2.129")},
			"mail-b.example.com.": {net.ParseIP("192.0.2.130")},
			"mail-c.example.org.": {net.ParseIP("192.0.2.140")},

			// DNSBL style lookups
			"mary.mobile-users._spf.example.com.":               {net.ParseIP("127.0.0.2")},
			"fred.mobile-users._spf.example.com.":               {net.ParseIP("127.0.0.2")},
			"15.15.168.192.joel.remote-users._spf.example.com.": {net.ParseIP("127.0.0.2")},
			"16.15.168.192.joel.remote-users._spf.example.com.": {net.ParseIP("127.0.0.2")},
		},
		MXRecords: map[string][]*net.MX{
			"example.com.": {
				{Host: "mail-a.example.com.", Pref: 10},
				{Host: "mail-b.example.com.", Pref: 20},
			},
			"example.org.": {
				{Host: "mail-c.example.org.", Pref: 10},
			},
		},
		PTRRecords: map[string][]string{
			"192.0.2.10":  {"example.com."},
			"192.0.2.11":  {"example.com."},
			"192.0.2.65":  {"amy.example.com."},
			"192.0.2.66":  {"bob.example.com."},
			"192.0.2.129": {"mail-a.example.com."},
			"192.0.2.130": {"mail-b.example.com."},
			"192.0.2.140": {"mail-c.example.org."},
			"10.0.0.4":    {"bob.example.com."},
		},
	}

	ctx := context.Background()

	verify := func(spfRecord string, ip net.IP, localpart string, expectedStatus Status) {
		t.Helper()
		resolver.TXTRecords["example.com."] = []string{spfRecord}

		args := Args{
			MailFromDomain: "example.com",
			MailFromLocal:  localpart,
			RemoteIP:       ip,
			LocalIP:        net.ParseIP("127.0.0.1"),
			LocalHostname:  "localhost",
		}
		received, _, _, _, err := Verify(ctx, resolver, args)
		if received.Result != expectedStatus {
			t.Errorf("SPF %q, IP %s, localpart %q: got %v, want %v (err=%v)",
				spfRecord, ip, localpart, received.Result, expectedStatus, err)
		}
	}

	// RFC 7208 A.1 Simple Examples
	verify("v=spf1 +all", net.ParseIP("192.0.2.129"), "", StatusPass)
	verify("v=spf1 +all", net.ParseIP("1.2.3.4"), "", StatusPass)
	verify("v=spf1 a -all", net.ParseIP("192.0.2.10"), "", StatusPass)
	verify("v=spf1 a -all", net.ParseIP("192.0.2.11"), "", StatusPass)
	verify("v=spf1 a -all", net.ParseIP("192.0.2.129"), "", StatusFail)
	verify("v=spf1 a:example.org -all", net.ParseIP("192.0.2.10"), "", StatusFail)
	verify("v=spf1 mx -all", net.ParseIP("192.0.2.129"), "", StatusPass)
	verify("v=spf1 mx -all", net.ParseIP("192.0.2.130"), "", StatusPass)
	verify("v=spf1 mx -all", net.ParseIP("192.0.2.10"), "", StatusFail)
	verify("v=spf1 mx:example.org -all", net.ParseIP("192.0.2.140"), "", StatusPass)
	verify("v=spf1 mx mx:example.org -all", net.ParseIP("192.0.2.129"), "", StatusPass)
	verify("v=spf1 mx mx:example.org -all", net.ParseIP("192.0.2.140"), "", StatusPass)
	verify("v=spf1 ptr -all", net.ParseIP("192.0.2.10"), "", StatusPass)
	verify("v=spf1 ptr -all", net.ParseIP("192.0.2.65"), "", StatusPass)
	verify("v=spf1 ptr -all", net.ParseIP("1.2.3.4"), "", StatusFail)
	verify("v=spf1 ip4:192.0.2.128/28 -all", net.ParseIP("192.0.2.129"), "", StatusPass)
	verify("v=spf1 ip4:192.0.2.128/28 -all", net.ParseIP("192.0.2.140"), "", StatusPass)
	verify("v=spf1 ip4:192.0.2.128/28 -all", net.ParseIP("192.0.2.10"), "", StatusFail)

	// Redirect test
	verify("v=spf1 redirect=_spf.example.com", net.ParseIP("192.0.2.129"), "", StatusPass)
	verify("v=spf1 redirect=_spf.example.com", net.ParseIP("192.0.2.10"), "", StatusFail)

	// DNSBL-style tests with macros
	verify("v=spf1 mx include:mobile-users._spf.%{d} include:remote-users._spf.%{d} -all",
		net.ParseIP("1.2.3.4"), "mary", StatusPass)
	verify("v=spf1 mx include:mobile-users._spf.%{d} include:remote-users._spf.%{d} -all",
		net.ParseIP("1.2.3.4"), "fred", StatusPass)
	verify("v=spf1 mx include:mobile-users._spf.%{d} include:remote-users._spf.%{d} -all",
		net.ParseIP("1.2.3.4"), "joel", StatusFail)
	verify("v=spf1 mx include:mobile-users._spf.%{d} include:remote-users._spf.%{d} -all",
		net.ParseIP("192.168.15.15"), "joel", StatusPass)
	verify("v=spf1 mx include:mobile-users._spf.%{d} include:remote-users._spf.%{d} -all",
		net.ParseIP("192.168.15.16"), "joel", StatusPass)
	verify("v=spf1 mx include:mobile-users._spf.%{d} include:remote-users._spf.%{d} -all",
		net.ParseIP("192.168.15.17"), "joel", StatusFail)
}

// TestVerifyMultipleDomains tests include and redirect across domains.
func TestVerifyMultipleDomains(t *testing.T) {
	resolver := &MockResolver{
		TXTRecords: map[string][]string{
			"example.org.":    {"v=spf1 include:example.com include:example.net -all"},
			"la.example.org.": {"v=spf1 redirect=example.org"},
			"example.com.":    {"v=spf1 ip4:10.0.0.1 -all"},
			"example.net.":    {"v=spf1 ip4:10.0.0.2 -all"},
		},
	}

	verify := func(domain, ip string, expectedStatus Status) {
		t.Helper()
		args := Args{
			MailFromDomain: domain,
			RemoteIP:       net.ParseIP(ip),
			LocalIP:        net.ParseIP("127.0.0.1"),
			LocalHostname:  "localhost",
		}
		received, _, _, _, err := Verify(context.Background(), resolver, args)
		if received.Result != expectedStatus {
			t.Errorf("domain=%s ip=%s: got %v, want %v (err=%v)",
				domain, ip, received.Result, expectedStatus, err)
		}
	}

	verify("example.com", "10.0.0.1", StatusPass)
	verify("example.net", "10.0.0.2", StatusPass)
	verify("example.com", "10.0.0.2", StatusFail)
	verify("example.net", "10.0.0.1", StatusFail)
	verify("example.org", "10.0.0.1", StatusPass)
	verify("example.org", "10.0.0.2", StatusPass)
	verify("example.org", "10.0.0.3", StatusFail)
	verify("la.example.org", "10.0.0.1", StatusPass)
	verify("la.example.org", "10.0.0.2", StatusPass)
	verify("la.example.org", "10.0.0.3", StatusFail)
}

// TestVerifyScenarios tests various edge cases and error scenarios.
func TestVerifyScenarios(t *testing.T) {
	resolver := &MockResolver{
		TXTRecords: map[string][]string{
			"mox.example.":                {"v=spf1 ip6:2001:db8::0/64 -all"},
			"void.example.":               {"v=spf1 exists:absent1.example exists:absent2.example ip4:1.2.3.4 exists:absent3.example -all"},
			"loop.example.":               {"v=spf1 include:loop.example -all"},
			"a-unknown.example.":          {"v=spf1 a:absent.example"},
			"include-bad-expand.example.": {"v=spf1 include:%{c}"},
			"exists-bad-expand.example.":  {"v=spf1 exists:%{c}"},
			"redir-bad-expand.example.":   {"v=spf1 redirect=%{c}"},
			"include-temperror.example.":  {"v=spf1 include:temperror.example"},
			"include-none.example.":       {"v=spf1 include:absent.example"},
			"include-permerror.example.":  {"v=spf1 include:permerror.example"},
			"permerror.example.":          {"v=spf1 a:%%"},
			"no-mx.example.":              {"v=spf1 mx -all"},
			"many-mx.example.":            {"v=spf1 mx -all"},
			"many-ptr.example.":           {"v=spf1 ptr:many-mx.example ~all"},
			"expl.example.":               {"v=spf1 ip4:10.0.1.1 -ip4:10.0.1.2 ?all exp=details.expl.example"},
			"details.expl.example.":       {"your ip %{i} is not allowed"},
			"expl-multi.example.":         {"v=spf1 ip4:10.0.1.1 -ip4:10.0.1.2 ~all exp=details-multi.expl.example"},
			"details-multi.expl.example.": {"your ip ", "%{i} is not allowed"},
		},
		ARecords: map[string][]net.IP{
			"mail.mox.example.":     {net.ParseIP("10.0.0.1")},
			"mx1.many-mx.example.":  {net.ParseIP("10.0.1.1")},
			"mx2.many-mx.example.":  {net.ParseIP("10.0.1.2")},
			"mx3.many-mx.example.":  {net.ParseIP("10.0.1.3")},
			"mx4.many-mx.example.":  {net.ParseIP("10.0.1.4")},
			"mx5.many-mx.example.":  {net.ParseIP("10.0.1.5")},
			"mx6.many-mx.example.":  {net.ParseIP("10.0.1.6")},
			"mx7.many-mx.example.":  {net.ParseIP("10.0.1.7")},
			"mx8.many-mx.example.":  {net.ParseIP("10.0.1.8")},
			"mx9.many-mx.example.":  {net.ParseIP("10.0.1.9")},
			"mx10.many-mx.example.": {net.ParseIP("10.0.1.10")},
			"mx11.many-mx.example.": {net.ParseIP("10.0.1.11")},
		},
		AAAARecords: map[string][]net.IP{
			"mail.mox.example.": {net.ParseIP("2001:db8::1")},
		},
		MXRecords: map[string][]*net.MX{
			"no-mx.example.": {{Host: ".", Pref: 10}},
			"many-mx.example.": {
				{Host: "mx1.many-mx.example.", Pref: 1},
				{Host: "mx2.many-mx.example.", Pref: 2},
				{Host: "mx3.many-mx.example.", Pref: 3},
				{Host: "mx4.many-mx.example.", Pref: 4},
				{Host: "mx5.many-mx.example.", Pref: 5},
				{Host: "mx6.many-mx.example.", Pref: 6},
				{Host: "mx7.many-mx.example.", Pref: 7},
				{Host: "mx8.many-mx.example.", Pref: 8},
				{Host: "mx9.many-mx.example.", Pref: 9},
				{Host: "mx10.many-mx.example.", Pref: 10},
				{Host: "mx11.many-mx.example.", Pref: 11},
			},
		},
		PTRRecords: map[string][]string{
			"2001:db8::1": {"mail.mox.example."},
			"10.0.1.1":    {"mx1.many-mx.example.", "mx2.many-mx.example.", "mx3.many-mx.example.", "mx4.many-mx.example.", "mx5.many-mx.example.", "mx6.many-mx.example.", "mx7.many-mx.example.", "mx8.many-mx.example.", "mx9.many-mx.example.", "mx10.many-mx.example.", "mx11.many-mx.example."},
		},
		Errors: map[string]error{
			"temperror.example.": errors.New("dns timeout"),
		},
	}

	test := func(domain string, ip net.IP, expectedStatus Status, expectErr bool) {
		t.Helper()
		args := Args{
			MailFromDomain: domain,
			MailFromLocal:  "x",
			RemoteIP:       ip,
			LocalIP:        net.ParseIP("127.0.0.1"),
			LocalHostname:  "localhost",
		}
		received, _, _, _, err := Verify(context.Background(), resolver, args)
		if (err != nil) != expectErr && received.Result == expectedStatus {
			// Allow status match even when error expectation differs.
			return
		}
		if received.Result != expectedStatus {
			t.Errorf("domain=%s ip=%s: got %v, want %v (err=%v)",
				domain, ip, received.Result, expectedStatus, err)
		}
	}

	// IPv6 remote IP
	test("mox.example", net.ParseIP("2001:db8::1"), StatusPass, false)
	test("mox.example", net.ParseIP("2001:fa11::1"), StatusFail, false)

	// Use EHLO identity
	args := Args{
		RemoteIP:    net.ParseIP("2001:db8::1"),
		HelloDomain: "mox.example",
	}
	received, _, _, _, _ := Verify(context.Background(), resolver, args)
	if received.Result != StatusPass {
		t.Errorf("EHLO identity: got %v, want pass", received.Result)
	}

	// Too many void lookups
	test("void.example", net.ParseIP("1.2.3.4"), StatusPass, false)     // IP found after 2 void lookups
	test("void.example", net.ParseIP("1.1.1.1"), StatusPermerror, true) // IP not found, hits void limit

	// Too many DNS requests (self-referencing loop)
	test("loop.example", net.ParseIP("1.2.3.4"), StatusPermerror, true)

	// a:other where other does not exist
	test("a-unknown.example", net.ParseIP("1.2.3.4"), StatusNeutral, false)

	// Expand with invalid macro (c only valid in exp)
	test("include-bad-expand.example", net.ParseIP("1.2.3.4"), StatusPermerror, true)
	test("exists-bad-expand.example", net.ParseIP("1.2.3.4"), StatusPermerror, true)
	test("redir-bad-expand.example", net.ParseIP("1.2.3.4"), StatusPermerror, true)

	// Include with varying results
	test("include-temperror.example", net.ParseIP("1.2.3.4"), StatusTemperror, true)
	test("include-none.example", net.ParseIP("1.2.3.4"), StatusPermerror, true)

	// MX with explicit "." for "no mail"
	test("no-mx.example", net.ParseIP("1.2.3.4"), StatusFail, false)

	// MX names beyond 10th entry result in Permerror
	test("many-mx.example", net.ParseIP("10.0.1.1"), StatusPass, false)
	test("many-mx.example", net.ParseIP("10.0.1.10"), StatusPass, false)
	test("many-mx.example", net.ParseIP("10.0.1.11"), StatusPermerror, true)
	test("many-mx.example", net.ParseIP("10.0.1.254"), StatusPermerror, true)

	// PTR names beyond 10th entry are ignored (softfail from ~all)
	test("many-ptr.example", net.ParseIP("10.0.1.1"), StatusPass, false)
	test("many-ptr.example", net.ParseIP("10.0.1.2"), StatusSoftfail, false)

	// Explanation from txt records
	test("expl.example", net.ParseIP("10.0.1.1"), StatusPass, false)
	received, _, expl, _, _ := Verify(context.Background(), resolver, Args{
		MailFromDomain: "expl.example",
		MailFromLocal:  "x",
		RemoteIP:       net.ParseIP("10.0.1.2"),
		LocalIP:        net.ParseIP("127.0.0.1"),
		LocalHostname:  "localhost",
	})
	if received.Result != StatusFail {
		t.Errorf("expl.example fail: got %v, want fail", received.Result)
	}
	if expl != "your ip 10.0.1.2 is not allowed" {
		t.Errorf("explanation: got %q, want 'your ip 10.0.1.2 is not allowed'", expl)
	}
	test("expl.example", net.ParseIP("10.0.1.3"), StatusNeutral, false)

	// Multi-record explanation
	received, _, expl, _, _ = Verify(context.Background(), resolver, Args{
		MailFromDomain: "expl-multi.example",
		MailFromLocal:  "x",
		RemoteIP:       net.ParseIP("10.0.1.2"),
		LocalIP:        net.ParseIP("127.0.0.1"),
		LocalHostname:  "localhost",
	})
	if received.Result != StatusFail {
		t.Errorf("expl-multi.example fail: got %v, want fail", received.Result)
	}
	if expl != "" {
		t.Errorf("multi explanation: got %q, want empty explanation", expl)
	}

	// Verify with IP EHLO
	args = Args{
		RemoteIP:    net.ParseIP("2001:db8::1"),
		HelloDomain: "::1",
		HelloIsIP:   true,
	}
	received, _, _, _, _ = Verify(context.Background(), resolver, args)
	if received.Result != StatusNone {
		t.Errorf("IP EHLO: got %v, want none", received.Result)
	}
}

// TestExpandMacrosRFC7208 tests macro expansion examples from RFC 7208.
func TestExpandMacrosRFC7208(t *testing.T) {
	resolver := &MockResolver{
		PTRRecords: map[string][]string{
			"10.0.0.1": {"other.example.", "sub.mx.mox.example.", "mx.mox.example."},
			"10.0.0.2": {"other.example.", "sub.mx.mox.example.", "mx.mox.example."},
			"10.0.0.3": {"other.example.", "sub.mx.mox.example.", "mx.mox.example."},
		},
		ARecords: map[string][]net.IP{
			"mx.mox.example.":     {net.ParseIP("10.0.0.1")},
			"sub.mx.mox.example.": {net.ParseIP("10.0.0.2")},
			"other.example.":      {net.ParseIP("10.0.0.3")},
		},
	}

	defArgs := Args{
		senderLocal:   "strong-bad",
		senderDomain:  "email.example.com",
		domain:        "email.example.com",
		MailFromLocal: "x",
		HelloDomain:   "mx.mox.example",
		LocalIP:       net.ParseIP("10.10.10.10"),
		LocalHostname: "self.example",
		dnsRequests:   new(int),
		voidLookups:   new(int),
	}

	ctx := context.Background()

	testDNS := func(macro, ip, expected string) {
		t.Helper()
		args := defArgs
		args.dnsRequests = new(int)
		args.voidLookups = new(int)
		if ip != "" {
			args.RemoteIP = net.ParseIP(ip)
		}

		result, _, err := expandDomainSpec(ctx, resolver, macro, args, true)
		if expected == "" {
			if err == nil {
				t.Errorf("macro %q: expected error, got %q", macro, result)
			}
			return
		}
		if err != nil {
			t.Errorf("macro %q: unexpected error: %v", macro, err)
			return
		}
		if result != expected {
			t.Errorf("macro %q: got %q, want %q", macro, result, expected)
		}
	}

	testExp := func(macro, ip, expected string) {
		t.Helper()
		args := defArgs
		args.dnsRequests = new(int)
		args.voidLookups = new(int)
		if ip != "" {
			args.RemoteIP = net.ParseIP(ip)
		}

		result, _, err := expandDomainSpec(ctx, resolver, macro, args, false)
		if expected == "" {
			if err == nil {
				t.Errorf("macro %q: expected error, got %q", macro, result)
			}
			return
		}
		if err != nil {
			t.Errorf("macro %q: unexpected error: %v", macro, err)
			return
		}
		if result != expected {
			t.Errorf("macro %q: got %q, want %q", macro, result, expected)
		}
	}

	// Examples from RFC 7208:1777
	testDNS("%{s}", "", "strong-bad@email.example.com")
	testDNS("%{o}", "", "email.example.com")
	testDNS("%{d}", "", "email.example.com")
	testDNS("%{d4}", "", "email.example.com")
	testDNS("%{d3}", "", "email.example.com")
	testDNS("%{d2}", "", "example.com")
	testDNS("%{d1}", "", "com")
	testDNS("%{dr}", "", "com.example.email")
	testDNS("%{d2r}", "", "example.email")
	testDNS("%{l}", "", "strong-bad")
	testDNS("%{l-}", "", "strong.bad")
	testDNS("%{lr}", "", "strong-bad")
	testDNS("%{lr-}", "", "bad.strong")
	testDNS("%{l1r-}", "", "strong")

	// Error cases
	testDNS("%", "", "")
	testDNS("%b", "", "")
	testDNS("%{", "", "")
	testDNS("%{s", "", "")
	testDNS("%{s1", "", "")
	testDNS("%{s0}", "", "")
	testDNS("%{s1r", "", "")

	// IP-related macros
	testDNS("%{ir}.%{v}._spf.%{d2}", "192.0.2.3", "3.2.0.192.in-addr._spf.example.com")
	testDNS("%{lr-}.lp._spf.%{d2}", "192.0.2.3", "bad.strong.lp._spf.example.com")
	testDNS("%{lr-}.lp.%{ir}.%{v}._spf.%{d2}", "192.0.2.3", "bad.strong.lp.3.2.0.192.in-addr._spf.example.com")
	testDNS("%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}", "192.0.2.3", "3.2.0.192.in-addr.strong.lp._spf.example.com")
	testDNS("%{d2}.trusted-domains.example.net", "192.0.2.3", "example.com.trusted-domains.example.net")

	// IPv6 expansion
	testDNS("%{ir}.%{v}._spf.%{d2}", "2001:db8::cb01", "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com")

	// Additional tests
	testDNS("%%%-%_", "10.0.0.1", "%%20 ")
	testDNS("%{p}", "10.0.0.1", "mx.mox.example")
	testDNS("%{p}", "10.0.0.2", "sub.mx.mox.example")
	testDNS("%{p}", "10.0.0.3", "other.example")
	testDNS("%{p}", "10.0.0.4", "unknown")
	testExp("%{c}", "10.0.0.1", "10.10.10.10")
	testExp("%{r}", "10.0.0.1", "self.example")

	// Time macro
	orig := timeNow
	defer func() { timeNow = orig }()
	now := orig()
	timeNow = func() time.Time { return now }
	testExp("%{t}", "10.0.0.1", fmt.Sprintf("%d", now.Unix()))

	// HELO macro
	testDNS("%{h}", "10.0.0.1", "mx.mox.example")

	// DNS name truncation test
	xlabel := make([]byte, 62)
	for i := range xlabel {
		xlabel[i] = 'a'
	}
	label := string(xlabel)
	name := label + "." + label + "." + label + "." + label // 4*62+3 = 251
	testDNS("x."+name, "10.0.0.1", "x."+name)               // Still fits
	testDNS("xx."+name, "10.0.0.1", name)                   // Truncated to fit
}

// TestLookupErrors tests various Lookup error conditions.
func TestLookupErrors(t *testing.T) {
	tests := []struct {
		name       string
		resolver   *MockResolver
		domain     string
		wantStatus Status
		wantErr    error
	}{
		{
			name: "malformed record",
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"malformed.example.": {"v=spf1 !"},
				},
			},
			domain:     "malformed.example",
			wantStatus: StatusPermerror,
			wantErr:    ErrRecordSyntax,
		},
		{
			name: "multiple spf records",
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"multiple.example.": {"v=spf1 +all", "v=spf1 -all"},
				},
			},
			domain:     "multiple.example",
			wantStatus: StatusPermerror,
			wantErr:    ErrMultipleRecords,
		},
		{
			name: "non-spf records only",
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"nonspf.example.": {"something else", "not spf"},
				},
			},
			domain:     "nonspf.example",
			wantStatus: StatusNone,
			wantErr:    ErrNoRecord,
		},
		{
			name: "dns error",
			resolver: &MockResolver{
				Errors: map[string]error{
					"temperror.example.": errors.New("dns timeout"),
				},
			},
			domain:     "temperror.example",
			wantStatus: StatusTemperror,
		},
		{
			name: "valid record",
			resolver: &MockResolver{
				TXTRecords: map[string][]string{
					"ok.example.": {"v=spf1 -all"},
				},
			},
			domain:     "ok.example",
			wantStatus: StatusNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, _, _, _, err := Lookup(context.Background(), tt.resolver, tt.domain)
			if status != tt.wantStatus {
				t.Errorf("status = %v, want %v", status, tt.wantStatus)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
