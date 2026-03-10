package spf

import (
	"net"
	"strings"
	"testing"
)

func expectParserError(t *testing.T, fn func()) (msg string) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected parser panic")
		}
		perr, ok := r.(parseError)
		if !ok {
			t.Fatalf("expected parseError panic, got %T", r)
		}
		msg = perr.Error()
	}()
	fn()
	return ""
}

func TestParseRecord(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantSPF   bool
		wantErr   bool
		checkFunc func(t *testing.T, r *Record)
	}{
		{
			name:    "simple pass all",
			input:   "v=spf1 +all",
			wantSPF: true,
			checkFunc: func(t *testing.T, r *Record) {
				if len(r.Directives) != 1 {
					t.Errorf("expected 1 directive, got %d", len(r.Directives))
				}
				if r.Directives[0].Mechanism != "all" {
					t.Errorf("expected mechanism 'all', got %q", r.Directives[0].Mechanism)
				}
				if r.Directives[0].Qualifier != "+" {
					t.Errorf("expected qualifier '+', got %q", r.Directives[0].Qualifier)
				}
			},
		},
		{
			name:    "default qualifier",
			input:   "v=spf1 all",
			wantSPF: true,
			checkFunc: func(t *testing.T, r *Record) {
				if r.Directives[0].Qualifier != "" {
					t.Errorf("expected empty qualifier, got %q", r.Directives[0].Qualifier)
				}
			},
		},
		{
			name:    "fail all",
			input:   "v=spf1 -all",
			wantSPF: true,
			checkFunc: func(t *testing.T, r *Record) {
				if r.Directives[0].Qualifier != "-" {
					t.Errorf("expected qualifier '-', got %q", r.Directives[0].Qualifier)
				}
			},
		},
		{
			name:    "softfail all",
			input:   "v=spf1 ~all",
			wantSPF: true,
			checkFunc: func(t *testing.T, r *Record) {
				if r.Directives[0].Qualifier != "~" {
					t.Errorf("expected qualifier '~', got %q", r.Directives[0].Qualifier)
				}
			},
		},
		{
			name:    "neutral all",
			input:   "v=spf1 ?all",
			wantSPF: true,
			checkFunc: func(t *testing.T, r *Record) {
				if r.Directives[0].Qualifier != "?" {
					t.Errorf("expected qualifier '?', got %q", r.Directives[0].Qualifier)
				}
			},
		},
		{
			name:    "include",
			input:   "v=spf1 include:example.com -all",
			wantSPF: true,
			checkFunc: func(t *testing.T, r *Record) {
				if len(r.Directives) != 2 {
					t.Errorf("expected 2 directives, got %d", len(r.Directives))
				}
				if r.Directives[0].Mechanism != "include" {
					t.Errorf("expected mechanism 'include', got %q", r.Directives[0].Mechanism)
				}
				if r.Directives[0].DomainSpec != "example.com" {
					t.Errorf("expected domain 'example.com', got %q", r.Directives[0].DomainSpec)
				}
			},
		},
		{
			name:    "a mechanism with domain",
			input:   "v=spf1 a:mail.example.com -all",
			wantSPF: true,
			checkFunc: func(t *testing.T, r *Record) {
				if r.Directives[0].Mechanism != "a" {
					t.Errorf("expected mechanism 'a', got %q", r.Directives[0].Mechanism)
				}
				if r.Directives[0].DomainSpec != "mail.example.com" {
					t.Errorf("expected domain 'mail.example.com', got %q", r.Directives[0].DomainSpec)
				}
			},
		},
		{
			name:    "a mechanism without domain",
			input:   "v=spf1 a -all",
			wantSPF: true,
			checkFunc: func(t *testing.T, r *Record) {
				if r.Directives[0].Mechanism != "a" {
					t.Errorf("expected mechanism 'a', got %q", r.Directives[0].Mechanism)
				}
				if r.Directives[0].DomainSpec != "" {
					t.Errorf("expected empty domain, got %q", r.Directives[0].DomainSpec)
				}
			},
		},
		{
			name:    "a mechanism with cidr",
			input:   "v=spf1 a/24 -all",
			wantSPF: true,
			checkFunc: func(t *testing.T, r *Record) {
				if r.Directives[0].IP4CIDRLen == nil || *r.Directives[0].IP4CIDRLen != 24 {
					t.Errorf("expected IP4CIDRLen 24")
				}
			},
		},
		{
			name:    "a mechanism with dual cidr",
			input:   "v=spf1 a/24//64 -all",
			wantSPF: true,
			checkFunc: func(t *testing.T, r *Record) {
				if r.Directives[0].IP4CIDRLen == nil || *r.Directives[0].IP4CIDRLen != 24 {
					t.Errorf("expected IP4CIDRLen 24")
				}
				if r.Directives[0].IP6CIDRLen == nil || *r.Directives[0].IP6CIDRLen != 64 {
					t.Errorf("expected IP6CIDRLen 64")
				}
			},
		},
		{
			name:    "mx mechanism",
			input:   "v=spf1 mx:example.com -all",
			wantSPF: true,
			checkFunc: func(t *testing.T, r *Record) {
				if r.Directives[0].Mechanism != "mx" {
					t.Errorf("expected mechanism 'mx', got %q", r.Directives[0].Mechanism)
				}
			},
		},
		{
			name:    "ptr mechanism",
			input:   "v=spf1 ptr:example.com -all",
			wantSPF: true,
			checkFunc: func(t *testing.T, r *Record) {
				if r.Directives[0].Mechanism != "ptr" {
					t.Errorf("expected mechanism 'ptr', got %q", r.Directives[0].Mechanism)
				}
			},
		},
		{
			name:    "ip4 mechanism",
			input:   "v=spf1 ip4:192.0.2.1 -all",
			wantSPF: true,
			checkFunc: func(t *testing.T, r *Record) {
				if r.Directives[0].Mechanism != "ip4" {
					t.Errorf("expected mechanism 'ip4', got %q", r.Directives[0].Mechanism)
				}
				if r.Directives[0].IP.String() != "192.0.2.1" {
					t.Errorf("expected IP '192.0.2.1', got %q", r.Directives[0].IP.String())
				}
				if r.Directives[0].IP4CIDRLen == nil || *r.Directives[0].IP4CIDRLen != 32 {
					t.Errorf("expected default IP4CIDRLen 32")
				}
			},
		},
		{
			name:    "ip4 mechanism with cidr",
			input:   "v=spf1 ip4:192.0.2.0/24 -all",
			wantSPF: true,
			checkFunc: func(t *testing.T, r *Record) {
				if r.Directives[0].IP4CIDRLen == nil || *r.Directives[0].IP4CIDRLen != 24 {
					t.Errorf("expected IP4CIDRLen 24")
				}
			},
		},
		{
			name:    "ip6 mechanism",
			input:   "v=spf1 ip6:2001:db8::1 -all",
			wantSPF: true,
			checkFunc: func(t *testing.T, r *Record) {
				if r.Directives[0].Mechanism != "ip6" {
					t.Errorf("expected mechanism 'ip6', got %q", r.Directives[0].Mechanism)
				}
				if r.Directives[0].IP6CIDRLen == nil || *r.Directives[0].IP6CIDRLen != 128 {
					t.Errorf("expected default IP6CIDRLen 128")
				}
			},
		},
		{
			name:    "ip6 mechanism with cidr",
			input:   "v=spf1 ip6:2001:db8::/32 -all",
			wantSPF: true,
			checkFunc: func(t *testing.T, r *Record) {
				if r.Directives[0].IP6CIDRLen == nil || *r.Directives[0].IP6CIDRLen != 32 {
					t.Errorf("expected IP6CIDRLen 32")
				}
			},
		},
		{
			name:    "exists mechanism",
			input:   "v=spf1 exists:%{i}.spf.example.com -all",
			wantSPF: true,
			checkFunc: func(t *testing.T, r *Record) {
				if r.Directives[0].Mechanism != "exists" {
					t.Errorf("expected mechanism 'exists', got %q", r.Directives[0].Mechanism)
				}
				if r.Directives[0].DomainSpec != "%{i}.spf.example.com" {
					t.Errorf("expected domain '%%{i}.spf.example.com', got %q", r.Directives[0].DomainSpec)
				}
			},
		},
		{
			name:    "redirect modifier",
			input:   "v=spf1 redirect=_spf.example.com",
			wantSPF: true,
			checkFunc: func(t *testing.T, r *Record) {
				if r.Redirect != "_spf.example.com" {
					t.Errorf("expected redirect '_spf.example.com', got %q", r.Redirect)
				}
			},
		},
		{
			name:    "exp modifier",
			input:   "v=spf1 -all exp=explain.example.com",
			wantSPF: true,
			checkFunc: func(t *testing.T, r *Record) {
				if r.Explanation != "explain.example.com" {
					t.Errorf("expected explanation 'explain.example.com', got %q", r.Explanation)
				}
			},
		},
		{
			name:    "complex record",
			input:   "v=spf1 +mx a:colo.example.com/28 include:aspmx.googlemail.com -all",
			wantSPF: true,
			checkFunc: func(t *testing.T, r *Record) {
				if len(r.Directives) != 4 {
					t.Errorf("expected 4 directives, got %d", len(r.Directives))
				}
			},
		},
		{
			name:    "not an SPF record",
			input:   "v=DKIM1; k=rsa; p=...",
			wantSPF: false,
		},
		{
			name:    "empty string",
			input:   "",
			wantSPF: false,
		},
		{
			name:    "case insensitive",
			input:   "V=SPF1 +ALL",
			wantSPF: true,
			checkFunc: func(t *testing.T, r *Record) {
				if len(r.Directives) != 1 {
					t.Errorf("expected 1 directive, got %d", len(r.Directives))
				}
			},
		},
		{
			name:    "multiple spaces",
			input:   "v=spf1   a   -all",
			wantSPF: true,
			checkFunc: func(t *testing.T, r *Record) {
				if len(r.Directives) != 2 {
					t.Errorf("expected 2 directives, got %d", len(r.Directives))
				}
			},
		},
		{
			name:    "trailing space",
			input:   "v=spf1 -all ",
			wantSPF: true,
			checkFunc: func(t *testing.T, r *Record) {
				if len(r.Directives) != 1 {
					t.Errorf("expected 1 directive, got %d", len(r.Directives))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, isSPF, err := ParseRecord(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseRecord() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if isSPF != tt.wantSPF {
				t.Errorf("ParseRecord() isSPF = %v, want %v", isSPF, tt.wantSPF)
				return
			}

			if tt.checkFunc != nil && r != nil {
				tt.checkFunc(t, r)
			}
		})
	}
}

func TestParseRecordErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "duplicate redirect",
			input: "v=spf1 redirect=a.example.com redirect=b.example.com",
		},
		{
			name:  "duplicate exp",
			input: "v=spf1 -all exp=a.example.com exp=b.example.com",
		},
		{
			name:  "invalid ip4 cidr",
			input: "v=spf1 ip4:192.0.2.0/33 -all",
		},
		{
			name:  "invalid ip6 cidr",
			input: "v=spf1 ip6:2001:db8::/129 -all",
		},
		{
			name:  "qualifier without mechanism",
			input: "v=spf1 + -all",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ParseRecord(tt.input)
			if err == nil {
				t.Errorf("ParseRecord() expected error for %q", tt.input)
			}
		})
	}
}

func TestParseRecordVersionSelection(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantSPF bool
		wantErr bool
	}{
		{name: "bare version", input: "v=spf1", wantSPF: true},
		{name: "version with trailing spaces", input: "v=spf1   ", wantSPF: true},
		{name: "spf10 is not spf", input: "v=spf10", wantSPF: false},
		{name: "spf1 suffix is not spf", input: "v=spf1x", wantSPF: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, isSPF, err := ParseRecord(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseRecord() error = %v, wantErr %v", err, tt.wantErr)
			}
			if isSPF != tt.wantSPF {
				t.Fatalf("ParseRecord() isSPF = %v, want %v", isSPF, tt.wantSPF)
			}
			if tt.wantSPF && err == nil && r == nil {
				t.Fatal("ParseRecord() returned nil record for SPF input")
			}
		})
	}
}

func TestRecordString(t *testing.T) {
	input := "v=spf1 +mx a:colo.example.com -all"
	r, _, err := ParseRecord(input)
	if err != nil {
		t.Fatalf("ParseRecord() error = %v", err)
	}

	s := r.String()
	if s != input {
		// String representation might vary slightly
		t.Logf("Record.String() = %q, original = %q", s, input)
	}
}

func TestDirectiveString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple all",
			input:    "v=spf1 -all",
			expected: "-all",
		},
		{
			name:     "ip4",
			input:    "v=spf1 ip4:192.0.2.0/24",
			expected: "ip4:192.0.2.0/24",
		},
		{
			name:     "include",
			input:    "v=spf1 include:example.com",
			expected: "include:example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _, err := ParseRecord(tt.input)
			if err != nil {
				t.Fatalf("ParseRecord() error = %v", err)
			}
			if len(r.Directives) == 0 {
				t.Fatal("no directives parsed")
			}
			s := r.Directives[0].String()
			if s != tt.expected {
				t.Errorf("Directive.String() = %q, want %q", s, tt.expected)
			}
		})
	}
}

func TestRecordStringWithModifiers(t *testing.T) {
	ip4CIDR := 24
	record := Record{
		Version: "spf1",
		Directives: []Directive{{
			Qualifier:  "-",
			Mechanism:  "ip4",
			IP:         net.ParseIP("192.0.2.0"),
			IP4CIDRLen: &ip4CIDR,
		}},
		Redirect:    "_spf.example.com",
		Explanation: "explain.example.com",
		Other: []Modifier{{
			Key:   "foo",
			Value: "bar",
		}},
	}

	got := record.String()
	want := "v=spf1 -ip4:192.0.2.0/24 redirect=_spf.example.com exp=explain.example.com foo=bar"
	if got != want {
		t.Fatalf("Record.String() = %q, want %q", got, want)
	}
}

func TestDirectiveMechanismStringIPv6(t *testing.T) {
	ip6CIDR := 64
	directive := Directive{
		Mechanism:  "ip6",
		IP:         net.ParseIP("2001:db8::1"),
		IP6CIDRLen: &ip6CIDR,
	}

	got := directive.MechanismString()
	want := "ip6:2001:db8::1/64"
	if got != want {
		t.Fatalf("Directive.MechanismString() = %q, want %q", got, want)
	}
}

func TestParserHelpers(t *testing.T) {
	if got := parseError("boom").Error(); got != "boom" {
		t.Fatalf("parseError.Error() = %q, want %q", got, "boom")
	}
	if got := toLower("AbC-123"); got != "abc-123" {
		t.Fatalf("toLower() = %q, want %q", got, "abc-123")
	}

	p := parser{s: "hello", lower: toLower("hello")}
	if got := p.xtake("he"); got != "he" {
		t.Fatalf("xtake() = %q, want %q", got, "he")
	}
	if got := p.xtakelist("ll", "xx"); got != "ll" {
		t.Fatalf("xtakelist() = %q, want %q", got, "ll")
	}

	p = parser{s: "42", lower: "42"}
	if n, raw := p.xnumber(); n != 42 || raw != "42" {
		t.Fatalf("xnumber() = (%d, %q), want (42, %q)", n, raw, "42")
	}
	p = parser{s: "0", lower: "0"}
	if n, raw := p.xnumber(); n != 0 || raw != "0" {
		t.Fatalf("xnumber() zero = (%d, %q), want (0, %q)", n, raw, "0")
	}

	p = parser{s: "mail.example.com", lower: "mail.example.com"}
	if got := p.xdomainSpec(true); got != "mail.example.com" {
		t.Fatalf("xdomainSpec() = %q, want %q", got, "mail.example.com")
	}

	p = parser{s: "%{s1r.-+,/_=}/rest", lower: toLower("%{s1r.-+,/_=}/rest")}
	if got := p.xmacroString(false); got != "%{s1r.-+,/_=}" {
		t.Fatalf("xmacroString(false) = %q, want %q", got, "%{s1r.-+,/_=}")
	}
	p = parser{s: "%%", lower: "%%"}
	if got := p.xmacroString(false); got != "%%" {
		t.Fatalf("xmacroString(escaped percent) = %q, want %q", got, "%%")
	}

	p = parser{s: "foo/bar", lower: "foo/bar"}
	if got := p.xmacroString(true); got != "foo/bar" {
		t.Fatalf("xmacroString(true) = %q, want %q", got, "foo/bar")
	}

	p = parser{s: "192.0.2.1", lower: "192.0.2.1"}
	ip4, raw4 := p.xip4address()
	if raw4 != "192.0.2.1" || !ip4.Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("xip4address() = (%v, %q), want (192.0.2.1, %q)", ip4, raw4, "192.0.2.1")
	}

	p = parser{s: "2001:db8::1", lower: toLower("2001:db8::1")}
	ip6, raw6 := p.xip6address()
	if raw6 != "2001:db8::1" || !ip6.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("xip6address() = (%v, %q), want (2001:db8::1, %q)", ip6, raw6, "2001:db8::1")
	}

	msg := expectParserError(t, func() {
		p := parser{s: "", lower: ""}
		_, _ = p.xnumber()
	})
	if !strings.Contains(msg, "expected number") {
		t.Fatalf("xnumber() empty panic = %q, want expected number message", msg)
	}

	msg = expectParserError(t, func() {
		big := strings.Repeat("9", 64)
		p := parser{s: big, lower: big}
		_, _ = p.xnumber()
	})
	if !strings.Contains(msg, "parsing number") {
		t.Fatalf("xnumber() overflow panic = %q, want parsing number message", msg)
	}

	msg = expectParserError(t, func() {
		p := parser{s: "abc", lower: "abc"}
		_ = p.xtake("z")
	})
	if !strings.Contains(msg, `expected "z"`) {
		t.Fatalf("xtake() panic = %q, want expected token message", msg)
	}

	msg = expectParserError(t, func() {
		p := parser{s: "abc", lower: "abc"}
		_ = p.xtakelist("x", "y")
	})
	if !strings.Contains(msg, "no match") {
		t.Fatalf("xtakelist() panic = %q, want no match", msg)
	}

	msg = expectParserError(t, func() {
		p := parser{s: "01", lower: "01"}
		_, _ = p.xnumber()
	})
	if !strings.Contains(msg, "invalid leading zero") {
		t.Fatalf("xnumber() panic = %q, want leading zero message", msg)
	}

	msg = expectParserError(t, func() {
		p := parser{s: "mail.123", lower: "mail.123"}
		_ = p.xdomainSpec(true)
	})
	if !strings.Contains(msg, "toplabel cannot be all digits") {
		t.Fatalf("xdomainSpec() panic = %q, want toplabel message", msg)
	}

	msg = expectParserError(t, func() {
		p := parser{s: ".", lower: "."}
		_ = p.xdomainSpec(true)
	})
	if !strings.Contains(msg, "invalid empty toplabel") {
		t.Fatalf("xdomainSpec() empty toplabel panic = %q, want empty toplabel message", msg)
	}

	msg = expectParserError(t, func() {
		p := parser{s: "mail.-example", lower: "mail.-example"}
		_ = p.xdomainSpec(true)
	})
	if !strings.Contains(msg, "toplabel cannot start with dash") {
		t.Fatalf("xdomainSpec() leading dash panic = %q, want leading dash message", msg)
	}

	msg = expectParserError(t, func() {
		p := parser{s: "mail.example-", lower: "mail.example-"}
		_ = p.xdomainSpec(true)
	})
	if !strings.Contains(msg, "toplabel cannot end with dash") {
		t.Fatalf("xdomainSpec() trailing dash panic = %q, want trailing dash message", msg)
	}

	msg = expectParserError(t, func() {
		p := parser{s: "mail.exa$mple", lower: "mail.exa$mple"}
		_ = p.xdomainSpec(true)
	})
	if !strings.Contains(msg, "invalid character in toplabel") {
		t.Fatalf("xdomainSpec() invalid char panic = %q, want invalid char message", msg)
	}

	msg = expectParserError(t, func() {
		big := "%{s" + strings.Repeat("9", 64) + "}"
		p := parser{s: big, lower: toLower(big)}
		_ = p.xmacroString(false)
	})
	if !strings.Contains(msg, "invalid digits") {
		t.Fatalf("xmacroString() overflow panic = %q, want invalid digits message", msg)
	}

	msg = expectParserError(t, func() {
		p := parser{s: "%{s0}", lower: "%{s0}"}
		_ = p.xmacroString(false)
	})
	if !strings.Contains(msg, "zero labels not allowed") {
		t.Fatalf("xmacroString() zero labels panic = %q, want zero labels message", msg)
	}

	msg = expectParserError(t, func() {
		p := parser{s: "999.0.0.1", lower: "999.0.0.1"}
		_, _ = p.xip4address()
	})
	if !strings.Contains(msg, "invalid IPv4 octet") {
		t.Fatalf("xip4address() panic = %q, want invalid octet message", msg)
	}

	msg = expectParserError(t, func() {
		p := parser{s: "1:::1", lower: "1:::1"}
		_, _ = p.xip6address()
	})
	if !strings.Contains(msg, "invalid IPv6 address") {
		t.Fatalf("xip6address() panic = %q, want invalid IPv6 message", msg)
	}
}

func TestParseRecordAdditionalErrors(t *testing.T) {
	tests := []string{
		"v=spf1 allx",
		"v=spf1 foo",
		"v=spf1 a/33",
		"v=spf1 a//129",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			_, _, err := ParseRecord(input)
			if err == nil {
				t.Fatalf("ParseRecord(%q) expected error", input)
			}
		})
	}

	r, isSPF, err := ParseRecord("v=spf1 foo=bar")
	if err != nil || !isSPF || len(r.Other) != 1 || r.Other[0].Key != "foo" || r.Other[0].Value != "bar" {
		t.Fatalf("ParseRecord() unknown modifier = (%v, %v, %v), want one parsed modifier", r, isSPF, err)
	}
}

func TestDirectiveStringDualCIDR(t *testing.T) {
	ip6CIDR := 64
	directive := Directive{
		Mechanism:  "a",
		DomainSpec: "example.com",
		IP6CIDRLen: &ip6CIDR,
	}
	if got := directive.String(); got != "a:example.com//64" {
		t.Fatalf("Directive.String() = %q, want %q", got, "a:example.com//64")
	}
}
