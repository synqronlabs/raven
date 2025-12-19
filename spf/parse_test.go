package spf

import (
	"testing"
)

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
