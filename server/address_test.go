package server

import (
	"errors"
	"testing"
)

func TestParseAddress_Valid(t *testing.T) {
	tests := []struct {
		name      string
		address   string
		allowUTF8 bool
		wantLocal string
		wantDom   string
	}{
		// Basic addresses
		{"simple", "user@example.com", false, "user", "example.com"},
		{"with dot", "user.name@example.com", false, "user.name", "example.com"},
		{"with plus", "user+tag@example.com", false, "user+tag", "example.com"},
		{"with hyphen", "user-name@example.com", false, "user-name", "example.com"},
		{"subdomain", "user@mail.example.com", false, "user", "mail.example.com"},
		{"numbers", "user123@example123.com", false, "user123", "example123.com"},

		// Special atext characters
		{"with exclamation", "user!name@example.com", false, "user!name", "example.com"},
		{"with hash", "user#name@example.com", false, "user#name", "example.com"},
		{"with percent", "user%name@example.com", false, "user%name", "example.com"},
		{"with ampersand", "user&name@example.com", false, "user&name", "example.com"},
		{"with apostrophe", "user'name@example.com", false, "user'name", "example.com"},
		{"with asterisk", "user*name@example.com", false, "user*name", "example.com"},
		{"with equals", "user=name@example.com", false, "user=name", "example.com"},
		{"with question", "user?name@example.com", false, "user?name", "example.com"},
		{"with caret", "user^name@example.com", false, "user^name", "example.com"},
		{"with underscore", "user_name@example.com", false, "user_name", "example.com"},
		{"with backtick", "user`name@example.com", false, "user`name", "example.com"},
		{"with braces", "user{name}@example.com", false, "user{name}", "example.com"},
		{"with pipe", "user|name@example.com", false, "user|name", "example.com"},
		{"with tilde", "user~name@example.com", false, "user~name", "example.com"},
		{"with slash", "user/name@example.com", false, "user/name", "example.com"},

		// Quoted local-part
		{"quoted simple", `"user"@example.com`, false, `"user"`, "example.com"},
		{"quoted with space", `"user name"@example.com`, false, `"user name"`, "example.com"},
		{"quoted with at", `"user@domain"@example.com`, false, `"user@domain"`, "example.com"},
		{"quoted with dot dot", `"user..name"@example.com`, false, `"user..name"`, "example.com"},
		{"quoted with backslash", `"user\\name"@example.com`, false, `"user\\name"`, "example.com"},
		{"quoted with quote", `"user\"name"@example.com`, false, `"user\"name"`, "example.com"},

		// IP address literals
		{"IPv4 literal", "user@[192.168.1.1]", false, "user", "[192.168.1.1]"},
		{"IPv6 literal", "user@[IPv6:2001:db8::1]", false, "user", "[IPv6:2001:db8::1]"},
		{"IPv6 full", "user@[IPv6:2001:0db8:0000:0000:0000:0000:0000:0001]", false, "user", "[IPv6:2001:0db8:0000:0000:0000:0000:0000:0001]"},

		// Internationalized (with SMTPUTF8)
		{"UTF8 local", "用户@example.com", true, "用户", "example.com"},
		{"UTF8 domain", "user@例え.jp", true, "user", "xn--r8jz45g.jp"}, // Punycode
		{"UTF8 both", "用户@例え.jp", true, "用户", "xn--r8jz45g.jp"},
		{"emoji local", "test😀@example.com", true, "test😀", "example.com"},
		{"german umlaut", "müller@example.com", true, "müller", "example.com"},
		{"russian", "пользователь@example.com", true, "пользователь", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := parseAddress(tt.address, tt.allowUTF8)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if parsed.LocalPart != tt.wantLocal {
				t.Errorf("LocalPart = %q, want %q", parsed.LocalPart, tt.wantLocal)
			}
			if parsed.Domain != tt.wantDom {
				t.Errorf("Domain = %q, want %q", parsed.Domain, tt.wantDom)
			}
		})
	}
}

func TestParseAddress_Invalid(t *testing.T) {
	tests := []struct {
		name      string
		address   string
		allowUTF8 bool
		wantErr   error
	}{
		// Empty/missing parts
		{"empty", "", false, ErrAddressEmpty},
		{"no at sign", "userexample.com", false, ErrAddressMissingAt},
		{"only at", "@", false, ErrLocalPartEmpty},
		{"empty local", "@example.com", false, ErrLocalPartEmpty},
		{"empty domain", "user@", false, ErrDomainEmpty},

		// Local-part errors
		{"local starts with dot", ".user@example.com", false, ErrInvalidLocalPart},
		{"local ends with dot", "user.@example.com", false, ErrInvalidLocalPart},
		{"consecutive dots", "user..name@example.com", false, ErrInvalidLocalPart},
		{"local too long", string(make([]byte, 65)) + "@example.com", false, ErrLocalPartTooLong},
		{"invalid char in local", "user<name@example.com", false, ErrInvalidLocalPart},
		{"space without quotes", "user name@example.com", false, ErrInvalidLocalPart},

		// Domain errors
		{"domain starts with dot", "user@.example.com", false, ErrInvalidDomain},
		{"domain ends with dot", "user@example.com.", false, ErrInvalidDomain},
		{"domain starts with hyphen", "user@-example.com", false, ErrInvalidDomain},
		{"label ends with hyphen", "user@example-.com", false, ErrInvalidDomain},
		{"consecutive dots in domain", "user@example..com", false, ErrInvalidDomain},
		{"invalid char in domain", "user@exam ple.com", false, ErrInvalidDomain},
		{"domain label too long", "user@" + string(make([]byte, 64)) + ".com", false, ErrInvalidDomain},

		// Non-ASCII without SMTPUTF8
		{"UTF8 local without flag", "用户@example.com", false, ErrNonASCIIWithoutUTF8},
		{"UTF8 domain without flag", "user@例え.jp", false, ErrNonASCIIWithoutUTF8},
		{"emoji without flag", "test😀@example.com", false, ErrNonASCIIWithoutUTF8},

		// IP literal errors
		{"invalid IPv4", "user@[999.999.999.999]", false, ErrInvalidIPLiteral},
		{"invalid IPv4 format", "user@[192.168.1]", false, ErrInvalidIPLiteral},
		{"IPv4 with leading zero", "user@[192.168.01.1]", false, ErrInvalidIPLiteral},
		{"invalid IPv6", "user@[IPv6:invalid]", false, ErrInvalidIPLiteral},
		{"bad literal format", "user@[notip]", false, ErrInvalidIPLiteral},

		// Length limits
		{"address too long", "user@" + string(make([]byte, 250)) + ".com", false, ErrAddressTooLong},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate valid-looking but invalid addresses for length tests
			addr := tt.address
			if tt.name == "local too long" {
				b := make([]byte, 65)
				for i := range b {
					b[i] = 'a'
				}
				addr = string(b) + "@example.com"
			}
			if tt.name == "domain label too long" {
				b := make([]byte, 64)
				for i := range b {
					b[i] = 'a'
				}
				addr = "user@" + string(b) + ".com"
			}
			if tt.name == "address too long" {
				b := make([]byte, 250)
				for i := range b {
					b[i] = 'a'
				}
				addr = "user@" + string(b) + ".com"
			}

			_, err := parseAddress(addr, tt.allowUTF8)
			if err == nil {
				t.Fatalf("expected error %v, got nil", tt.wantErr)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestParsePath_Valid(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		allowUTF8  bool
		wantAddr   string
		wantParams string
	}{
		{"simple", "<user@example.com>", false, "user@example.com", ""},
		{"with params", "<user@example.com> SIZE=1000", false, "user@example.com", "SIZE=1000"},
		{"null path", "<>", false, "", ""},
		{"multiple params", "<user@example.com> SIZE=100 BODY=8BITMIME", false, "user@example.com", "SIZE=100 BODY=8BITMIME"},
		{"with spaces", "  <user@example.com>  SIZE=100  ", false, "user@example.com", "SIZE=100"},
		{"UTF8 address", "<用户@example.com>", true, "用户@example.com", ""},
		{"IDN domain", "<user@例え.jp>", true, "user@xn--r8jz45g.jp", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, params, err := parsePath(tt.path, tt.allowUTF8)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if parsed.String() != tt.wantAddr {
				t.Errorf("address = %q, want %q", parsed.String(), tt.wantAddr)
			}
			if params != tt.wantParams {
				t.Errorf("params = %q, want %q", params, tt.wantParams)
			}
		})
	}
}

func TestParsePath_Invalid(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		allowUTF8 bool
	}{
		{"empty", "", false},
		{"no brackets", "user@example.com", false},
		{"no closing bracket", "<user@example.com", false},
		{"no opening bracket", "user@example.com>", false},
		{"UTF8 without flag", "<用户@example.com>", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := parsePath(tt.path, tt.allowUTF8)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestValidateIPv4(t *testing.T) {
	valid := []string{
		"0.0.0.0",
		"1.2.3.4",
		"192.168.1.1",
		"255.255.255.255",
		"10.0.0.1",
	}

	invalid := []string{
		"256.1.1.1",
		"1.256.1.1",
		"1.1.256.1",
		"1.1.1.256",
		"1.1.1",
		"1.1.1.1.1",
		"1.1.1.",
		".1.1.1",
		"01.1.1.1",  // Leading zero
		"001.1.1.1", // Leading zeros
		"1.1.1.1a",
		"a.1.1.1",
		"",
	}

	for _, ip := range valid {
		if !isValidIPv4(ip) {
			t.Errorf("isValidIPv4(%q) = false, want true", ip)
		}
	}

	for _, ip := range invalid {
		if isValidIPv4(ip) {
			t.Errorf("isValidIPv4(%q) = true, want false", ip)
		}
	}
}

func TestValidateIPv6(t *testing.T) {
	valid := []string{
		"2001:db8::1",
		"::1",
		"::",
		"2001:0db8:0000:0000:0000:0000:0000:0001",
		"fe80::1",
		"2001:db8:85a3::8a2e:370:7334",
	}

	invalid := []string{
		"",
		"2001:db8::1::2", // Multiple ::
		"2001:db8:1:2:3:4:5:6:7:8",
		"gggg::1",
		"2001:db8",
	}

	for _, ip := range valid {
		if !isValidIPv6(ip) {
			t.Errorf("isValidIPv6(%q) = false, want true", ip)
		}
	}

	for _, ip := range invalid {
		if isValidIPv6(ip) {
			t.Errorf("isValidIPv6(%q) = true, want false", ip)
		}
	}
}

func TestIDNConversion(t *testing.T) {
	tests := []struct {
		domain   string
		expected string
	}{
		{"example.com", "example.com"},
		{"例え.jp", "xn--r8jz45g.jp"},
		{"münchen.de", "xn--mnchen-3ya.de"},
		{"中文.com", "xn--fiq228c.com"},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			result, err := validateAndNormalizeDomain(tt.domain, true)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("got %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestSMTPUTF8Enforcement(t *testing.T) {
	// Without SMTPUTF8, non-ASCII should be rejected
	_, err := parseAddress("用户@example.com", false)
	if !errors.Is(err, ErrNonASCIIWithoutUTF8) {
		t.Errorf("expected ErrNonASCIIWithoutUTF8, got %v", err)
	}

	// With SMTPUTF8, non-ASCII should be accepted
	parsed, err := parseAddress("用户@example.com", true)
	if err != nil {
		t.Fatalf("unexpected error with SMTPUTF8: %v", err)
	}
	if parsed.LocalPart != "用户" {
		t.Errorf("LocalPart = %q, want %q", parsed.LocalPart, "用户")
	}
}

func TestQuotedLocalPart(t *testing.T) {
	valid := []struct {
		address string
		local   string
	}{
		{`"simple"@example.com`, `"simple"`},
		{`"with space"@example.com`, `"with space"`},
		{`"with.dot"@example.com`, `"with.dot"`},
		{`"with@at"@example.com`, `"with@at"`},
		{`"with\"quote"@example.com`, `"with\"quote"`},
		{`"with\\backslash"@example.com`, `"with\\backslash"`},
	}

	for _, tt := range valid {
		t.Run(tt.local, func(t *testing.T) {
			parsed, err := parseAddress(tt.address, false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if parsed.LocalPart != tt.local {
				t.Errorf("LocalPart = %q, want %q", parsed.LocalPart, tt.local)
			}
		})
	}
}

func TestExtractPathAndParams_SourceRoutes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantPath string
		wantParm string
	}{
		{"no source route", "<user@example.com>", "user@example.com", ""},
		{"single relay", "<@relay:user@example.com>", "user@example.com", ""},
		{"multiple relays", "<@a,@b:user@example.com>", "user@example.com", ""},
		{"source route with params", "<@relay:user@example.com> SIZE=100", "user@example.com", "SIZE=100"},
		{"null path", "<>", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, params, err := extractPathAndParams(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if path != tt.wantPath {
				t.Errorf("path = %q, want %q", path, tt.wantPath)
			}
			if params != tt.wantParm {
				t.Errorf("params = %q, want %q", params, tt.wantParm)
			}
		})
	}
}
