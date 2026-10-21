package mail

import (
	"errors"
	"testing"
)

func TestParseAddrSpec_Valid(t *testing.T) {
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

		// Quoted local-part (stored in unquoted semantic form)
		{"quoted simple", `"user"@example.com`, false, `user`, "example.com"},
		{"quoted with space", `"user name"@example.com`, false, `user name`, "example.com"},
		{"quoted with at", `"user@domain"@example.com`, false, `user@domain`, "example.com"},
		{"quoted with dot dot", `"user..name"@example.com`, false, `user..name`, "example.com"},
		{"quoted with backslash", `"user\\name"@example.com`, false, `user\name`, "example.com"},
		{"quoted with quote", `"user\"name"@example.com`, false, `user"name`, "example.com"},

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
			parsed, err := ParseAddrSpec(tt.address, tt.allowUTF8)
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

func TestParseAddrSpec_Invalid(t *testing.T) {
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
		{"invalid char in local", "user<name@example.com", false, ErrInvalidLocalPart},
		{"space without quotes", "user name@example.com", false, ErrInvalidLocalPart},

		// Domain errors
		{"domain starts with dot", "user@.example.com", false, ErrInvalidDomain},
		{"domain ends with dot", "user@example.com.", false, ErrInvalidDomain},
		{"domain starts with hyphen", "user@-example.com", false, ErrInvalidDomain},
		{"label ends with hyphen", "user@example-.com", false, ErrInvalidDomain},
		{"consecutive dots in domain", "user@example..com", false, ErrInvalidDomain},
		{"invalid char in domain", "user@exam ple.com", false, ErrInvalidDomain},

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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseAddrSpec(tt.address, tt.allowUTF8)
			if err == nil {
				t.Fatalf("expected error %v, got nil", tt.wantErr)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseAddrSpec_LengthLimits(t *testing.T) {
	local := make([]byte, 65)
	for i := range local {
		local[i] = 'a'
	}
	if _, err := ParseAddrSpec(string(local)+"@example.com", false); !errors.Is(err, ErrLocalPartTooLong) {
		t.Errorf("local too long error = %v, want %v", err, ErrLocalPartTooLong)
	}

	label := make([]byte, 64)
	for i := range label {
		label[i] = 'a'
	}
	if _, err := ParseAddrSpec("user@"+string(label)+".com", false); !errors.Is(err, ErrInvalidDomain) {
		t.Errorf("domain label too long error = %v, want %v", err, ErrInvalidDomain)
	}

	domain := make([]byte, 250)
	for i := range domain {
		domain[i] = 'a'
	}
	if _, err := ParseAddrSpec("user@"+string(domain)+".com", false); !errors.Is(err, ErrAddressTooLong) {
		t.Errorf("address too long error = %v, want %v", err, ErrAddressTooLong)
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
		{"source route", "<@relay.example.com:user@example.com>", false, "user@example.com", ""},
		{"source route multiple", "<@a.example.com,@b.example.com:user@example.com> SIZE=5", false, "user@example.com", "SIZE=5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, params, err := ParsePath(tt.path, tt.allowUTF8)
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
		{"bad source route", "<@:user@example.com>", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ParsePath(tt.path, tt.allowUTF8)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestValidateIPv4(t *testing.T) {
	valid := []string{"0.0.0.0", "1.2.3.4", "192.168.1.1", "255.255.255.255", "10.0.0.1"}
	for _, ip := range valid {
		if !isValidIPv4(ip) {
			t.Errorf("isValidIPv4(%q) = false, want true", ip)
		}
	}

	invalid := []string{"256.1.1.1", "1.256.1.1", "1.1.256.1", "1.1.1.256", "1.1.1", "1.1.1.1.1", "1.1.1.", ".1.1.1", "01.1.1.1", "001.1.1.1", "1.1.1.1a", "a.1.1.1", ""}
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
		"::ffff:192.0.2.1",
	}
	for _, ip := range valid {
		if !isValidIPv6(ip) {
			t.Errorf("isValidIPv6(%q) = false, want true", ip)
		}
	}

	invalid := []string{"", "2001:db8::1::2", "2001:db8:1:2:3:4:5:6:7:8", "gggg::1", "2001:db8"}
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
	if _, err := ParseAddrSpec("用户@example.com", false); !errors.Is(err, ErrNonASCIIWithoutUTF8) {
		t.Errorf("expected ErrNonASCIIWithoutUTF8, got %v", err)
	}

	parsed, err := ParseAddrSpec("用户@example.com", true)
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
		{`"simple"@example.com`, `simple`},
		{`"with space"@example.com`, `with space`},
		{`"with.dot"@example.com`, `with.dot`},
		{`"with@at"@example.com`, `with@at`},
		{`"with\"quote"@example.com`, `with"quote`},
		{`"with\\backslash"@example.com`, `with\backslash`},
	}

	for _, tt := range valid {
		t.Run(tt.local, func(t *testing.T) {
			parsed, err := ParseAddrSpec(tt.address, false)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if parsed.LocalPart != tt.local {
				t.Errorf("LocalPart = %q, want %q", parsed.LocalPart, tt.local)
			}
			// The semantic local-part must serialize back to an SMTP-valid
			// local-part, re-quoting when required.
			if _, err := ParseAddrSpec(parsed.String(), false); err != nil {
				t.Errorf("ParseAddrSpec(%q) after serialization error: %v", parsed.String(), err)
			}
		})
	}
}

func TestParseAddress_Mailbox(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantLocal   string
		wantDomain  string
		wantDisplay string
	}{
		{"addr-spec", "user@example.com", "user", "example.com", ""},
		{"name-addr", "Jane Doe <jane@example.com>", "jane", "example.com", "Jane Doe"},
		{"quoted display", `"Doe, John" <john@example.com>`, "john", "example.com", "Doe, John"},
		{"comment", "(lead) user@example.com", "user", "example.com", ""},
		{"obs domain literal", "user@[IPv6:2001:db8::1]", "user", "[IPv6:2001:db8::1]", ""},
		{"utf8", "Jöhn <jöhn@example.com>", "jöhn", "example.com", "Jöhn"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseAddress(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if parsed.LocalPart != tt.wantLocal || parsed.Domain != tt.wantDomain || parsed.DisplayName != tt.wantDisplay {
				t.Errorf("got %+v, want local=%q domain=%q display=%q", parsed, tt.wantLocal, tt.wantDomain, tt.wantDisplay)
			}
		})
	}
}

func TestParseAddressList(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"single", "user@example.com", []string{"user@example.com"}},
		{"two", "a@example.com, b@example.com", []string{"a@example.com", "b@example.com"}},
		{"quoted comma", `"Doe, John" <john@example.com>`, []string{"john@example.com"}},
		{"display names", "Jane <jane@example.com>, Bob <bob@example.com>", []string{"jane@example.com", "bob@example.com"}},
		{"empty group", "Undisclosed recipients:;", nil},
		{"group with members", "Friends: a@example.com, b@example.com;", []string{"a@example.com", "b@example.com"}},
		{"comment", "user@example.com (comment)", []string{"user@example.com"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAddressList(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d addresses, want %d (%v)", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i].String() != tt.want[i] {
					t.Errorf("address[%d] = %q, want %q", i, got[i].String(), tt.want[i])
				}
			}
		})
	}
}

func FuzzParseAddress(f *testing.F) {
	f.Add("user@example.com")
	f.Add("Jane Doe <jane@example.com>")
	f.Add(`"Doe, John" <john@example.com>`)
	f.Add("Friends: a@example.com, b@example.com;")
	f.Add("user@[IPv6:2001:db8::1]")
	f.Add("Thu, 12 Dec 2024 10:00:00 +0000")
	f.Add("<@relay.example.com:user@example.com> SIZE=10")

	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseAddress(s)
		_, _ = ParseAddressList(s)
		_, _, _ = ParsePath(s, true)
		_, _ = ParseDate(s)
	})
}

func TestParseDate(t *testing.T) {
	valid := []string{
		"Thu, 12 Dec 2024 10:00:00 +0000",
		"Thu, 12 Dec 2024 10:00:00 -0700",
		"12 Dec 2024 10:00 +0000",
		"Thu, 12 Dec 24 10:00:00 GMT",
		"Thu, 12 Dec 2024 10:00:00 EST",
		"Thu, 12 Dec 2024 10:00:00 -0000",
	}
	for _, value := range valid {
		if _, err := ParseDate(value); err != nil {
			t.Errorf("ParseDate(%q) error = %v", value, err)
		}
	}

	invalid := []string{"not a date", "", "Thu, 12 Dec 2024", "Thu 12 2024 10:00:00 +0000"}
	for _, value := range invalid {
		if _, err := ParseDate(value); err == nil {
			t.Errorf("ParseDate(%q) = nil error, want error", value)
		}
	}
}
