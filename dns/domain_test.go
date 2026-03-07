package dns

import "testing"

func TestIsValidSMTPHostname(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		want     bool
	}{
		// Valid domain names
		{"simple domain", "example.com", true},
		{"subdomain", "mail.example.com", true},
		{"deep subdomain", "smtp.mail.example.com", true},
		{"single label", "localhost", true},
		{"with trailing dot", "example.com.", true},
		{"numeric labels", "123.example.com", true},
		{"alphanumeric", "mail1.example.com", true},
		{"hyphen in middle", "my-server.example.com", true},

		// Valid IPv4 address literals
		{"IPv4 literal", "[192.168.1.1]", true},
		{"IPv4 loopback", "[127.0.0.1]", true},
		{"IPv4 zeros", "[0.0.0.0]", true},

		// Valid IPv6 address literals
		{"IPv6 literal", "[IPv6:2001:db8::1]", true},
		{"IPv6 full", "[IPv6:2001:0db8:0000:0000:0000:0000:0000:0001]", true},
		{"IPv6 loopback", "[IPv6:::1]", true},
		{"IPv6 lowercase prefix", "[ipv6:2001:db8::1]", true},

		// Valid internationalized domain names (IDN)
		{"IDN hostname", "müller.example.com", true},
		{"IDN Chinese", "邮件.example.com", true},

		// Invalid hostnames
		{"empty string", "", false},
		{"only spaces", "   ", false},
		{"starts with hyphen", "-example.com", false},
		{"ends with hyphen", "example-.com", false},
		{"label starts with hyphen", "mail.-example.com", false},
		{"label ends with hyphen", "mail.example-.com", false},
		{"double dot", "mail..example.com", false},
		{"empty label", ".example.com", false},
		{"label too long", "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz.com", false},
		{"invalid chars underscore", "my_server.example.com", false},
		{"invalid chars space", "my server.example.com", false},

		// Invalid address literals
		{"unclosed bracket", "[192.168.1.1", false},
		{"no opening bracket", "192.168.1.1]", false},
		{"empty brackets", "[]", false},
		{"invalid IPv4 in brackets", "[999.999.999.999]", false},
		{"IPv6 without prefix", "[2001:db8::1]", false},
		{"invalid IPv6", "[IPv6:not-an-ip]", false},
		{"bare IPv4", "192.168.1.1", false},
		{"bare IPv6", "2001:db8::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidSMTPHostname(tt.hostname); got != tt.want {
				t.Errorf("IsValidSMTPHostname(%q) = %v, want %v", tt.hostname, got, tt.want)
			}
		})
	}
}

func TestIsValidDomain(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		// Valid ASCII domains
		{"simple", "example.com", true},
		{"subdomain", "www.example.com", true},
		{"numeric TLD", "example.123", true},
		{"all numeric label", "123.example.com", true},
		{"single char labels", "a.b.c", true},
		{"with trailing dot", "example.com.", true},
		{"max label length 63", "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789a.com", true},

		// Valid internationalized domain names (IDN)
		{"IDN German", "münchen.de", true},
		{"IDN Chinese", "中文.com", true},
		{"IDN Japanese", "日本語.jp", true},
		{"IDN Arabic", "مثال.com", true},
		{"IDN Cyrillic", "пример.рф", true},
		{"IDN mixed", "café.example.com", true},
		{"Punycode", "xn--mnchen-3ya.de", true},

		// Invalid domains
		{"empty", "", false},
		{"only dot", ".", false},
		{"double dot", "example..com", false},
		{"starts with dot", ".example.com", false},
		{"label over 63 chars", "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789ab.com", false},
		{"starts with hyphen", "-example.com", false},
		{"ends with hyphen", "example-.com", false},
		{"contains underscore", "ex_ample.com", false},
		{"contains space", "ex ample.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidDomain(tt.domain); got != tt.want {
				t.Errorf("IsValidDomain(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}
