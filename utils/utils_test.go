package utils

import (
	"net"
	"testing"
)

func TestContainsNonASCII(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "empty string",
			input:    "",
			expected: false,
		},
		{
			name:     "pure ASCII lowercase",
			input:    "hello world",
			expected: false,
		},
		{
			name:     "pure ASCII with numbers",
			input:    "hello123world",
			expected: false,
		},
		{
			name:     "pure ASCII with symbols",
			input:    "hello!@#$%^&*()_+-=",
			expected: false,
		},
		{
			name:     "email address",
			input:    "user@example.com",
			expected: false,
		},
		{
			name:     "ASCII with newlines",
			input:    "hello\r\nworld",
			expected: false,
		},
		{
			name:     "ASCII with tabs",
			input:    "hello\tworld",
			expected: false,
		},
		{
			name:     "single non-ASCII character",
			input:    "ä",
			expected: true,
		},
		{
			name:     "UTF-8 umlaut",
			input:    "hello wörld",
			expected: true,
		},
		{
			name:     "UTF-8 emoji",
			input:    "hello 👋",
			expected: true,
		},
		{
			name:     "Chinese characters",
			input:    "你好",
			expected: true,
		},
		{
			name:     "mixed ASCII and UTF-8",
			input:    "hello世界",
			expected: true,
		},
		{
			name:     "international email-like",
			input:    "user@exämple.com",
			expected: true,
		},
		{
			name:     "high ASCII byte string",
			input:    string([]byte{0x80}),
			expected: true,
		},
		{
			name:     "boundary ASCII (127)",
			input:    string([]byte{127}),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ContainsNonASCII(tt.input)
			if result != tt.expected {
				t.Errorf("ContainsNonASCII(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGenerateID(t *testing.T) {
	// Test that GenerateID returns a non-empty string
	id := GenerateID()
	if id == "" {
		t.Error("GenerateID() returned empty string")
	}

	// Test that GenerateID returns a ULID of expected length (26 characters)
	expectedLen := 26
	if len(id) != expectedLen {
		t.Errorf("GenerateID() returned string of length %d, want %d", len(id), expectedLen)
	}

	// Test that the returned string is valid Crockford's base32 (ULID alphabet)
	for _, c := range id {
		if !isULIDChar(c) {
			t.Errorf("GenerateID() returned invalid ULID character: %c", c)
			break
		}
	}

	// Test uniqueness (generate multiple IDs and ensure they're different)
	ids := make(map[string]bool)
	for range 100 {
		newID := GenerateID()
		if ids[newID] {
			t.Errorf("GenerateID() returned duplicate ID: %s", newID)
		}
		ids[newID] = true
	}
}

// isULIDChar checks if a character is valid in Crockford's base32 encoding (ULID alphabet).
// Valid characters: 0-9, A-Z (excluding I, L, O, U)
func isULIDChar(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'H') || (c >= 'J' && c <= 'K') ||
		(c >= 'M' && c <= 'N') || (c >= 'P' && c <= 'T') || (c >= 'V' && c <= 'Z')
}

func TestGetIPFromAddr(t *testing.T) {
	tests := []struct {
		name        string
		addr        net.Addr
		expectedIP  string
		expectError bool
	}{
		{
			name:        "nil address",
			addr:        nil,
			expectedIP:  "",
			expectError: true,
		},
		{
			name:        "TCP IPv4 address",
			addr:        &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 25},
			expectedIP:  "192.168.1.1",
			expectError: false,
		},
		{
			name:        "TCP IPv6 address",
			addr:        &net.TCPAddr{IP: net.ParseIP("::1"), Port: 25},
			expectedIP:  "::1",
			expectError: false,
		},
		{
			name:        "TCP IPv4 loopback",
			addr:        &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 587},
			expectedIP:  "127.0.0.1",
			expectError: false,
		},
		{
			name:        "UDP address",
			addr:        &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 53},
			expectedIP:  "10.0.0.1",
			expectError: false,
		},
		{
			name:        "IP address",
			addr:        &net.IPAddr{IP: net.ParseIP("8.8.8.8")},
			expectedIP:  "8.8.8.8",
			expectError: false,
		},
		{
			name:        "IPv6 full address",
			addr:        &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 25},
			expectedIP:  "2001:db8::1",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, err := GetIPFromAddr(tt.addr)
			if tt.expectError {
				if err == nil {
					t.Errorf("GetIPFromAddr() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("GetIPFromAddr() unexpected error: %v", err)
				return
			}
			if ip.String() != tt.expectedIP {
				t.Errorf("GetIPFromAddr() = %v, want %v", ip.String(), tt.expectedIP)
			}
		})
	}
}

// mockAddr implements net.Addr for testing the fallback path
type mockAddr struct {
	network string
	str     string
}

func (m mockAddr) Network() string { return m.network }
func (m mockAddr) String() string  { return m.str }

func TestGetIPFromAddr_FallbackPath(t *testing.T) {
	tests := []struct {
		name        string
		addr        net.Addr
		expectedIP  string
		expectError bool
	}{
		{
			name:        "string with host:port",
			addr:        mockAddr{network: "tcp", str: "192.168.1.100:25"},
			expectedIP:  "192.168.1.100",
			expectError: false,
		},
		{
			name:        "string with IPv6 host:port",
			addr:        mockAddr{network: "tcp", str: "[::1]:25"},
			expectedIP:  "::1",
			expectError: false,
		},
		{
			name:        "invalid address string",
			addr:        mockAddr{network: "tcp", str: "not-an-ip"},
			expectedIP:  "",
			expectError: true,
		},
		{
			name:        "just IP without port",
			addr:        mockAddr{network: "tcp", str: "10.0.0.1"},
			expectedIP:  "10.0.0.1",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, err := GetIPFromAddr(tt.addr)
			if tt.expectError {
				if err == nil {
					t.Errorf("GetIPFromAddr() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("GetIPFromAddr() unexpected error: %v", err)
				return
			}
			if ip.String() != tt.expectedIP {
				t.Errorf("GetIPFromAddr() = %v, want %v", ip.String(), tt.expectedIP)
			}
		})
	}
}

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
