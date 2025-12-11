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

	// Test that GenerateID returns a hex-encoded string of expected length
	// 8 bytes -> 16 hex characters
	expectedLen := 16
	if len(id) != expectedLen {
		t.Errorf("GenerateID() returned string of length %d, want %d", len(id), expectedLen)
	}

	// Test that the returned string is valid hex
	for _, c := range id {
		if !isHexChar(c) {
			t.Errorf("GenerateID() returned non-hex character: %c", c)
			break
		}
	}

	// Test uniqueness (generate multiple IDs and ensure they're different)
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		newID := GenerateID()
		if ids[newID] {
			t.Errorf("GenerateID() returned duplicate ID: %s", newID)
		}
		ids[newID] = true
	}
}

func isHexChar(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
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
