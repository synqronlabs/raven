package io

import "testing"

func TestContainsNonASCII(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{name: "empty string", input: "", expected: false},
		{name: "pure ASCII lowercase", input: "hello world", expected: false},
		{name: "pure ASCII with numbers", input: "hello123world", expected: false},
		{name: "pure ASCII with symbols", input: "hello!@#$%^&*()_+-=", expected: false},
		{name: "email address", input: "user@example.com", expected: false},
		{name: "ASCII with newlines", input: "hello\r\nworld", expected: false},
		{name: "ASCII with tabs", input: "hello\tworld", expected: false},
		{name: "single non-ASCII character", input: "ä", expected: true},
		{name: "UTF-8 umlaut", input: "hello wörld", expected: true},
		{name: "UTF-8 emoji", input: "hello 👋", expected: true},
		{name: "Chinese characters", input: "你好", expected: true},
		{name: "mixed ASCII and UTF-8", input: "hello世界", expected: true},
		{name: "international email-like", input: "user@exämple.com", expected: true},
		{name: "high ASCII byte string", input: string([]byte{0x80}), expected: true},
		{name: "boundary ASCII (127)", input: string([]byte{127}), expected: false},
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
