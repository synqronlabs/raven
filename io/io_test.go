package io

import (
	"bufio"
	"strings"
	"testing"
)

func TestIsASCII(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected bool
	}{
		{
			name:     "empty slice",
			input:    []byte{},
			expected: true,
		},
		{
			name:     "pure ASCII lowercase",
			input:    []byte("hello world"),
			expected: true,
		},
		{
			name:     "pure ASCII with numbers and symbols",
			input:    []byte("Hello123!@#$%^&*()"),
			expected: true,
		},
		{
			name:     "ASCII with CRLF",
			input:    []byte("hello\r\n"),
			expected: true,
		},
		{
			name:     "ASCII control characters",
			input:    []byte{0x00, 0x1F, 0x7F},
			expected: true,
		},
		{
			name:     "boundary ASCII (127)",
			input:    []byte{127},
			expected: true,
		},
		{
			name:     "non-ASCII single byte (128)",
			input:    []byte{128},
			expected: false,
		},
		{
			name:     "non-ASCII high byte",
			input:    []byte{255},
			expected: false,
		},
		{
			name:     "mixed ASCII with UTF-8",
			input:    []byte("hello wörld"),
			expected: false,
		},
		{
			name:     "UTF-8 emoji",
			input:    []byte("hello 👋"),
			expected: false,
		},
		{
			name:     "ASCII with non-ASCII at end",
			input:    []byte("hello\x80"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isASCII(tt.input)
			if result != tt.expected {
				t.Errorf("isASCII(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestValidateAndConvert(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		max         int
		expected    string
		expectError error
	}{
		{
			name:        "valid line with CRLF",
			input:       []byte("EHLO example.com\r\n"),
			max:         100,
			expected:    "EHLO example.com",
			expectError: nil,
		},
		{
			name:        "empty line with just CRLF",
			input:       []byte("\r\n"),
			max:         100,
			expected:    "",
			expectError: nil,
		},
		{
			name:        "line at max length",
			input:       []byte("abc\r\n"),
			max:         5,
			expected:    "abc",
			expectError: nil,
		},
		{
			name:        "line exceeds max length",
			input:       []byte("abcdef\r\n"),
			max:         5,
			expected:    "",
			expectError: ErrLineTooLong,
		},
		{
			name:        "line with only LF (bad ending)",
			input:       []byte("hello\n"),
			max:         100,
			expected:    "",
			expectError: ErrBadLineEnding,
		},
		{
			name:        "single byte line",
			input:       []byte("\n"),
			max:         100,
			expected:    "",
			expectError: ErrBadLineEnding,
		},
		{
			name:        "line with CR only before LF",
			input:       []byte("test\r\n"),
			max:         100,
			expected:    "test",
			expectError: nil,
		},
		{
			name:        "SMTP command",
			input:       []byte("MAIL FROM:<user@example.com>\r\n"),
			max:         512,
			expected:    "MAIL FROM:<user@example.com>",
			expectError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validateAndConvert(tt.input, tt.max)
			if err != tt.expectError {
				t.Errorf("validateAndConvert() error = %v, want %v", err, tt.expectError)
				return
			}
			if result != tt.expected {
				t.Errorf("validateAndConvert() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestReadLine(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		max         int
		enforce     bool
		expected    string
		expectError error
	}{
		{
			name:        "simple valid line",
			input:       "EHLO localhost\r\n",
			max:         100,
			enforce:     false,
			expected:    "EHLO localhost",
			expectError: nil,
		},
		{
			name:        "line with bad ending",
			input:       "EHLO localhost\n",
			max:         100,
			enforce:     false,
			expected:    "",
			expectError: ErrBadLineEnding,
		},
		{
			name:        "line too long",
			input:       "EHLO verylonghostname.example.com\r\n",
			max:         10,
			enforce:     false,
			expected:    "",
			expectError: ErrLineTooLong,
		},
		{
			name:        "8-bit data with enforce=false",
			input:       "EHLO exämple.com\r\n",
			max:         100,
			enforce:     false,
			expected:    "EHLO exämple.com",
			expectError: nil,
		},
		{
			name:        "8-bit data with enforce=true",
			input:       "EHLO exämple.com\r\n",
			max:         100,
			enforce:     true,
			expected:    "",
			expectError: Err8BitIn7BitMode, // Non-ASCII detected with enforcement enabled
		},
		{
			name:        "empty line",
			input:       "\r\n",
			max:         100,
			enforce:     false,
			expected:    "",
			expectError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bufio.NewReader(strings.NewReader(tt.input))
			result, err := ReadLine(reader, tt.max, tt.enforce)
			if err != tt.expectError {
				t.Errorf("ReadLine() error = %v, want %v", err, tt.expectError)
				return
			}
			if result != tt.expected {
				t.Errorf("ReadLine() = %q, want %q", result, tt.expected)
			}
		})
	}
}
