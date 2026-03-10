package io

import (
	"bufio"
	"errors"
	"strings"
	"testing"
)

// TestReadLine_SlowPath exercises ReadLine when lines exceed the internal bufio
// buffer, forcing the multi-chunk accumulation code path.
func TestReadLine_SlowPath(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		max         int
		enforce     bool
		bufSize     int
		expected    string
		expectError error
	}{
		{
			name:        "line longer than buffer succeeds",
			input:       "EHLO localhost.example.com\r\n",
			max:         512,
			enforce:     false,
			bufSize:     4,
			expected:    "EHLO localhost.example.com",
			expectError: nil,
		},
		{
			name:        "line too long via slow path triggers drain",
			input:       "EHLO verylongdomainname.example.com\r\n",
			max:         10,
			enforce:     false,
			bufSize:     4,
			expected:    "",
			expectError: ErrLineTooLong,
		},
		{
			name:        "8-bit data in slow path with enforcement",
			input:       "EHLO ex\xc3\xa4mple.com\r\n",
			max:         512,
			enforce:     true,
			bufSize:     4,
			expected:    "",
			expectError: Err8BitIn7BitMode,
		},
		{
			name:        "8-bit data in slow path without enforcement",
			input:       "EHLO ex\xc3\xa4mple.com\r\n",
			max:         512,
			enforce:     false,
			bufSize:     4,
			expected:    "EHLO ex\xc3\xa4mple.com",
			expectError: nil,
		},
		{
			name:        "bad line ending via slow path",
			input:       "EHLO verylonghostname.example\n",
			max:         512,
			enforce:     false,
			bufSize:     4,
			expected:    "",
			expectError: ErrBadLineEnding,
		},
		{
			name:        "multiple lines reads first only via slow path",
			input:       "EHLO localhost.example.com\r\nRCPT TO:<user@example.com>\r\n",
			max:         512,
			enforce:     false,
			bufSize:     4,
			expected:    "EHLO localhost.example.com",
			expectError: nil,
		},
		{
			name:        "line exactly at max threshold via slow path",
			input:       "ABCDEFG\r\n",
			max:         9,
			enforce:     false,
			bufSize:     4,
			expected:    "ABCDEFG",
			expectError: nil,
		},
		{
			name:        "8-bit byte appearing in later chunk with enforcement",
			input:       "EHLO example." + string([]byte{0xC8}) + "com\r\n",
			max:         512,
			enforce:     true,
			bufSize:     4,
			expected:    "",
			expectError: Err8BitIn7BitMode,
		},
		{
			// bufio.NewReaderSize has a minimum of 16 bytes, so bufSize=4 still
			// gives a 16-byte internal buffer.  To ensure the non-ASCII byte
			// lands in a SECOND chunk (inside the accumulation loop, line 52)
			// rather than the first chunk (pre-loop check, line 37), use a
			// bufSize large enough that the first chunk is clean ASCII and
			// the \xC8 byte appears in the next read.
			name:        "8-bit byte in second in-loop chunk with enforcement",
			input:       strings.Repeat("A", 22) + string([]byte{0xC8}) + "\r\n",
			max:         512,
			enforce:     true,
			bufSize:     20,
			expected:    "",
			expectError: Err8BitIn7BitMode,
		},
		{
			name:        "slow path accumulates across many small chunks",
			input:       strings.Repeat("X", 64) + "\r\n",
			max:         512,
			enforce:     false,
			bufSize:     4,
			expected:    strings.Repeat("X", 64),
			expectError: nil,
		},
		{
			name:        "slow path detects too-long across chunks",
			input:       strings.Repeat("Y", 32) + "\r\n",
			max:         20,
			enforce:     false,
			bufSize:     4,
			expected:    "",
			expectError: ErrLineTooLong,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bufio.NewReaderSize(strings.NewReader(tt.input), tt.bufSize)
			result, err := ReadLine(reader, tt.max, tt.enforce)
			if !errors.Is(err, tt.expectError) && err != tt.expectError {
				t.Errorf("ReadLine() error = %v, want %v", err, tt.expectError)
				return
			}
			if result != tt.expected {
				t.Errorf("ReadLine() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestReadLine_EOFPaths tests that ReadLine returns an error when the underlying
// reader produces EOF before a complete CRLF-terminated line is available.
func TestReadLine_EOFPaths(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		bufSize int
	}{
		// Fast-path cases (input fits in bufio buffer).
		{"no newline at all", "EHLO localhost", 4096},
		{"empty reader", "", 4096},
		{"single CR without LF", "A\r", 4096},
		// Slow-path case: input exceeds the small bufio buffer so the
		// first ReadSlice returns ErrBufferFull; subsequent reads hit EOF.
		// This exercises the "reading continued SMTP line" error branch.
		{"EOF in slow path - no terminator", strings.Repeat("Z", 24), 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bufio.NewReaderSize(strings.NewReader(tt.input), tt.bufSize)
			_, err := ReadLine(reader, 512, false)
			if err == nil {
				t.Errorf("ReadLine(%q) expected error for EOF/no-newline, got nil", tt.input)
			}
		})
	}
}

// TestDrainLine_EOFWithNoFollowingLine verifies that drainLine handles EOF
// gracefully when there is NO newline at all after the oversize content —
// covering the `err != bufio.ErrBufferFull` (EOF) return inside drainLine.
func TestDrainLine_EOFWithNoFollowingLine(t *testing.T) {
	// 40 X's with NO CRLF: slow path triggers ErrLineTooLong and drainLine
	// is called; drainLine reads chunks and eventually hits io.EOF with no
	// '\n' found, which exercises its `err != bufio.ErrBufferFull` return.
	long := strings.Repeat("X", 40)
	reader := bufio.NewReaderSize(strings.NewReader(long), 8)
	_, err := ReadLine(reader, 10, false)
	if !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("expected ErrLineTooLong, got %v", err)
	}
}

// TestReadLine_DrainEnablesNextRead verifies that when ReadLine encounters a
// line that is too long in the slow path, drainLine clears the reader so the
// next call begins at the start of the following line.
func TestReadLine_DrainEnablesNextRead(t *testing.T) {
	long := strings.Repeat("X", 40)
	input := long + "\r\nOK\r\n"
	reader := bufio.NewReaderSize(strings.NewReader(input), 8)

	// First read: the long line exceeds max=10; should error and drain the rest.
	_, err := ReadLine(reader, 10, false)
	if !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("expected ErrLineTooLong, got %v", err)
	}

	// Second read: should succeed because drainLine consumed the remainder.
	result, err := ReadLine(reader, 512, false)
	if err != nil {
		t.Fatalf("ReadLine after drain: unexpected error: %v", err)
	}
	if result != "OK" {
		t.Errorf("ReadLine after drain: got %q, want %q", result, "OK")
	}
}

// TestReadLine_DrainMultipleChunks verifies drain works when the oversized line
// spans many internal buffer chunks before the next valid line.
func TestReadLine_DrainMultipleChunks(t *testing.T) {
	// Line is 100 bytes which spans many 4-byte bufio reads; max is 5.
	long := strings.Repeat("A", 100)
	input := long + "\r\nDONE\r\n"
	reader := bufio.NewReaderSize(strings.NewReader(input), 4)

	_, err := ReadLine(reader, 5, false)
	if !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("expected ErrLineTooLong, got %v", err)
	}

	result, err := ReadLine(reader, 512, false)
	if err != nil {
		t.Fatalf("ReadLine after multi-chunk drain: unexpected error: %v", err)
	}
	if result != "DONE" {
		t.Errorf("ReadLine after multi-chunk drain: got %q, want %q", result, "DONE")
	}
}

// FuzzReadLine fuzz-tests ReadLine for panics and verifies key invariants:
// - result contains no CR or LF
// - result length never exceeds max
// - enforce=true never returns non-ASCII bytes
func FuzzReadLine(f *testing.F) {
	f.Add("EHLO localhost\r\n", 512, false, 16)
	f.Add("\r\n", 512, false, 16)
	f.Add("MAIL FROM:<user@example.com>\r\n", 512, false, 4)
	f.Add("hello\n", 512, false, 8)
	f.Add("hello\x80world\r\n", 512, true, 4)
	f.Add(strings.Repeat("A", 200)+"\r\n", 100, false, 8)
	f.Add("", 512, false, 8)
	f.Add("\r\n", 1, false, 4)
	f.Add("QUIT\r\n", 512, true, 512)

	f.Fuzz(func(t *testing.T, input string, max int, enforce bool, bufSize int) {
		if max <= 0 || max > 1<<20 {
			max = 512
		}
		if bufSize < 1 || bufSize > 4096 {
			bufSize = 16
		}
		reader := bufio.NewReaderSize(strings.NewReader(input), bufSize)
		result, err := ReadLine(reader, max, enforce)
		if err != nil {
			return
		}
		// Invariant 1: if enforce=true, every byte in result must be <= 127.
		if enforce {
			for i := 0; i < len(result); i++ {
				if result[i] > 127 {
					t.Errorf("ReadLine(enforce=true) returned non-ASCII byte at position %d in %q", i, result)
					return
				}
			}
		}
		// Invariant 2: result must not contain raw CR or LF characters.
		if strings.ContainsAny(result, "\r\n") {
			t.Errorf("ReadLine() result contains CR or LF: %q", result)
		}
		// Invariant 3: result byte length must not exceed max.
		if len(result) > max {
			t.Errorf("ReadLine() result length %d exceeds max %d: %q", len(result), max, result)
		}
	})
}

// FuzzContainsNonASCII verifies ContainsNonASCII is consistent with a direct
// byte-level check: any byte > 127 implies non-ASCII and vice versa.
func FuzzContainsNonASCII(f *testing.F) {
	f.Add("hello")
	f.Add("hello w\xc3\xb6rld") // ö in UTF-8
	f.Add("")
	f.Add(string([]byte{127}))
	f.Add(string([]byte{128}))
	f.Add("user@example.com")
	f.Add("\x00\x7f")
	f.Add("\xff")

	f.Fuzz(func(t *testing.T, s string) {
		result := ContainsNonASCII(s)

		// Ground truth: presence of any byte > 127.
		hasHighByte := false
		for i := 0; i < len(s); i++ {
			if s[i] > 127 {
				hasHighByte = true
				break
			}
		}
		if result != hasHighByte {
			t.Errorf("ContainsNonASCII(%q) = %v, byte-level check = %v", s, result, hasHighByte)
		}
	})
}

// FuzzValidateAndConvert fuzz-tests validateAndConvert for panics and checks
// that on success the result equals the input stripped of its trailing CRLF.
func FuzzValidateAndConvert(f *testing.F) {
	f.Add([]byte("EHLO localhost\r\n"), 512)
	f.Add([]byte("\r\n"), 512)
	f.Add([]byte("hello\n"), 512)
	f.Add([]byte{}, 512)
	f.Add([]byte("x"), 512)
	f.Add([]byte("ab\r\n"), 2)
	f.Add([]byte("ab\r\n"), 4)
	f.Add([]byte("\r\n"), 2)

	f.Fuzz(func(t *testing.T, b []byte, max int) {
		if max <= 0 || max > 1<<20 {
			max = 512
		}
		result, err := validateAndConvert(b, max)
		if err != nil {
			return
		}
		// On success: input must end with CRLF.
		if len(b) < 2 || b[len(b)-2] != '\r' || b[len(b)-1] != '\n' {
			t.Errorf("validateAndConvert succeeded but input %q does not end in CRLF", b)
			return
		}
		// On success: result must equal input without trailing CRLF.
		want := string(b[:len(b)-2])
		if result != want {
			t.Errorf("validateAndConvert() = %q, want %q", result, want)
		}
		// On success: result byte length must not exceed max.
		if len(result) > max {
			t.Errorf("validateAndConvert() result length %d exceeds max %d", len(result), max)
		}
	})
}

// FuzzIsASCIIConsistency checks that the unexported isASCII is the logical
// complement of ContainsNonASCII: isASCII(b) == !ContainsNonASCII(string(b)).
func FuzzIsASCIIConsistency(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte{0x80})
	f.Add([]byte{127})
	f.Add([]byte{})
	f.Add([]byte("hello\x00world"))
	f.Add([]byte{0xC3, 0xA4}) // ä in UTF-8

	f.Fuzz(func(t *testing.T, b []byte) {
		ascii := isASCII(b)
		nonASCII := ContainsNonASCII(string(b))
		// The two functions check the same criterion from different angles.
		if ascii == nonASCII {
			t.Errorf("isASCII(%q) = %v but ContainsNonASCII(%q) = %v; expected complements",
				b, ascii, string(b), nonASCII)
		}
	})
}
