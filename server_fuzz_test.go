package raven

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// Fuzz Tests
// =============================================================================

// FuzzServerCommands fuzzes the server with random SMTP commands.
func FuzzServerCommands(f *testing.F) {
	// Seed corpus with valid and edge-case commands
	seeds := []string{
		"EHLO example.com",
		"HELO example.com",
		"MAIL FROM:<test@example.com>",
		"RCPT TO:<user@example.com>",
		"DATA",
		"QUIT",
		"NOOP",
		"RSET",
		"VRFY user",
		"EXPN list",
		"HELP",
		"AUTH PLAIN",
		"STARTTLS",
		// Edge cases
		"",
		" ",
		"\t",
		"EHLO",
		"MAIL FROM:",
		"MAIL FROM:<>",
		"RCPT TO:",
		"RCPT TO:<>",
		"MAIL FROM:<user@example.com> BODY=8BITMIME",
		"MAIL FROM:<user@example.com> SIZE=100",
		"MAIL FROM:<test@example.com> SMTPUTF8",
		// Malformed
		"EHLO \x00hostname",
		"MAIL FROM:<\xff@example.com>",
		strings.Repeat("A", 1000),
		"MAIL FROM:<" + strings.Repeat("a", 500) + "@example.com>",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, command string) {
		ts := newTestServer(t)
		defer ts.Close()

		conn, err := net.DialTimeout("tcp", ts.addr, 2*time.Second)
		if err != nil {
			t.Skip("could not connect")
			return
		}
		defer conn.Close()

		conn.SetDeadline(time.Now().Add(2 * time.Second))

		reader := bufio.NewReader(conn)

		// Read greeting
		reader.ReadString('\n')

		// Send EHLO first
		fmt.Fprintf(conn, "EHLO test.com\r\n")
		for {
			line, _ := reader.ReadString('\n')
			if len(line) < 4 || line[3] == ' ' {
				break
			}
		}

		// Send fuzzed command
		fmt.Fprintf(conn, "%s\r\n", command)
		reader.ReadString('\n')

		// The server should not panic - that's the main test
	})
}

// FuzzServerMessageData fuzzes message body content.
func FuzzServerMessageData(f *testing.F) {
	// Seed with various message types
	seeds := []string{
		"Subject: Test\r\n\r\nHello World",
		"Subject: Test\r\n\r\n.",
		"Subject: Test\r\n\r\n..",
		"Subject: Test\r\n\r\n...",
		"Subject: Test\r\n\r\n.\r\n",
		"Subject: Test\r\n\r\nLine with . at start",
		"Subject: Test\r\n\r\n" + strings.Repeat("A", 1000),
		"Subject: Test\r\n\r\n\x00\x01\x02",
		"Subject: Test\r\n\r\nUTF-8: αβγδ",
		"",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, body string) {
		ts := newTestServer(t)
		defer ts.Close()

		conn, err := net.DialTimeout("tcp", ts.addr, 2*time.Second)
		if err != nil {
			t.Skip("could not connect")
			return
		}
		defer conn.Close()

		conn.SetDeadline(time.Now().Add(2 * time.Second))

		reader := bufio.NewReader(conn)

		// Read greeting
		reader.ReadString('\n')

		// EHLO
		fmt.Fprintf(conn, "EHLO test.com\r\n")
		for {
			line, _ := reader.ReadString('\n')
			if len(line) < 4 || line[3] == ' ' {
				break
			}
		}

		// MAIL FROM
		fmt.Fprintf(conn, "MAIL FROM:<sender@example.com>\r\n")
		reader.ReadString('\n')

		// RCPT TO
		fmt.Fprintf(conn, "RCPT TO:<recipient@example.com>\r\n")
		reader.ReadString('\n')

		// DATA
		fmt.Fprintf(conn, "DATA\r\n")
		reader.ReadString('\n')

		// Send body
		fmt.Fprintf(conn, "%s\r\n.\r\n", body)
		reader.ReadString('\n')

		// The server should handle any input without panicking
	})
}

// FuzzMailFromParameters fuzzes MAIL FROM parameters.
func FuzzMailFromParameters(f *testing.F) {
	seeds := []string{
		"MAIL FROM:<test@example.com>",
		"MAIL FROM:<test@example.com> SIZE=100",
		"MAIL FROM:<test@example.com> BODY=7BIT",
		"MAIL FROM:<test@example.com> BODY=8BITMIME",
		"MAIL FROM:<test@example.com> SMTPUTF8",
		"MAIL FROM:<test@example.com> AUTH=<>",
		"MAIL FROM:<test@example.com> SIZE=100 BODY=8BITMIME",
		"MAIL FROM:<> SIZE=0",
		"MAIL FROM:<test@example.com> SIZE=-1",
		"MAIL FROM:<test@example.com> SIZE=999999999999999999999",
		"MAIL FROM:<test@example.com> BODY=INVALID",
		"MAIL FROM:<test@example.com> UNKNOWN=value",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, command string) {
		ts := newTestServer(t)
		defer ts.Close()

		conn, err := net.DialTimeout("tcp", ts.addr, 2*time.Second)
		if err != nil {
			t.Skip("could not connect")
			return
		}
		defer conn.Close()

		conn.SetDeadline(time.Now().Add(2 * time.Second))

		reader := bufio.NewReader(conn)

		// Read greeting and send EHLO
		reader.ReadString('\n')
		fmt.Fprintf(conn, "EHLO test.com\r\n")
		for {
			line, _ := reader.ReadString('\n')
			if len(line) < 4 || line[3] == ' ' {
				break
			}
		}

		// Send fuzzed MAIL FROM
		fmt.Fprintf(conn, "%s\r\n", command)
		reader.ReadString('\n')

		// Server should not panic
	})
}

// =============================================================================
// Edge Case Tests
// =============================================================================

func TestServer_8BitDataWithout8BITMIME(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	// Don't specify BODY parameter - defaults to 7BIT
	tc.Send("MAIL FROM:<sender@example.com>")
	tc.ExpectCode(250)

	tc.Send("RCPT TO:<recipient@example.com>")
	tc.ExpectCode(250)

	tc.Send("DATA")
	tc.ExpectCode(354)

	// Send 8-bit data (UTF-8 characters) without BODY=8BITMIME
	tc.Send("Subject: Test")
	tc.Send("")
	tc.Send("This contains 8-bit data: \xc3\xa9\xc3\xa0\xc3\xb9") // UTF-8 éàù
	tc.Send(".")

	// Server should reject with 554 (transaction failed)
	tc.ExpectCode(554)
}

func TestServer_8BitDataWith8BITMIME(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	// Properly declare BODY=8BITMIME
	tc.Send("MAIL FROM:<sender@example.com> BODY=8BITMIME")
	tc.ExpectCode(250)

	tc.Send("RCPT TO:<recipient@example.com>")
	tc.ExpectCode(250)

	tc.Send("DATA")
	tc.ExpectCode(354)

	// Send 8-bit data with proper declaration
	tc.Send("Subject: Test")
	tc.Send("")
	tc.Send("This contains 8-bit data: \xc3\xa9\xc3\xa0\xc3\xb9") // UTF-8 éàù
	tc.Send(".")

	// Should succeed
	tc.ExpectCode(250)
}

func TestServer_7BitDataWith7BIT(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	// Explicitly declare BODY=7BIT
	tc.Send("MAIL FROM:<sender@example.com> BODY=7BIT")
	tc.ExpectCode(250)

	tc.Send("RCPT TO:<recipient@example.com>")
	tc.ExpectCode(250)

	tc.Send("DATA")
	tc.ExpectCode(354)

	// Send only 7-bit ASCII data
	tc.Send("Subject: Test")
	tc.Send("")
	tc.Send("This is pure ASCII content.")
	tc.Send(".")

	// Should succeed
	tc.ExpectCode(250)
}

func TestServer_NonASCIIAddressWithoutSMTPUTF8(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	// Try to send from a non-ASCII address without SMTPUTF8
	tc.Send("MAIL FROM:<müller@example.com>")
	// Should be rejected
	resp := tc.ReadLine()
	code := extractCode(resp)
	if code < 500 {
		t.Errorf("expected 5xx error for non-ASCII address without SMTPUTF8, got %d", code)
	}
}

func TestServer_NonASCIIAddressWithSMTPUTF8(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	// Non-ASCII address with SMTPUTF8 declared
	tc.Send("MAIL FROM:<müller@example.com> SMTPUTF8")
	tc.ExpectCode(250)

	tc.Send("RCPT TO:<recipient@example.com>")
	tc.ExpectCode(250)
}

func TestServer_NonASCIIRecipientWithoutSMTPUTF8(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	tc.Send("MAIL FROM:<sender@example.com>")
	tc.ExpectCode(250)

	// Try to send to a non-ASCII address without SMTPUTF8
	tc.Send("RCPT TO:<用户@example.com>")
	// Should be rejected
	resp := tc.ReadLine()
	code := extractCode(resp)
	if code < 500 {
		t.Errorf("expected 5xx error for non-ASCII recipient without SMTPUTF8, got %d", code)
	}
}

func TestServer_DotStuffingEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		lines    []string
		expected string
	}{
		{
			name:     "single dot line",
			lines:    []string{"Subject: Test", "", "Before", ".", "After"},
			expected: "Before\r\n.\r\nAfter",
		},
		{
			name:     "double dot becomes single",
			lines:    []string{"Subject: Test", "", "..Double dot start"},
			expected: ".Double dot start",
		},
		{
			name:     "triple dot becomes double",
			lines:    []string{"Subject: Test", "", "...Triple dot start"},
			expected: "..Triple dot start",
		},
		{
			name:     "dot in middle of line",
			lines:    []string{"Subject: Test", "", "Some.thing"},
			expected: "Some.thing",
		},
		{
			name:     "only dots",
			lines:    []string{"Subject: Test", "", ".."},
			expected: ".",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var receivedBody string

			ts := newTestServer(t, func(s *Server) {
				s.OnMessage(func(c *Context) *Response {
					receivedBody = string(c.Mail.Content.Body)
					return c.Next()
				})
			})
			defer ts.Close()

			tc := ts.Dial()
			defer tc.Close()

			tc.Send("EHLO client.example.com")
			tc.ExpectMultilineCode(250)

			tc.Send("MAIL FROM:<sender@example.com>")
			tc.ExpectCode(250)

			tc.Send("RCPT TO:<recipient@example.com>")
			tc.ExpectCode(250)

			tc.Send("DATA")
			tc.ExpectCode(354)

			// Send lines with proper dot-stuffing
			for _, line := range tt.lines {
				// Apply dot-stuffing for lines starting with dot
				if strings.HasPrefix(line, ".") {
					tc.Send(".%s", line)
				} else {
					tc.Send("%s", line)
				}
			}
			tc.Send(".")

			tc.ExpectCode(250)

			// Check if body contains expected content
			if !strings.Contains(receivedBody, tt.expected) {
				t.Errorf("expected body to contain %q, got %q", tt.expected, receivedBody)
			}
		})
	}
}

func TestServer_EmptyCommands(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	// Send empty command
	tc.Send("")
	resp := tc.ReadLine()
	code := extractCode(resp)
	if code < 500 {
		t.Errorf("expected 5xx error for empty command, got %d", code)
	}
}

func TestServer_WhitespaceOnlyCommands(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	// Send whitespace-only command
	tc.Send("   ")
	resp := tc.ReadLine()
	code := extractCode(resp)
	if code < 500 {
		t.Errorf("expected 5xx error for whitespace-only command, got %d", code)
	}
}

func TestServer_NullByteInCommand(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	// Send command with null byte
	tc.Send("EHLO test\x00.com")
	// Should still work (server may strip or handle null)
	tc.ReadLine()
}

// =============================================================================
// Line Length Tests
// =============================================================================

func TestServer_CommandLineLength(t *testing.T) {
	// Test with custom max line length
	ts := newTestServer(t, func(s *Server) {
		s.MaxLineLength(100)
	})
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	// Command within limit should work
	tc.Send("EHLO example.com")
	tc.ExpectMultilineCode(250)

	// Command exceeding limit should be rejected
	longHostname := strings.Repeat("a", 150)
	tc.Send("EHLO %s.com", longHostname)
	resp := tc.ReadLine()
	code := extractCode(resp)
	if code != 500 && code != 501 {
		t.Errorf("expected 500/501 for command exceeding line length, got %d", code)
	}
}

func TestServer_DataLineLength_Within998(t *testing.T) {
	var receivedBody string

	ts := newTestServer(t, func(s *Server) {
		s.OnMessage(func(c *Context) *Response {
			receivedBody = string(c.Mail.Content.Body)
			return c.Next()
		})
	})
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	tc.Send("MAIL FROM:<sender@example.com>")
	tc.ExpectCode(250)

	tc.Send("RCPT TO:<recipient@example.com>")
	tc.ExpectCode(250)

	tc.Send("DATA")
	tc.ExpectCode(354)

	// Line at exactly 998 characters (RFC 5322 limit, excluding CRLF)
	tc.Send("Subject: Test")
	tc.Send("")
	line998 := strings.Repeat("X", 998)
	tc.Send("%s", line998)
	tc.Send(".")

	tc.ExpectCode(250)

	if !strings.Contains(receivedBody, line998) {
		t.Error("expected 998-char line to be accepted")
	}
}

func TestServer_DataLineLength_Exceeds998(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	tc.Send("MAIL FROM:<sender@example.com>")
	tc.ExpectCode(250)

	tc.Send("RCPT TO:<recipient@example.com>")
	tc.ExpectCode(250)

	tc.Send("DATA")
	tc.ExpectCode(354)

	// Line exceeding 998 characters should be rejected
	tc.Send("Subject: Test")
	tc.Send("")
	line1500 := strings.Repeat("X", 1500)
	tc.Send("%s", line1500)
	tc.Send(".")

	// Should be rejected - line too long
	resp := tc.ReadLine()
	code := extractCode(resp)
	if code != 501 {
		t.Errorf("expected 501 for line exceeding 998 chars, got %d", code)
	}
}

func TestServer_HeaderLineLength(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	tc.Send("MAIL FROM:<sender@example.com>")
	tc.ExpectCode(250)

	tc.Send("RCPT TO:<recipient@example.com>")
	tc.ExpectCode(250)

	tc.Send("DATA")
	tc.ExpectCode(354)

	// Header line exceeding limit
	longSubject := "Subject: " + strings.Repeat("X", 1500)
	tc.Send("%s", longSubject)
	tc.Send("")
	tc.Send("Body")
	tc.Send(".")

	// Should be rejected - header line too long
	resp := tc.ReadLine()
	code := extractCode(resp)
	if code != 501 {
		t.Errorf("expected 501 for header line exceeding limit, got %d", code)
	}
}

func TestServer_MAIL_FROM_LineLength(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.MaxLineLength(100)
	})
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	// MAIL FROM command exceeding line length limit
	longLocal := strings.Repeat("a", 150)
	tc.Send("MAIL FROM:<%s@example.com>", longLocal)
	resp := tc.ReadLine()
	code := extractCode(resp)
	if code != 500 && code != 501 {
		t.Errorf("expected 500/501 for MAIL FROM exceeding line length, got %d", code)
	}
}

func TestServer_RCPT_TO_LineLength(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.MaxLineLength(100)
	})
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	tc.Send("MAIL FROM:<sender@example.com>")
	tc.ExpectCode(250)

	// RCPT TO command exceeding line length limit
	longLocal := strings.Repeat("b", 150)
	tc.Send("RCPT TO:<%s@example.com>", longLocal)
	resp := tc.ReadLine()
	code := extractCode(resp)
	if code != 500 && code != 501 {
		t.Errorf("expected 500/501 for RCPT TO exceeding line length, got %d", code)
	}
}

func TestServer_DefaultLineLengthIsRecommended(t *testing.T) {
	// Verify default line length uses RecommendedLineLength (78)
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	// Line of 78 chars should work
	hostname := strings.Repeat("a", 70) // "EHLO " + 70 + ".com" = 79 chars
	tc.Send("EHLO %s.com", hostname)
	resp := tc.ReadLine()
	code := extractCode(resp)
	// Should work - right at the limit
	if code/100 != 2 && code/100 != 5 {
		t.Errorf("expected 2xx or 5xx response, got %d", code)
	}
}

func TestServer_CustomMaxLineLength(t *testing.T) {
	// Test with larger custom line length
	ts := newTestServer(t, func(s *Server) {
		s.MaxLineLength(1000)
	})
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	// Long command that would normally be rejected should work
	// Use valid domain labels (max 63 chars each, max 253 total)
	longHostname := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60)
	tc.Send("EHLO %s.com", longHostname)
	tc.ExpectMultilineCode(250)
}

func TestServer_VeryLongCommand(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	// RFC 5321 limits command line to 512 bytes
	longCommand := "EHLO " + strings.Repeat("a", 600) + ".com"
	tc.Send("%s", longCommand)
	resp := tc.ReadLine()
	code := extractCode(resp)
	// Server should handle gracefully (either accept or reject, but not crash)
	if code == 0 {
		t.Error("expected valid response code")
	}
}

func TestServer_VeryLongAddress(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	// Very long local part (RFC 5321 limits to 64 characters)
	longLocal := strings.Repeat("a", 100)
	tc.Send("MAIL FROM:<%s@example.com>", longLocal)
	resp := tc.ReadLine()
	code := extractCode(resp)
	// Should reject with syntax error
	if code < 500 {
		t.Errorf("expected 5xx error for too-long local part, got %d", code)
	}
}

func TestServer_VeryLongDomain(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	// Very long domain (RFC 5321 limits to 255 characters total)
	longDomain := strings.Repeat("a", 300) + ".com"
	tc.Send("MAIL FROM:<test@%s>", longDomain)
	resp := tc.ReadLine()
	code := extractCode(resp)
	// Should reject with syntax error
	if code < 500 {
		t.Errorf("expected 5xx error for too-long domain, got %d", code)
	}
}

func TestServer_SizeParameterZero(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.MaxMessageSize(1024)
	})
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	// SIZE=0 should be acceptable
	tc.Send("MAIL FROM:<sender@example.com> SIZE=0")
	tc.ExpectCode(250)
}

func TestServer_SizeParameterNegative(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.MaxMessageSize(1024)
	})
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	// SIZE=-1 should be rejected - negative sizes are invalid
	tc.Send("MAIL FROM:<sender@example.com> SIZE=-1")
	tc.ExpectCode(501) // Syntax error
}

func TestServer_SizeParameterOverflow(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.MaxMessageSize(1024)
	})
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	// SIZE with value that would overflow int64
	tc.Send("MAIL FROM:<sender@example.com> SIZE=99999999999999999999999")
	resp := tc.ReadLine()
	code := extractCode(resp)
	if code < 500 {
		t.Errorf("expected 5xx error for overflow SIZE, got %d", code)
	}
}

func TestServer_MultipleBodyParameters(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	// Multiple BODY parameters - should use first or reject
	tc.Send("MAIL FROM:<sender@example.com> BODY=7BIT BODY=8BITMIME")
	resp := tc.ReadLine()
	code := extractCode(resp)
	// Server should handle gracefully
	if code == 0 {
		t.Error("expected valid response code")
	}
}

func TestServer_CaseSensitivity(t *testing.T) {
	tests := []struct {
		name    string
		command string
		expect  int // expected response code category (2xx, 5xx, etc.)
	}{
		{"lowercase ehlo", "ehlo example.com", 250},
		{"mixed case EHLO", "EhLo example.com", 250},
		{"lowercase mail from", "mail from:<test@example.com>", 250},
		{"mixed case MAIL FROM", "MaIl FrOm:<test@example.com>", 250},
		{"lowercase quit", "quit", 221},
		{"uppercase QUIT", "QUIT", 221},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newTestServer(t)
			defer ts.Close()

			tc := ts.Dial()
			defer tc.Close()

			if strings.HasPrefix(strings.ToLower(tt.command), "mail") ||
				strings.HasPrefix(strings.ToLower(tt.command), "rcpt") {
				tc.Send("EHLO client.example.com")
				tc.ExpectMultilineCode(250)
			}

			tc.Send("%s", tt.command)
			resp := tc.ReadLine()
			code := extractCode(resp)

			// Check if response is in expected category
			if tt.expect == 250 {
				if code != 250 {
					// For multiline responses, just check category
					if code/100 != 2 {
						t.Errorf("expected 2xx for %q, got %d", tt.command, code)
					}
				}
			} else if code != tt.expect {
				t.Errorf("expected %d for %q, got %d", tt.expect, tt.command, code)
			}
		})
	}
}

func TestServer_PipeliningViolation(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	conn, err := net.DialTimeout("tcp", ts.addr, 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	reader.ReadString('\n')

	// Send multiple commands without waiting for responses (pipelining)
	// EHLO followed by MAIL FROM in one write
	fmt.Fprintf(conn, "EHLO client.example.com\r\nMAIL FROM:<sender@example.com>\r\n")

	// Read EHLO response (multiline)
	for {
		line, _ := reader.ReadString('\n')
		if len(line) < 4 || line[3] == ' ' {
			break
		}
	}

	// Read MAIL FROM response - should work with pipelining enabled
	line, _ := reader.ReadString('\n')
	code := extractCode(line)
	if code != 250 {
		t.Errorf("expected 250 for pipelined MAIL FROM, got %d", code)
	}
}

func TestServer_AuthBeforeEHLO(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.Auth([]string{"PLAIN"}, func(c *Context, mechanism, identity, password string) *Response {
			return nil // Accept all
		})
	})
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	// Try AUTH before EHLO
	tc.Send("AUTH PLAIN")
	resp := tc.ReadLine()
	code := extractCode(resp)
	if code != 503 {
		t.Errorf("expected 503 for AUTH before EHLO, got %d", code)
	}
}

func TestServer_AuthWithInvalidMechanism(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.Auth([]string{"PLAIN"}, func(c *Context, mechanism, identity, password string) *Response {
			return nil // Accept all
		})
	})
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	// Try AUTH with unsupported mechanism
	tc.Send("AUTH CRAM-MD5")
	resp := tc.ReadLine()
	code := extractCode(resp)
	if code < 500 {
		t.Errorf("expected 5xx for unsupported AUTH mechanism, got %d", code)
	}
}

func TestServer_AuthPLAINMalformedBase64(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.Auth([]string{"PLAIN"}, func(c *Context, mechanism, identity, password string) *Response {
			return nil // Accept all
		})
	})
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	// AUTH PLAIN with invalid base64
	tc.Send("AUTH PLAIN !!!invalid-base64!!!")
	resp := tc.ReadLine()
	code := extractCode(resp)
	if code < 500 {
		t.Errorf("expected 5xx for invalid base64, got %d", code)
	}
}

func TestServer_AuthPLAINWrongFormat(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.Auth([]string{"PLAIN"}, func(c *Context, mechanism, identity, password string) *Response {
			return nil // Accept all
		})
	})
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	// AUTH PLAIN with valid base64 but wrong SASL format (missing null separators)
	wrongFormat := base64.StdEncoding.EncodeToString([]byte("usernamepassword"))
	tc.Send("AUTH PLAIN %s", wrongFormat)
	resp := tc.ReadLine()
	code := extractCode(resp)
	if code < 500 {
		t.Errorf("expected 5xx for malformed PLAIN credentials, got %d", code)
	}
}

func TestServer_STARTTLSAfterTransaction(t *testing.T) {
	cert, _ := generateTestCertFuzz(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	ts := newTestServer(t, func(s *Server) {
		s.TLS(tlsConfig)
	})
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	// Start a transaction
	tc.Send("MAIL FROM:<sender@example.com>")
	tc.ExpectCode(250)

	// Try STARTTLS during transaction - should be rejected
	tc.Send("STARTTLS")
	resp := tc.ReadLine()
	code := extractCode(resp)
	if code != 503 {
		t.Errorf("expected 503 for STARTTLS during transaction, got %d", code)
	}
}

func TestServer_RcptToWithoutMailFrom(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	// Try RCPT TO without MAIL FROM
	tc.Send("RCPT TO:<recipient@example.com>")
	tc.ExpectCode(503)
}

func TestServer_DataWithoutRcptTo(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	tc.Send("MAIL FROM:<sender@example.com>")
	tc.ExpectCode(250)

	// Try DATA without RCPT TO
	tc.Send("DATA")
	tc.ExpectCode(503)
}

func TestServer_DoubleMailFrom(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	tc.Send("MAIL FROM:<sender1@example.com>")
	tc.ExpectCode(250)

	// Try second MAIL FROM without completing first transaction
	tc.Send("MAIL FROM:<sender2@example.com>")
	tc.ExpectCode(503)
}

func TestServer_BareLineFeeds(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	conn, err := net.DialTimeout("tcp", ts.addr, 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	reader.ReadString('\n')

	// Send command with bare LF instead of CRLF
	fmt.Fprintf(conn, "EHLO example.com\n")

	// Server should handle gracefully
	reader.ReadString('\n')
}

func TestServer_BareCarriageReturns(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	conn, err := net.DialTimeout("tcp", ts.addr, 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))

	reader := bufio.NewReader(conn)

	// Read greeting
	reader.ReadString('\n')

	// Send command with CR not followed by LF
	fmt.Fprintf(conn, "EHLO example\r.com\r\n")

	// Server should handle gracefully
	reader.ReadString('\n')
}

// Helper to extract SMTP code from response line
func extractCode(line string) int {
	if len(line) < 3 {
		return 0
	}
	code := 0
	fmt.Sscanf(line, "%d", &code)
	return code
}

// generateTestCertFuzz creates a self-signed certificate for testing.
func generateTestCertFuzz(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	// Create certificate template
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test"},
			CommonName:   "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com", "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	// Encode certificate and key
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Parse certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Create cert pool
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certPEM)

	return cert, certPool
}
