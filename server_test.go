package raven

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// testClient is a simple SMTP client for integration testing.
type testClient struct {
	conn   net.Conn
	reader *bufio.Reader
	t      *testing.T
}

func newTestClient(t *testing.T, addr string) *testClient {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	// Set default deadline
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	return &testClient{
		conn:   conn,
		reader: bufio.NewReader(conn),
		t:      t,
	}
}

func (c *testClient) close() {
	c.conn.Close()
}

func (c *testClient) send(cmd string) {
	_, err := c.conn.Write([]byte(cmd + "\r\n"))
	if err != nil {
		c.t.Fatalf("Failed to send command %q: %v", cmd, err)
	}
}

func (c *testClient) sendRaw(data []byte) {
	_, err := c.conn.Write(data)
	if err != nil {
		c.t.Fatalf("Failed to send raw data: %v", err)
	}
}

func (c *testClient) readLine() string {
	line, err := c.reader.ReadString('\n')
	if err != nil {
		c.t.Fatalf("Failed to read response: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

func (c *testClient) readMultiline() []string {
	var lines []string
	for {
		line := c.readLine()
		lines = append(lines, line)
		// Check if this is the last line (no dash after code)
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}
	return lines
}

func (c *testClient) expectCode(expectedCode int) string {
	line := c.readLine()
	code := 0
	fmt.Sscanf(line, "%d", &code)
	if code != expectedCode {
		c.t.Errorf("Expected code %d, got response: %s", expectedCode, line)
	}
	return line
}

func (c *testClient) expectMultilineCode(expectedCode int) []string {
	lines := c.readMultiline()
	if len(lines) == 0 {
		c.t.Fatalf("Expected multiline response with code %d, got empty", expectedCode)
	}
	code := 0
	fmt.Sscanf(lines[len(lines)-1], "%d", &code)
	if code != expectedCode {
		c.t.Errorf("Expected code %d, got response: %v", expectedCode, lines)
	}
	return lines
}

// discardLogger returns a logger that discards all output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testServerConfig returns a ServerConfig with default values suitable for testing.
func testServerConfig() ServerConfig {
	return ServerConfig{}
}

// startTestServer starts a test server on a random port and returns the server and address.
func startTestServer(t *testing.T, config ServerConfig) (*Server, string) {
	// Find a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find free port: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	config.Addr = addr
	if config.Hostname == "" {
		config.Hostname = "test.example.com"
	}
	// Disable logging in tests
	config.Logger = discardLogger()

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	go func() {
		_ = server.ListenAndServe()
	}()

	// Wait for server to start
	for range 50 {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	return server, addr
}

// ============================================================================
// Basic SMTP Session Tests
// ============================================================================

func TestBasicSMTPSession(t *testing.T) {
	var receivedMail *Mail
	var mu sync.Mutex

	config := testServerConfig()
	config.Callbacks = &Callbacks{
		OnMessage: func(ctx context.Context, conn *Connection, mail *Mail) error {
			mu.Lock()
			receivedMail = mail
			mu.Unlock()
			return nil
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	// Read greeting
	client.expectCode(220)

	// EHLO
	client.send("EHLO client.example.com")
	lines := client.expectMultilineCode(250)
	if len(lines) < 2 {
		t.Errorf("Expected multiple EHLO response lines, got %d", len(lines))
	}

	// MAIL FROM
	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(250)

	// RCPT TO
	client.send("RCPT TO:<recipient@example.com>")
	client.expectCode(250)

	// DATA
	client.send("DATA")
	client.expectCode(354)

	// Send message content
	client.send("Subject: Test Message")
	client.send("From: sender@example.com")
	client.send("To: recipient@example.com")
	client.send("")
	client.send("This is a test message.")
	client.send(".")
	client.expectCode(250)

	// QUIT
	client.send("QUIT")
	client.expectCode(221)

	// Verify received mail
	mu.Lock()
	if receivedMail == nil {
		t.Error("Expected to receive mail, but got nil")
	} else {
		if receivedMail.Envelope.From.Mailbox.String() != "sender@example.com" {
			t.Errorf("Expected from sender@example.com, got %s", receivedMail.Envelope.From.Mailbox.String())
		}
		if len(receivedMail.Envelope.To) != 1 {
			t.Errorf("Expected 1 recipient, got %d", len(receivedMail.Envelope.To))
		}
		if receivedMail.Envelope.To[0].Address.Mailbox.String() != "recipient@example.com" {
			t.Errorf("Expected to recipient@example.com, got %s", receivedMail.Envelope.To[0].Address.Mailbox.String())
		}
	}
	mu.Unlock()
}

// TestDATANoTrailingNewline verifies that the DATA command does not append
// an extra trailing CRLF at the end of the message. Per RFC 5321, each line
// should end with CRLF, but there should be no additional CRLF after the
// last line of the message body.
func TestDATANoTrailingNewline(t *testing.T) {
	var receivedMail *Mail
	var mu sync.Mutex

	config := testServerConfig()
	config.Callbacks = &Callbacks{
		OnMessage: func(ctx context.Context, conn *Connection, mail *Mail) error {
			mu.Lock()
			receivedMail = mail
			mu.Unlock()
			return nil
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)
	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(250)
	client.send("RCPT TO:<recipient@example.com>")
	client.expectCode(250)
	client.send("DATA")
	client.expectCode(354)

	// Send message content - note the body ends with "Last line" with no blank line after
	client.send("Subject: Test")
	client.send("")
	client.send("First line")
	client.send("Last line")
	client.send(".")
	client.expectCode(250)

	client.send("QUIT")
	client.expectCode(221)

	// Verify the raw content
	mu.Lock()
	defer mu.Unlock()

	if receivedMail == nil {
		t.Fatal("Expected to receive mail, but got nil")
	}

	raw := receivedMail.Content.ToRaw()

	// The expected raw content (excluding the Received header which is prepended)
	// After the Received header, we expect:
	// "Subject: Test\r\n\r\nFirst line\r\nLast line\r\n"
	//
	// The message should NOT end with "\r\n\r\n" (double CRLF)
	// It should end with exactly one CRLF after "Last line"

	rawStr := string(raw)

	// Check that the message does not end with double CRLF
	if strings.HasSuffix(rawStr, "\r\n\r\n") {
		t.Errorf("Message should not end with double CRLF (trailing newline), got: %q", rawStr[len(rawStr)-20:])
	}

	// Check that the message ends with single CRLF (after "Last line")
	if !strings.HasSuffix(rawStr, "Last line\r\n") {
		t.Errorf("Message should end with 'Last line\\r\\n', got: %q", rawStr[len(rawStr)-20:])
	}

	// Additional check: verify body content is correctly formed
	if !strings.Contains(rawStr, "First line\r\nLast line\r\n") {
		t.Errorf("Body content malformed, got: %q", rawStr)
	}
}

// TestDATAPreservesTrailingBlankLine verifies that when a message intentionally
// ends with a blank line, it is preserved (as a single CRLF) but not doubled.
func TestDATAPreservesTrailingBlankLine(t *testing.T) {
	var receivedMail *Mail
	var mu sync.Mutex

	config := testServerConfig()
	config.Callbacks = &Callbacks{
		OnMessage: func(ctx context.Context, conn *Connection, mail *Mail) error {
			mu.Lock()
			receivedMail = mail
			mu.Unlock()
			return nil
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)
	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(250)
	client.send("RCPT TO:<recipient@example.com>")
	client.expectCode(250)
	client.send("DATA")
	client.expectCode(354)

	// Send message content with an intentional blank line at the end of body
	client.send("Subject: Test")
	client.send("")
	client.send("Body content")
	client.send("") // Intentional blank line at end of body
	client.send(".")
	client.expectCode(250)

	client.send("QUIT")
	client.expectCode(221)

	mu.Lock()
	defer mu.Unlock()

	if receivedMail == nil {
		t.Fatal("Expected to receive mail, but got nil")
	}

	rawStr := string(receivedMail.Content.ToRaw())

	// The body should end with "Body content\r\n\r\n" (content + blank line)
	// but NOT "Body content\r\n\r\n\r\n" (content + blank line + extra)
	if !strings.HasSuffix(rawStr, "Body content\r\n\r\n") {
		t.Errorf("Message body should end with 'Body content\\r\\n\\r\\n', got suffix: %q", rawStr[len(rawStr)-30:])
	}

	// Count trailing CRLFs to ensure there's exactly 2 (one for "Body content", one for blank line)
	suffix := rawStr[len(rawStr)-6:]
	if suffix != "nt\r\n\r\n" { // "content\r\n\r\n" ending
		t.Errorf("Unexpected suffix, expected 'nt\\r\\n\\r\\n', got: %q", suffix)
	}
}

// TestDATALineLengthRFC5322 verifies that the server enforces RFC 5322
// line length limits (998 characters max, excluding CRLF) for DATA content.
func TestDATALineLengthRFC5322(t *testing.T) {
	config := testServerConfig()
	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)
	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(250)
	client.send("RCPT TO:<recipient@example.com>")
	client.expectCode(250)
	client.send("DATA")
	client.expectCode(354)

	// Send headers
	client.send("Subject: Test")
	client.send("")

	// Send a line that exceeds 998 characters (RFC 5322 limit)
	longLine := make([]byte, 1000)
	for i := range longLine {
		longLine[i] = 'a'
	}
	client.send(string(longLine))
	client.send(".")

	// Server should reject with syntax error (501) due to line too long
	resp := client.readLine()
	code := 0
	fmt.Sscanf(resp, "%d", &code)
	if code != 501 {
		t.Errorf("Expected error code 501 for line too long, got: %s", resp)
	}
}

// TestDATALineLengthAtLimit verifies that lines exactly at 998 chars are accepted.
func TestDATALineLengthAtLimit(t *testing.T) {
	var receivedMail *Mail
	var mu sync.Mutex

	config := testServerConfig()
	config.Callbacks = &Callbacks{
		OnMessage: func(ctx context.Context, conn *Connection, mail *Mail) error {
			mu.Lock()
			receivedMail = mail
			mu.Unlock()
			return nil
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)
	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(250)
	client.send("RCPT TO:<recipient@example.com>")
	client.expectCode(250)
	client.send("DATA")
	client.expectCode(354)

	// Send headers
	client.send("Subject: Test")
	client.send("")

	// Send a line exactly at 998 characters (RFC 5322 limit)
	line998 := make([]byte, 998)
	for i := range line998 {
		line998[i] = 'b'
	}
	client.send(string(line998))
	client.send(".")
	client.expectCode(250)

	client.send("QUIT")
	client.expectCode(221)

	mu.Lock()
	defer mu.Unlock()

	if receivedMail == nil {
		t.Fatal("Expected to receive mail with 998-char line")
	}
}

func TestHELO(t *testing.T) {
	config := testServerConfig()
	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("HELO client.example.com")
	client.expectCode(250) // Single line response for HELO

	// Should be able to proceed with transaction
	client.send("MAIL FROM:<test@example.com>")
	client.expectCode(250)
}

func TestMultipleRecipients(t *testing.T) {
	var receivedMail *Mail
	var mu sync.Mutex

	config := testServerConfig()
	config.Callbacks = &Callbacks{
		OnMessage: func(ctx context.Context, conn *Connection, mail *Mail) error {
			mu.Lock()
			receivedMail = mail
			mu.Unlock()
			return nil
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)
	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(250)

	// Multiple recipients
	client.send("RCPT TO:<rcpt1@example.com>")
	client.expectCode(250)
	client.send("RCPT TO:<rcpt2@example.com>")
	client.expectCode(250)
	client.send("RCPT TO:<rcpt3@example.com>")
	client.expectCode(250)

	client.send("DATA")
	client.expectCode(354)
	client.send("Subject: Multi-recipient test")
	client.send("")
	client.send("Body")
	client.send(".")
	client.expectCode(250)

	client.send("QUIT")
	client.expectCode(221)

	mu.Lock()
	if receivedMail == nil {
		t.Error("Expected to receive mail")
	} else if len(receivedMail.Envelope.To) != 3 {
		t.Errorf("Expected 3 recipients, got %d", len(receivedMail.Envelope.To))
	}
	mu.Unlock()
}

func TestRSET(t *testing.T) {
	config := testServerConfig()
	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	// Start transaction
	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(250)
	client.send("RCPT TO:<recipient@example.com>")
	client.expectCode(250)

	// Reset
	client.send("RSET")
	client.expectCode(250)

	// Should need MAIL FROM again
	client.send("RCPT TO:<recipient@example.com>")
	client.expectCode(503) // Bad sequence

	// Start new transaction
	client.send("MAIL FROM:<another@example.com>")
	client.expectCode(250)

	client.send("QUIT")
	client.expectCode(221)
}

func TestNOOP(t *testing.T) {
	config := testServerConfig()
	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("NOOP")
	client.expectCode(250)

	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	client.send("NOOP")
	client.expectCode(250)

	client.send("QUIT")
	client.expectCode(221)
}

func TestHELP(t *testing.T) {
	config := testServerConfig()
	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)

	// General HELP (no topic) - should return multiline response
	client.send("HELP")
	lines := client.expectMultilineCode(214)
	if len(lines) < 2 {
		t.Errorf("Expected multiline HELP response, got %d lines", len(lines))
	}
	// Check that it contains the project URL
	found := false
	for _, line := range lines {
		if strings.Contains(line, "github.com/synqronlabs/raven") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected HELP response to contain project URL")
	}

	// Topic-specific HELP
	client.send("HELP MAIL")
	resp := client.expectCode(214)
	if !strings.Contains(resp, "MAIL FROM") {
		t.Errorf("Expected HELP MAIL to describe MAIL FROM command, got: %s", resp)
	}

	// Unknown topic
	client.send("HELP UNKNOWN")
	resp = client.expectCode(214)
	if !strings.Contains(resp, "No help available") {
		t.Errorf("Expected 'No help available' for unknown topic, got: %s", resp)
	}

	client.send("QUIT")
	client.expectCode(221)
}

func TestHELPCallback(t *testing.T) {
	config := testServerConfig()
	config.Callbacks = &Callbacks{
		OnHelp: func(ctx context.Context, conn *Connection, topic string) []string {
			if topic == "CUSTOM" {
				return []string{"This is custom help", "For the CUSTOM topic"}
			}
			return nil // Use default for other topics
		},
	}
	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)

	// Custom topic should use callback response
	client.send("HELP CUSTOM")
	lines := client.expectMultilineCode(214)
	if len(lines) != 2 {
		t.Errorf("Expected 2 lines from custom HELP, got %d", len(lines))
	}
	if !strings.Contains(lines[0], "custom help") {
		t.Errorf("Expected custom help response, got: %v", lines)
	}

	// Other topics should use default
	client.send("HELP MAIL")
	resp := client.expectCode(214)
	if !strings.Contains(resp, "MAIL FROM") {
		t.Errorf("Expected default HELP MAIL response, got: %s", resp)
	}

	client.send("QUIT")
	client.expectCode(221)
}

// ============================================================================
// Extension Tests - Intrinsic Extensions
// ============================================================================

func TestIntrinsicExtensionsAdvertised(t *testing.T) {
	config := testServerConfig()
	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	lines := client.expectMultilineCode(250)

	// Check for intrinsic extensions
	extensions := make(map[string]bool)
	for _, line := range lines {
		// Skip the greeting line
		if strings.Contains(line, "Hello") {
			continue
		}
		// Extract extension name (after 250- or 250 )
		parts := strings.SplitN(line, " ", 2)
		if len(parts) >= 1 {
			extLine := strings.TrimLeft(parts[0], "250-")
			extLine = strings.TrimLeft(extLine, "250 ")
			if len(parts) > 1 {
				extLine = parts[1]
			}
			extName := strings.Split(extLine, " ")[0]
			extensions[extName] = true
		}
	}

	// Verify intrinsic extensions are present
	intrinsicExts := []string{"8BITMIME", "PIPELINING", "SMTPUTF8", "ENHANCEDSTATUSCODES"}
	for _, ext := range intrinsicExts {
		found := false
		for _, line := range lines {
			if strings.Contains(line, ext) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected intrinsic extension %s to be advertised", ext)
		}
	}

	client.send("QUIT")
	client.expectCode(221)
}

func Test8BitMIME(t *testing.T) {
	var receivedMail *Mail
	var mu sync.Mutex

	config := testServerConfig()
	config.Callbacks = &Callbacks{
		OnMessage: func(ctx context.Context, conn *Connection, mail *Mail) error {
			mu.Lock()
			receivedMail = mail
			mu.Unlock()
			return nil
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	// Use BODY=8BITMIME parameter
	client.send("MAIL FROM:<sender@example.com> BODY=8BITMIME")
	client.expectCode(250)
	client.send("RCPT TO:<recipient@example.com>")
	client.expectCode(250)
	client.send("DATA")
	client.expectCode(354)
	client.send("Subject: 8-bit test")
	client.send("Content-Type: text/plain; charset=utf-8")
	client.send("")
	client.send("Hello with UTF-8: café résumé naïve")
	client.send(".")
	client.expectCode(250)

	mu.Lock()
	if receivedMail == nil {
		t.Error("Expected to receive mail")
	} else if receivedMail.Envelope.BodyType != BodyType8BitMIME {
		t.Errorf("Expected body type 8BITMIME, got %s", receivedMail.Envelope.BodyType)
	}
	mu.Unlock()

	client.send("QUIT")
	client.expectCode(221)
}

func TestSMTPUTF8(t *testing.T) {
	var receivedMail *Mail
	var mu sync.Mutex

	config := testServerConfig()
	config.Callbacks = &Callbacks{
		OnMessage: func(ctx context.Context, conn *Connection, mail *Mail) error {
			mu.Lock()
			receivedMail = mail
			mu.Unlock()
			return nil
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	// Use SMTPUTF8 parameter for internationalized email
	client.send("MAIL FROM:<sender@example.com> SMTPUTF8")
	client.expectCode(250)
	client.send("RCPT TO:<recipient@example.com>")
	client.expectCode(250)
	client.send("DATA")
	client.expectCode(354)
	client.send("Subject: UTF-8 test")
	client.send("")
	client.send("Body")
	client.send(".")
	client.expectCode(250)

	mu.Lock()
	if receivedMail == nil {
		t.Error("Expected to receive mail")
	} else if !receivedMail.Envelope.SMTPUTF8 {
		t.Error("Expected SMTPUTF8 flag to be set")
	}
	mu.Unlock()

	client.send("QUIT")
	client.expectCode(221)
}

func Test8BitDataRejectedWithout8BITMIME(t *testing.T) {
	config := testServerConfig()

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	// Send mail WITHOUT BODY=8BITMIME (defaults to 7BIT)
	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(250)
	client.send("RCPT TO:<recipient@example.com>")
	client.expectCode(250)
	client.send("DATA")
	client.expectCode(354)

	// Send message with 8-bit data (UTF-8 characters) without declaring 8BITMIME
	client.send("Subject: Test with 8-bit data")
	client.send("Content-Type: text/plain; charset=utf-8")
	client.send("")
	// Send UTF-8 content (café has bytes > 127)
	client.sendRaw([]byte("Hello caf\xc3\xa9 r\xc3\xa9sum\xc3\xa9 na\xc3\xafve\r\n"))
	client.send(".")
	client.expectCode(554) // Transaction failed - 8-bit data in 7BIT mode

	client.send("QUIT")
	client.expectCode(221)
}

func TestUTF8AddressRequiresSMTPUTF8InMailFrom(t *testing.T) {
	config := testServerConfig()

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	// Try to use UTF-8 in local part without SMTPUTF8 parameter
	client.send("MAIL FROM:<müller@example.com>")
	client.expectCode(553) // Mailbox name invalid - non-ASCII without SMTPUTF8

	// Try with SMTPUTF8 parameter - should work
	client.send("MAIL FROM:<müller@example.com> SMTPUTF8")
	client.expectCode(250)

	client.send("QUIT")
	client.expectCode(221)
}

func TestUTF8AddressRequiresSMTPUTF8InRcptTo(t *testing.T) {
	config := testServerConfig()

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	// Start transaction without SMTPUTF8
	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(250)

	// Try to use UTF-8 in recipient without having declared SMTPUTF8 in MAIL FROM
	client.send("RCPT TO:<日本語@example.com>")
	client.expectCode(553) // Mailbox name invalid - non-ASCII without SMTPUTF8

	client.send("RSET")
	client.expectCode(250)

	// Now try with SMTPUTF8 declared in MAIL FROM
	client.send("MAIL FROM:<sender@example.com> SMTPUTF8")
	client.expectCode(250)

	// UTF-8 recipient should now work
	client.send("RCPT TO:<日本語@example.com>")
	client.expectCode(250)

	client.send("QUIT")
	client.expectCode(221)
}

func TestUTF8DomainRequiresSMTPUTF8(t *testing.T) {
	config := testServerConfig()

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	// Try UTF-8 in domain without SMTPUTF8
	client.send("MAIL FROM:<user@例え.jp>")
	client.expectCode(553) // Mailbox name invalid

	// With SMTPUTF8 - should work
	client.send("MAIL FROM:<user@例え.jp> SMTPUTF8")
	client.expectCode(250)

	client.send("QUIT")
	client.expectCode(221)
}

// ============================================================================
// Extension Tests - SIZE
// ============================================================================

func TestSIZEExtensionAdvertised(t *testing.T) {
	config := testServerConfig()
	config.MaxMessageSize = 10 * 1024 * 1024 // 10MB

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	lines := client.expectMultilineCode(250)

	// Check SIZE is advertised with correct value
	found := false
	for _, line := range lines {
		if strings.Contains(line, "SIZE") {
			found = true
			if !strings.Contains(line, "10485760") {
				t.Errorf("Expected SIZE 10485760, got: %s", line)
			}
			break
		}
	}
	if !found {
		t.Error("Expected SIZE extension to be advertised")
	}

	client.send("QUIT")
	client.expectCode(221)
}

func TestSIZEParameterAccepted(t *testing.T) {
	config := testServerConfig()
	config.MaxMessageSize = 1024 * 1024 // 1MB

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	// SIZE within limit
	client.send("MAIL FROM:<sender@example.com> SIZE=1000")
	client.expectCode(250)

	client.send("QUIT")
	client.expectCode(221)
}

func TestSIZEParameterRejected(t *testing.T) {
	config := testServerConfig()
	config.MaxMessageSize = 1000 // 1KB

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	// SIZE exceeds limit
	client.send("MAIL FROM:<sender@example.com> SIZE=10000")
	client.expectCode(552) // Exceeded storage

	client.send("QUIT")
	client.expectCode(221)
}

// ============================================================================
// Extension Tests - DSN
// ============================================================================

func TestDSNExtensionAdvertisement(t *testing.T) {
	tests := []struct {
		name      string
		enableDSN bool
		expectDSN bool
	}{
		{"Enabled", true, true},
		{"Disabled", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := testServerConfig()
			config.EnableDSN = tt.enableDSN

			server, addr := startTestServer(t, config)
			defer server.Close()

			client := newTestClient(t, addr)
			defer client.close()

			client.expectCode(220)
			client.send("EHLO client.example.com")
			lines := client.expectMultilineCode(250)

			found := false
			for _, line := range lines {
				if strings.Contains(line, "DSN") && !strings.Contains(line, "Hello") {
					found = true
					break
				}
			}

			if tt.expectDSN && !found {
				t.Error("Expected DSN extension to be advertised")
			}
			if !tt.expectDSN && found {
				t.Error("DSN should not be advertised when disabled")
			}

			client.send("QUIT")
			client.expectCode(221)
		})
	}
}

func TestDSNParameters(t *testing.T) {
	var receivedMail *Mail
	var mu sync.Mutex

	config := testServerConfig()
	config.EnableDSN = true
	config.Callbacks = &Callbacks{
		OnMessage: func(ctx context.Context, conn *Connection, mail *Mail) error {
			mu.Lock()
			receivedMail = mail
			mu.Unlock()
			return nil
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	// MAIL FROM with DSN parameters
	client.send("MAIL FROM:<sender@example.com> RET=HDRS ENVID=test123")
	client.expectCode(250)

	// RCPT TO with DSN parameters
	client.send("RCPT TO:<recipient@example.com> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;original@example.com")
	client.expectCode(250)

	client.send("DATA")
	client.expectCode(354)
	client.send("Subject: DSN test")
	client.send("")
	client.send("Body")
	client.send(".")
	client.expectCode(250)

	mu.Lock()
	if receivedMail == nil {
		t.Error("Expected to receive mail")
	} else {
		if receivedMail.Envelope.EnvID != "test123" {
			t.Errorf("Expected EnvID 'test123', got '%s'", receivedMail.Envelope.EnvID)
		}
		if receivedMail.Envelope.DSNParams == nil || receivedMail.Envelope.DSNParams.RET != "HDRS" {
			t.Error("Expected DSN RET=HDRS")
		}
		if len(receivedMail.Envelope.To) > 0 && receivedMail.Envelope.To[0].DSNParams != nil {
			if receivedMail.Envelope.To[0].DSNParams.ORcpt != "rfc822;original@example.com" {
				t.Errorf("Expected ORCPT 'rfc822;original@example.com', got '%s'", receivedMail.Envelope.To[0].DSNParams.ORcpt)
			}
		} else {
			t.Error("Expected recipient DSN params")
		}
	}
	mu.Unlock()

	client.send("QUIT")
	client.expectCode(221)
}

func TestDSNParametersRejectedWhenDisabled(t *testing.T) {
	config := testServerConfig()
	config.EnableDSN = false

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	// DSN parameters should be rejected
	client.send("MAIL FROM:<sender@example.com> ENVID=test123")
	client.expectCode(504) // Parameter not implemented

	client.send("QUIT")
	client.expectCode(221)
}

// ============================================================================
// Extension Tests - CHUNKING (BDAT)
// ============================================================================

func TestChunkingExtensionAdvertised(t *testing.T) {
	config := testServerConfig()
	config.EnableChunking = true

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	lines := client.expectMultilineCode(250)

	foundChunking := false
	foundBinaryMIME := false
	for _, line := range lines {
		if strings.Contains(line, "CHUNKING") {
			foundChunking = true
		}
		if strings.Contains(line, "BINARYMIME") {
			foundBinaryMIME = true
		}
	}
	if !foundChunking {
		t.Error("Expected CHUNKING extension to be advertised")
	}
	if !foundBinaryMIME {
		t.Error("Expected BINARYMIME extension to be advertised with CHUNKING")
	}

	client.send("QUIT")
	client.expectCode(221)
}

func TestBDATSingleChunk(t *testing.T) {
	var receivedMail *Mail
	var mu sync.Mutex

	config := testServerConfig()
	config.EnableChunking = true
	config.Callbacks = &Callbacks{
		OnMessage: func(ctx context.Context, conn *Connection, mail *Mail) error {
			mu.Lock()
			receivedMail = mail
			mu.Unlock()
			return nil
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)
	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(250)
	client.send("RCPT TO:<recipient@example.com>")
	client.expectCode(250)

	// Send message using BDAT
	message := "Subject: BDAT test\r\n\r\nThis is the body.\r\n"
	client.send(fmt.Sprintf("BDAT %d LAST", len(message)))
	client.sendRaw([]byte(message))
	client.expectCode(250)

	mu.Lock()
	if receivedMail == nil {
		t.Error("Expected to receive mail")
	}
	mu.Unlock()

	client.send("QUIT")
	client.expectCode(221)
}

func TestBDATMultipleChunks(t *testing.T) {
	var receivedMail *Mail
	var mu sync.Mutex

	config := testServerConfig()
	config.EnableChunking = true
	config.Callbacks = &Callbacks{
		OnMessage: func(ctx context.Context, conn *Connection, mail *Mail) error {
			mu.Lock()
			receivedMail = mail
			mu.Unlock()
			return nil
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)
	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(250)
	client.send("RCPT TO:<recipient@example.com>")
	client.expectCode(250)

	// Send message in multiple chunks
	chunk1 := "Subject: Multi-chunk test\r\n"
	chunk2 := "\r\nThis is "
	chunk3 := "the body.\r\n"

	client.send(fmt.Sprintf("BDAT %d", len(chunk1)))
	client.sendRaw([]byte(chunk1))
	client.expectCode(250)

	client.send(fmt.Sprintf("BDAT %d", len(chunk2)))
	client.sendRaw([]byte(chunk2))
	client.expectCode(250)

	client.send(fmt.Sprintf("BDAT %d LAST", len(chunk3)))
	client.sendRaw([]byte(chunk3))
	client.expectCode(250)

	mu.Lock()
	if receivedMail == nil {
		t.Error("Expected to receive mail")
	} else {
		// Verify the parsed content matches what was sent
		expectedBody := "This is the body.\r\n"
		if string(receivedMail.Content.Body) != expectedBody {
			t.Errorf("Expected body %q, got %q", expectedBody, string(receivedMail.Content.Body))
		}
		// Verify Subject header was parsed
		subject := receivedMail.Content.Headers.Get("Subject")
		if subject != "Multi-chunk test" {
			t.Errorf("Expected Subject 'Multi-chunk test', got %q", subject)
		}
	}
	mu.Unlock()

	client.send("QUIT")
	client.expectCode(221)
}

func TestBDATNotAvailableWhenDisabled(t *testing.T) {
	config := testServerConfig()
	config.EnableChunking = false

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)
	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(250)
	client.send("RCPT TO:<recipient@example.com>")
	client.expectCode(250)

	client.send("BDAT 100 LAST")
	client.expectCode(502) // Command not implemented

	client.send("QUIT")
	client.expectCode(221)
}

// ============================================================================
// Extension Tests - AUTH
// ============================================================================

func TestAuthExtensionAdvertised(t *testing.T) {
	config := testServerConfig()
	config.AuthMechanisms = []string{"PLAIN", "LOGIN"}
	config.EnableLoginAuth = true

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	lines := client.expectMultilineCode(250)

	found := false
	for _, line := range lines {
		if strings.Contains(line, "AUTH") {
			found = true
			if !strings.Contains(line, "PLAIN") || !strings.Contains(line, "LOGIN") {
				t.Errorf("Expected AUTH PLAIN LOGIN, got: %s", line)
			}
			break
		}
	}
	if !found {
		t.Error("Expected AUTH extension to be advertised")
	}

	client.send("QUIT")
	client.expectCode(221)
}

func TestAuthPLAIN(t *testing.T) {
	config := testServerConfig()
	config.AuthMechanisms = []string{"PLAIN", "LOGIN"}
	config.EnableLoginAuth = true
	config.Callbacks = &Callbacks{
		OnAuth: func(ctx context.Context, conn *Connection, mechanism, identity, password string) error {
			if identity == "testuser" && password == "testpass" {
				return nil
			}
			return fmt.Errorf("invalid credentials")
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	// AUTH PLAIN with initial response
	// Format: \0identity\0password
	credentials := base64.StdEncoding.EncodeToString([]byte("\x00testuser\x00testpass"))
	client.send("AUTH PLAIN " + credentials)
	client.expectCode(235) // Auth success

	client.send("QUIT")
	client.expectCode(221)
}

func TestAuthPLAINWithChallenge(t *testing.T) {
	config := testServerConfig()
	config.AuthMechanisms = []string{"PLAIN"}
	config.Callbacks = &Callbacks{
		OnAuth: func(ctx context.Context, conn *Connection, mechanism, identity, password string) error {
			if identity == "user" && password == "pass" {
				return nil
			}
			return fmt.Errorf("invalid credentials")
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	// AUTH PLAIN without initial response
	client.send("AUTH PLAIN")
	client.expectCode(334) // Challenge

	// Send credentials
	credentials := base64.StdEncoding.EncodeToString([]byte("\x00user\x00pass"))
	client.send(credentials)
	client.expectCode(235) // Auth success

	client.send("QUIT")
	client.expectCode(221)
}

func TestAuthLOGIN(t *testing.T) {
	config := testServerConfig()
	config.AuthMechanisms = []string{"LOGIN"}
	config.EnableLoginAuth = true
	config.Callbacks = &Callbacks{
		OnAuth: func(ctx context.Context, conn *Connection, mechanism, identity, password string) error {
			if identity == "loginuser" && password == "loginpass" {
				return nil
			}
			return fmt.Errorf("invalid credentials")
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	client.send("AUTH LOGIN")
	client.expectCode(334) // Username challenge

	client.send(base64.StdEncoding.EncodeToString([]byte("loginuser")))
	client.expectCode(334) // Password challenge

	client.send(base64.StdEncoding.EncodeToString([]byte("loginpass")))
	client.expectCode(235) // Auth success

	client.send("QUIT")
	client.expectCode(221)
}

func TestAuthFailed(t *testing.T) {
	config := testServerConfig()
	config.AuthMechanisms = []string{"PLAIN"}
	config.Callbacks = &Callbacks{
		OnAuth: func(ctx context.Context, conn *Connection, mechanism, identity, password string) error {
			return fmt.Errorf("always fail")
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	credentials := base64.StdEncoding.EncodeToString([]byte("\x00user\x00pass"))
	client.send("AUTH PLAIN " + credentials)
	client.expectCode(535) // RFC 4954: 535 for authentication credentials invalid

	client.send("QUIT")
	client.expectCode(221)
}

func TestRequireAuth(t *testing.T) {
	config := testServerConfig()
	config.AuthMechanisms = []string{"PLAIN"}
	config.RequireAuth = true
	config.Callbacks = &Callbacks{
		OnAuth: func(ctx context.Context, conn *Connection, mechanism, identity, password string) error {
			return nil
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	// Try to send mail without auth
	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(554) // Auth required

	// Now authenticate
	credentials := base64.StdEncoding.EncodeToString([]byte("\x00user\x00pass"))
	client.send("AUTH PLAIN " + credentials)
	client.expectCode(235)

	// Should work now
	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(250)

	client.send("QUIT")
	client.expectCode(221)
}

// ============================================================================
// Extension Tests - Implicit TLS (SMTPS)
// ============================================================================

// newTLSTestClient creates a test client that connects over TLS (for implicit TLS/SMTPS testing).
func newTLSTestClient(t *testing.T, addr string) *testClient {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		addr,
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		t.Fatalf("Failed to connect to TLS server: %v", err)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	return &testClient{
		conn:   conn,
		reader: bufio.NewReader(conn),
		t:      t,
	}
}

// startTLSTestServer starts a test server with implicit TLS on a random port.
func startTLSTestServer(t *testing.T, config ServerConfig) (*Server, string) {
	// Find a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find free port: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	config.Addr = addr
	if config.Hostname == "" {
		config.Hostname = "test.example.com"
	}
	config.Logger = discardLogger()

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server with implicit TLS in background
	go func() {
		_ = server.ListenAndServeTLS()
	}()

	// Wait for server to start (need TLS connection)
	for range 50 {
		conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	return server, addr
}

func TestImplicitTLSBasicSession(t *testing.T) {
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	var receivedMail *Mail
	var mu sync.Mutex

	config := testServerConfig()
	config.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	config.Callbacks = &Callbacks{
		OnMessage: func(ctx context.Context, conn *Connection, mail *Mail) error {
			mu.Lock()
			receivedMail = mail
			mu.Unlock()
			return nil
		},
	}

	server, addr := startTLSTestServer(t, config)
	defer server.Close()

	client := newTLSTestClient(t, addr)
	defer client.close()

	// Should receive greeting
	client.expectCode(220)

	// Complete SMTP session
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)
	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(250)
	client.send("RCPT TO:<recipient@example.com>")
	client.expectCode(250)
	client.send("DATA")
	client.expectCode(354)
	client.send("Subject: Test\r\n\r\nHello World\r\n.")
	client.expectCode(250)
	client.send("QUIT")
	client.expectCode(221)

	// Verify mail was received
	mu.Lock()
	defer mu.Unlock()
	if receivedMail == nil {
		t.Fatal("Expected to receive mail")
	}
	if receivedMail.Envelope.From.Mailbox.String() != "sender@example.com" {
		t.Errorf("Expected sender 'sender@example.com', got %q", receivedMail.Envelope.From.Mailbox.String())
	}
}

func TestImplicitTLSNoSTARTTLSAdvertised(t *testing.T) {
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	config := testServerConfig()
	config.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	server, addr := startTLSTestServer(t, config)
	defer server.Close()

	client := newTLSTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	lines := client.expectMultilineCode(250)

	// STARTTLS should NOT be advertised on implicit TLS connection
	for _, line := range lines {
		if strings.Contains(line, "STARTTLS") {
			t.Error("STARTTLS should not be advertised on implicit TLS connection")
		}
	}

	client.send("QUIT")
	client.expectCode(221)
}

func TestImplicitTLSWithAuth(t *testing.T) {
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	authenticated := false

	config := testServerConfig()
	config.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	config.AuthMechanisms = []string{"PLAIN", "LOGIN"}
	config.EnableLoginAuth = true
	config.Callbacks = &Callbacks{
		OnAuth: func(ctx context.Context, conn *Connection, mechanism, identity, password string) error {
			if identity == "user" && password == "pass" {
				authenticated = true
				return nil
			}
			return fmt.Errorf("invalid credentials")
		},
	}

	server, addr := startTLSTestServer(t, config)
	defer server.Close()

	client := newTLSTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	lines := client.expectMultilineCode(250)

	// AUTH should be advertised on implicit TLS connection
	found := false
	for _, line := range lines {
		if strings.Contains(line, "AUTH") && strings.Contains(line, "PLAIN") {
			found = true
			break
		}
	}
	if !found {
		t.Error("AUTH should be advertised on implicit TLS connection")
	}

	// Authenticate using PLAIN
	// AUTH PLAIN base64(\0user\0pass)
	credentials := base64.StdEncoding.EncodeToString([]byte("\x00user\x00pass"))
	client.send("AUTH PLAIN " + credentials)
	client.expectCode(235) // Authentication successful

	if !authenticated {
		t.Error("Expected authentication callback to be called")
	}

	client.send("QUIT")
	client.expectCode(221)
}

func TestImplicitTLSRequiresTLSConfig(t *testing.T) {
	config := testServerConfig()
	config.Hostname = "test.example.com"
	// No TLSConfig set

	server, err := NewServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Close()

	// ListenAndServeTLS should fail without TLSConfig
	err = server.ListenAndServeTLS()
	if err == nil {
		t.Error("Expected error when starting TLS server without TLSConfig")
	}
	if !strings.Contains(err.Error(), "TLS config is required") {
		t.Errorf("Expected 'TLS config is required' error, got: %v", err)
	}
}

func TestImplicitTLSProtocolInReceivedHeader(t *testing.T) {
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	var receivedMail *Mail
	var mu sync.Mutex

	config := testServerConfig()
	config.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	config.Callbacks = &Callbacks{
		OnMessage: func(ctx context.Context, conn *Connection, mail *Mail) error {
			mu.Lock()
			receivedMail = mail
			mu.Unlock()
			return nil
		},
	}

	server, addr := startTLSTestServer(t, config)
	defer server.Close()

	client := newTLSTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)
	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(250)
	client.send("RCPT TO:<recipient@example.com>")
	client.expectCode(250)
	client.send("DATA")
	client.expectCode(354)
	client.send("Subject: Test\r\n\r\nTest body\r\n.")
	client.expectCode(250)
	client.send("QUIT")
	client.expectCode(221)

	// Verify protocol indicates TLS was used
	mu.Lock()
	defer mu.Unlock()
	if receivedMail == nil {
		t.Fatal("Expected to receive mail")
	}
	// The With field in the most recent trace should indicate ESMTPS (TLS)
	if len(receivedMail.Trace) == 0 {
		t.Fatal("Expected trace information in received mail")
	}
	if !strings.Contains(receivedMail.Trace[0].With, "SMTPS") {
		t.Errorf("Expected protocol to contain 'SMTPS' for implicit TLS, got %q", receivedMail.Trace[0].With)
	}
}

// ============================================================================
// Extension Tests - STARTTLS
// ============================================================================

func TestSTARTTLSAdvertised(t *testing.T) {
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	config := testServerConfig()
	config.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	lines := client.expectMultilineCode(250)

	found := false
	for _, line := range lines {
		if strings.Contains(line, "STARTTLS") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected STARTTLS extension to be advertised")
	}

	client.send("QUIT")
	client.expectCode(221)
}

func TestSTARTTLSNotAdvertisedWithoutConfig(t *testing.T) {
	config := testServerConfig()
	// No TLSConfig

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	lines := client.expectMultilineCode(250)

	for _, line := range lines {
		if strings.Contains(line, "STARTTLS") {
			t.Error("STARTTLS should not be advertised without TLSConfig")
		}
	}

	client.send("QUIT")
	client.expectCode(221)
}

func TestSTARTTLSUpgrade(t *testing.T) {
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	config := testServerConfig()
	config.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	// Initiate STARTTLS
	client.send("STARTTLS")
	client.expectCode(220)

	// Upgrade to TLS
	// Reset deadline before TLS handshake
	client.conn.SetDeadline(time.Now().Add(10 * time.Second))
	tlsConn := tls.Client(client.conn, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}
	client.conn = tlsConn
	client.reader = bufio.NewReader(tlsConn)
	// Reset deadline after upgrade
	client.conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Need to re-issue EHLO after STARTTLS
	client.send("EHLO client.example.com")
	lines := client.expectMultilineCode(250)

	// STARTTLS should NOT be advertised after upgrade
	for _, line := range lines {
		if strings.Contains(line, "STARTTLS") {
			t.Error("STARTTLS should not be advertised after TLS upgrade")
		}
	}

	client.send("QUIT")
	client.expectCode(221)
}

// ============================================================================
// Connection Limits and Error Handling Tests
// ============================================================================

func TestMaxRecipients(t *testing.T) {
	config := testServerConfig()
	config.MaxRecipients = 3

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)
	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(250)

	// Add max recipients
	for i := range 3 {
		client.send(fmt.Sprintf("RCPT TO:<rcpt%d@example.com>", i))
		client.expectCode(250)
	}

	// One more should fail
	client.send("RCPT TO:<rcpt3@example.com>")
	client.expectCode(452) // Insufficient storage (too many recipients)

	client.send("QUIT")
	client.expectCode(221)
}

func TestMaxMessageSize(t *testing.T) {
	config := testServerConfig()
	config.MaxMessageSize = 500 // Small but realistic for testing

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)
	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(250)
	client.send("RCPT TO:<recipient@example.com>")
	client.expectCode(250)
	client.send("DATA")
	client.expectCode(354)

	// Send message larger than limit
	// Build a large message body all at once
	var msg strings.Builder
	msg.WriteString("Subject: Large message\r\n\r\n")
	for range 50 {
		msg.WriteString("This is line of padding text to make message large.\r\n")
	}
	msg.WriteString(".\r\n")
	client.sendRaw([]byte(msg.String()))
	client.expectCode(552) // Exceeded storage

	client.send("QUIT")
	client.expectCode(221)
}

func TestBadSequenceErrors(t *testing.T) {
	config := testServerConfig()
	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)

	// MAIL without EHLO
	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(503)

	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	// RCPT without MAIL
	client.send("RCPT TO:<recipient@example.com>")
	client.expectCode(503)

	// DATA without RCPT
	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(250)
	client.send("DATA")
	client.expectCode(503)

	client.send("QUIT")
	client.expectCode(221)
}

func TestUnknownCommand(t *testing.T) {
	config := testServerConfig()
	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("UNKNOWNCOMMAND test")
	client.expectCode(501) // Syntax error (unknown commands are parsed as invalid syntax)

	client.send("QUIT")
	client.expectCode(221)
}

// ============================================================================
// Callback Tests
// ============================================================================

func TestOnConnectCallback(t *testing.T) {
	connectCalled := false
	var mu sync.Mutex

	config := testServerConfig()
	config.Callbacks = &Callbacks{
		OnConnect: func(ctx context.Context, conn *Connection) error {
			mu.Lock()
			connectCalled = true
			mu.Unlock()
			return nil
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)

	mu.Lock()
	if !connectCalled {
		t.Error("OnConnect callback was not called")
	}
	mu.Unlock()

	client.send("QUIT")
	client.expectCode(221)
}

func TestOnConnectReject(t *testing.T) {
	config := testServerConfig()
	config.Callbacks = &Callbacks{
		OnConnect: func(ctx context.Context, conn *Connection) error {
			return fmt.Errorf("connection rejected")
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	// Should get rejection
	client.expectCode(554)
}

func TestOnMailFromCallback(t *testing.T) {
	var receivedFrom string
	var mu sync.Mutex

	config := testServerConfig()
	config.Callbacks = &Callbacks{
		OnMailFrom: func(ctx context.Context, conn *Connection, from Path, params map[string]string) error {
			mu.Lock()
			receivedFrom = from.Mailbox.String()
			mu.Unlock()
			return nil
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)
	client.send("MAIL FROM:<test@callback.com>")
	client.expectCode(250)

	mu.Lock()
	if receivedFrom != "test@callback.com" {
		t.Errorf("Expected from 'test@callback.com', got '%s'", receivedFrom)
	}
	mu.Unlock()

	client.send("QUIT")
	client.expectCode(221)
}

func TestOnMailFromReject(t *testing.T) {
	config := testServerConfig()
	config.Callbacks = &Callbacks{
		OnMailFrom: func(ctx context.Context, conn *Connection, from Path, params map[string]string) error {
			if strings.Contains(from.Mailbox.Domain, "blocked.com") {
				return fmt.Errorf("sender rejected")
			}
			return nil
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	client.send("MAIL FROM:<sender@blocked.com>")
	client.expectCode(550) // Rejected

	client.send("MAIL FROM:<sender@allowed.com>")
	client.expectCode(250) // Accepted

	client.send("QUIT")
	client.expectCode(221)
}

func TestOnRcptToCallback(t *testing.T) {
	var recipients []string
	var mu sync.Mutex

	config := testServerConfig()
	config.Callbacks = &Callbacks{
		OnRcptTo: func(ctx context.Context, conn *Connection, to Path, params map[string]string) error {
			mu.Lock()
			recipients = append(recipients, to.Mailbox.String())
			mu.Unlock()
			return nil
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)
	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(250)

	client.send("RCPT TO:<rcpt1@example.com>")
	client.expectCode(250)
	client.send("RCPT TO:<rcpt2@example.com>")
	client.expectCode(250)

	mu.Lock()
	if len(recipients) != 2 {
		t.Errorf("Expected 2 recipients, got %d", len(recipients))
	}
	mu.Unlock()

	client.send("QUIT")
	client.expectCode(221)
}

func TestOnRcptToReject(t *testing.T) {
	config := testServerConfig()
	config.Callbacks = &Callbacks{
		OnRcptTo: func(ctx context.Context, conn *Connection, to Path, params map[string]string) error {
			if strings.Contains(to.Mailbox.LocalPart, "invalid") {
				return fmt.Errorf("recipient rejected")
			}
			return nil
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)
	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(250)

	client.send("RCPT TO:<invalid@example.com>")
	client.expectCode(550) // Rejected

	client.send("RCPT TO:<valid@example.com>")
	client.expectCode(250) // Accepted

	client.send("QUIT")
	client.expectCode(221)
}

func TestOnDataCallback(t *testing.T) {
	dataCalled := false
	var mu sync.Mutex

	config := testServerConfig()
	config.Callbacks = &Callbacks{
		OnData: func(ctx context.Context, conn *Connection) error {
			mu.Lock()
			dataCalled = true
			mu.Unlock()
			return nil
		},
		OnMessage: func(ctx context.Context, conn *Connection, mail *Mail) error {
			return nil
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)
	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(250)
	client.send("RCPT TO:<recipient@example.com>")
	client.expectCode(250)
	client.send("DATA")
	client.expectCode(354)

	mu.Lock()
	if !dataCalled {
		t.Error("OnData callback was not called")
	}
	mu.Unlock()

	client.send("Subject: Test")
	client.send("")
	client.send("Body")
	client.send(".")
	client.expectCode(250)

	client.send("QUIT")
	client.expectCode(221)
}

func TestOnEhloCallback(t *testing.T) {
	var clientHostname string
	var mu sync.Mutex

	config := testServerConfig()
	config.Callbacks = &Callbacks{
		OnEhlo: func(ctx context.Context, conn *Connection, hostname string) (map[Extension]string, error) {
			mu.Lock()
			clientHostname = hostname
			mu.Unlock()
			return nil, nil // Return nil to use default extensions
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO my.custom.hostname")
	client.expectMultilineCode(250)

	mu.Lock()
	if clientHostname != "my.custom.hostname" {
		t.Errorf("Expected hostname 'my.custom.hostname', got '%s'", clientHostname)
	}
	mu.Unlock()

	client.send("QUIT")
	client.expectCode(221)
}

// ============================================================================
// Multiple Transaction Tests
// ============================================================================

func TestMultipleTransactions(t *testing.T) {
	messageCount := 0
	var mu sync.Mutex

	config := testServerConfig()
	config.Callbacks = &Callbacks{
		OnMessage: func(ctx context.Context, conn *Connection, mail *Mail) error {
			mu.Lock()
			messageCount++
			mu.Unlock()
			return nil
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	// First transaction
	client.send("MAIL FROM:<sender1@example.com>")
	client.expectCode(250)
	client.send("RCPT TO:<recipient1@example.com>")
	client.expectCode(250)
	client.send("DATA")
	client.expectCode(354)
	client.send("Subject: Message 1")
	client.send("")
	client.send("Body 1")
	client.send(".")
	client.expectCode(250)

	// Second transaction (same connection)
	client.send("MAIL FROM:<sender2@example.com>")
	client.expectCode(250)
	client.send("RCPT TO:<recipient2@example.com>")
	client.expectCode(250)
	client.send("DATA")
	client.expectCode(354)
	client.send("Subject: Message 2")
	client.send("")
	client.send("Body 2")
	client.send(".")
	client.expectCode(250)

	mu.Lock()
	if messageCount != 2 {
		t.Errorf("Expected 2 messages, got %d", messageCount)
	}
	mu.Unlock()

	client.send("QUIT")
	client.expectCode(221)
}

// ============================================================================
// Test Certificates (self-signed for testing)
// ============================================================================

// generateTestCert creates a self-signed certificate for testing.
func generateTestCert() (tls.Certificate, error) {
	// Generate RSA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// TestRequireTLSRejectsMailWithoutTLS tests that MAIL FROM is rejected when RequireTLS is set
// and the connection is not using TLS.
func TestRequireTLSRejectsMailWithoutTLS(t *testing.T) {
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	config := testServerConfig()
	config.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	config.RequireTLS = true

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	// Try MAIL FROM without TLS - should be rejected
	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(554) // TLS required

	client.send("QUIT")
	client.expectCode(221)
}

// TestRequireTLSAllowsMailAfterSTARTTLS tests that MAIL FROM succeeds after STARTTLS
// when RequireTLS is set.
func TestRequireTLSAllowsMailAfterSTARTTLS(t *testing.T) {
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	config := testServerConfig()
	config.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	config.RequireTLS = true

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	// Upgrade to TLS
	client.send("STARTTLS")
	client.expectCode(220)

	client.conn.SetDeadline(time.Now().Add(10 * time.Second))
	tlsConn := tls.Client(client.conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}
	client.conn = tlsConn
	client.reader = bufio.NewReader(tlsConn)
	client.conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Re-EHLO after TLS
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	// Now MAIL FROM should work
	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(250)

	client.send("RCPT TO:<recipient@example.com>")
	client.expectCode(250)

	client.send("QUIT")
	client.expectCode(221)
}

// TestRequireTLSHidesAuthWithoutTLS tests that AUTH is not advertised when RequireTLS is set
// and the connection is not using TLS.
func TestRequireTLSHidesAuthWithoutTLS(t *testing.T) {
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	config := testServerConfig()
	config.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	config.RequireTLS = true
	config.AuthMechanisms = []string{"PLAIN", "LOGIN"}
	config.EnableLoginAuth = true
	config.Callbacks = &Callbacks{
		OnAuth: func(ctx context.Context, conn *Connection, mechanism, identity, password string) error {
			if identity == "user" && password == "pass" {
				return nil
			}
			return fmt.Errorf("invalid credentials")
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	lines := client.expectMultilineCode(250)

	// AUTH should NOT be advertised without TLS when RequireTLS is set
	for _, line := range lines {
		if strings.Contains(line, "AUTH") {
			t.Error("AUTH should not be advertised without TLS when RequireTLS is set")
		}
	}

	// Upgrade to TLS
	client.send("STARTTLS")
	client.expectCode(220)

	client.conn.SetDeadline(time.Now().Add(10 * time.Second))
	tlsConn := tls.Client(client.conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}
	client.conn = tlsConn
	client.reader = bufio.NewReader(tlsConn)
	client.conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Re-EHLO after TLS
	client.send("EHLO client.example.com")
	lines = client.expectMultilineCode(250)

	// AUTH should now be advertised
	found := false
	for _, line := range lines {
		if strings.Contains(line, "AUTH") && strings.Contains(line, "PLAIN") {
			found = true
			break
		}
	}
	if !found {
		t.Error("AUTH should be advertised after STARTTLS")
	}

	client.send("QUIT")
	client.expectCode(221)
}

// ============================================================================
// Middleware Tests
// ============================================================================

// startBuilderTestServer starts a test server using ServerBuilder on a random port.
func startBuilderTestServer(t *testing.T, builder *ServerBuilder) (*Server, string) {
	// Find a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to find free port: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	server, err := builder.Addr(addr).Build()
	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}

	// Start server in background
	go func() {
		_ = server.ListenAndServe()
	}()

	// Wait for server to start
	for range 50 {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	return server, addr
}

func TestMiddlewareExecutionOrder(t *testing.T) {
	var executionOrder []string
	var mu sync.Mutex

	// Create middleware that records execution order
	createMiddleware := func(name string) Middleware {
		return func(next HandlerFunc) HandlerFunc {
			return func(ctx *Context) error {
				mu.Lock()
				executionOrder = append(executionOrder, name+"-before")
				mu.Unlock()

				err := next(ctx)

				mu.Lock()
				executionOrder = append(executionOrder, name+"-after")
				mu.Unlock()

				return err
			}
		}
	}

	builder := New("test.example.com").
		Logger(discardLogger()).
		Use(createMiddleware("mw1")).
		Use(createMiddleware("mw2")).
		OnEhlo(func(ctx *Context) error {
			mu.Lock()
			executionOrder = append(executionOrder, "handler")
			mu.Unlock()
			return nil
		})

	server, addr := startBuilderTestServer(t, builder)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)
	client.send("QUIT")
	client.expectCode(221)

	// Verify execution order: outer middleware wraps inner
	// mw1-before -> mw2-before -> handler -> mw2-after -> mw1-after
	mu.Lock()
	defer mu.Unlock()

	expected := []string{"mw1-before", "mw2-before", "handler", "mw2-after", "mw1-after"}
	if len(executionOrder) != len(expected) {
		t.Errorf("Expected %d execution steps, got %d: %v", len(expected), len(executionOrder), executionOrder)
		return
	}
	for i, exp := range expected {
		if executionOrder[i] != exp {
			t.Errorf("Step %d: expected %q, got %q", i, exp, executionOrder[i])
		}
	}
}

func TestMiddlewareModifiesContext(t *testing.T) {
	var capturedValue string
	var mu sync.Mutex

	// Middleware that adds a value to context
	addValueMiddleware := func(next HandlerFunc) HandlerFunc {
		return func(ctx *Context) error {
			ctx.Set("custom-key", "custom-value")
			return next(ctx)
		}
	}

	builder := New("test.example.com").
		Logger(discardLogger()).
		Use(addValueMiddleware).
		OnConnect(func(ctx *Context) error {
			if val, ok := ctx.Get("custom-key"); ok {
				mu.Lock()
				capturedValue = val.(string)
				mu.Unlock()
			}
			return nil
		})

	server, addr := startBuilderTestServer(t, builder)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("QUIT")
	client.expectCode(221)

	mu.Lock()
	defer mu.Unlock()
	if capturedValue != "custom-value" {
		t.Errorf("Expected 'custom-value', got %q", capturedValue)
	}
}

func TestMiddlewareCanAbortRequest(t *testing.T) {
	handlerCalled := false

	// Middleware that aborts the request
	abortMiddleware := func(next HandlerFunc) HandlerFunc {
		return func(ctx *Context) error {
			// Return error to prevent handler from being called
			return fmt.Errorf("middleware rejected")
		}
	}

	builder := New("test.example.com").
		Logger(discardLogger()).
		Use(abortMiddleware).
		OnMailFrom(func(ctx *Context) error {
			handlerCalled = true
			return nil
		})

	server, addr := startBuilderTestServer(t, builder)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	// MAIL FROM should fail because middleware aborts
	client.send("MAIL FROM:<sender@example.com>")
	line := client.readLine()
	code := 0
	fmt.Sscanf(line, "%d", &code)
	if code < 400 {
		t.Errorf("Expected error code (4xx or 5xx), got %d", code)
	}

	if handlerCalled {
		t.Error("Handler should not be called when middleware aborts")
	}

	client.send("QUIT")
	client.expectCode(221)
}

func TestMiddlewareAppliedToMultipleHandlers(t *testing.T) {
	var calledFor []string
	var mu sync.Mutex

	// Middleware that tracks which events it's called for
	trackingMiddleware := func(next HandlerFunc) HandlerFunc {
		return func(ctx *Context) error {
			// We can identify the event by checking what's in the context
			event := "unknown"
			if _, ok := ctx.Get("from"); ok {
				event = "mail-from"
			} else if _, ok := ctx.Get("to"); ok {
				event = "rcpt-to"
			} else if ctx.Mail != nil {
				event = "message"
			} else {
				event = "connect-or-helo"
			}

			mu.Lock()
			calledFor = append(calledFor, event)
			mu.Unlock()

			return next(ctx)
		}
	}

	builder := New("test.example.com").
		Logger(discardLogger()).
		Use(trackingMiddleware).
		OnMailFrom(func(ctx *Context) error { return nil }).
		OnRcptTo(func(ctx *Context) error { return nil }).
		OnMessage(func(ctx *Context) error { return nil })

	server, addr := startBuilderTestServer(t, builder)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)
	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(250)
	client.send("RCPT TO:<recipient@example.com>")
	client.expectCode(250)
	client.send("DATA")
	client.expectCode(354)
	client.send("Subject: Test\r\n\r\nBody\r\n.")
	client.expectCode(250)
	client.send("QUIT")
	client.expectCode(221)

	mu.Lock()
	defer mu.Unlock()

	// Middleware should be called for each registered handler
	if len(calledFor) != 3 {
		t.Errorf("Expected middleware called 3 times, got %d: %v", len(calledFor), calledFor)
	}
}

func TestMiddlewareAccessConnectionInfo(t *testing.T) {
	var remoteAddr string
	var isTLS bool
	var mu sync.Mutex

	// Middleware that captures connection info
	captureInfoMiddleware := func(next HandlerFunc) HandlerFunc {
		return func(ctx *Context) error {
			mu.Lock()
			remoteAddr = ctx.RemoteAddr()
			isTLS = ctx.IsTLS()
			mu.Unlock()
			return next(ctx)
		}
	}

	builder := New("test.example.com").
		Logger(discardLogger()).
		Use(captureInfoMiddleware).
		OnConnect(func(ctx *Context) error { return nil })

	server, addr := startBuilderTestServer(t, builder)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("QUIT")
	client.expectCode(221)

	mu.Lock()
	defer mu.Unlock()

	if remoteAddr == "" {
		t.Error("Expected middleware to capture remote address")
	}
	if isTLS {
		t.Error("Expected non-TLS connection")
	}
}

func TestMultipleMiddlewareChaining(t *testing.T) {
	var values []string
	var mu sync.Mutex

	// Each middleware adds its own value to context
	createAddValueMiddleware := func(key, value string) Middleware {
		return func(next HandlerFunc) HandlerFunc {
			return func(ctx *Context) error {
				ctx.Set(key, value)
				return next(ctx)
			}
		}
	}

	builder := New("test.example.com").
		Logger(discardLogger()).
		Use(createAddValueMiddleware("key1", "value1")).
		Use(createAddValueMiddleware("key2", "value2")).
		Use(createAddValueMiddleware("key3", "value3")).
		OnEhlo(func(ctx *Context) error {
			mu.Lock()
			defer mu.Unlock()
			if v, ok := ctx.Get("key1"); ok {
				values = append(values, v.(string))
			}
			if v, ok := ctx.Get("key2"); ok {
				values = append(values, v.(string))
			}
			if v, ok := ctx.Get("key3"); ok {
				values = append(values, v.(string))
			}
			return nil
		})

	server, addr := startBuilderTestServer(t, builder)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)
	client.send("QUIT")
	client.expectCode(221)

	mu.Lock()
	defer mu.Unlock()

	if len(values) != 3 {
		t.Errorf("Expected 3 values from middleware chain, got %d: %v", len(values), values)
	}
	expected := []string{"value1", "value2", "value3"}
	for i, exp := range expected {
		if i < len(values) && values[i] != exp {
			t.Errorf("Value %d: expected %q, got %q", i, exp, values[i])
		}
	}
}

// TestREQUIRETLSExtensionAdvertisedAfterSTARTTLS tests that REQUIRETLS is advertised
// in EHLO response only after TLS is established (per RFC 8689).
func TestREQUIRETLSExtensionAdvertisedAfterSTARTTLS(t *testing.T) {
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	config := testServerConfig()
	config.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	lines := client.expectMultilineCode(250)

	// REQUIRETLS should NOT be advertised before TLS
	for _, line := range lines {
		if strings.Contains(line, "REQUIRETLS") {
			t.Error("REQUIRETLS should not be advertised before TLS is established")
		}
	}

	// Upgrade to TLS
	client.send("STARTTLS")
	client.expectCode(220)

	client.conn.SetDeadline(time.Now().Add(10 * time.Second))
	tlsConn := tls.Client(client.conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}
	client.conn = tlsConn
	client.reader = bufio.NewReader(tlsConn)
	client.conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Re-EHLO after TLS
	client.send("EHLO client.example.com")
	lines = client.expectMultilineCode(250)

	// REQUIRETLS should now be advertised after TLS is established
	foundRequireTLS := false
	for _, line := range lines {
		if strings.Contains(line, "REQUIRETLS") {
			foundRequireTLS = true
			break
		}
	}
	if !foundRequireTLS {
		t.Error("REQUIRETLS should be advertised after TLS is established")
	}

	client.send("QUIT")
	client.expectCode(221)
}

// TestREQUIRETLSParameterAcceptedWithTLS tests that MAIL FROM with REQUIRETLS
// parameter is accepted when TLS is active.
func TestREQUIRETLSParameterAcceptedWithTLS(t *testing.T) {
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	var receivedMail *Mail
	config := testServerConfig()
	config.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	config.Callbacks = &Callbacks{
		OnMessage: func(ctx context.Context, conn *Connection, mail *Mail) error {
			receivedMail = mail
			return nil
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	// Upgrade to TLS
	client.send("STARTTLS")
	client.expectCode(220)

	client.conn.SetDeadline(time.Now().Add(10 * time.Second))
	tlsConn := tls.Client(client.conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}
	client.conn = tlsConn
	client.reader = bufio.NewReader(tlsConn)
	client.conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Re-EHLO after TLS
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	// MAIL FROM with REQUIRETLS should be accepted
	client.send("MAIL FROM:<sender@example.com> REQUIRETLS")
	client.expectCode(250)

	client.send("RCPT TO:<recipient@example.com>")
	client.expectCode(250)

	client.send("DATA")
	client.expectCode(354)

	client.send("From: sender@example.com")
	client.send("To: recipient@example.com")
	client.send("Subject: Test REQUIRETLS")
	client.send("")
	client.send("Test message with REQUIRETLS.")
	client.send(".")
	client.expectCode(250)

	client.send("QUIT")
	client.expectCode(221)

	// Verify the RequireTLS flag was set on the envelope
	if receivedMail == nil {
		t.Fatal("Expected to receive mail")
	}
	if !receivedMail.Envelope.RequireTLS {
		t.Error("Expected RequireTLS flag to be set on envelope")
	}
}

// TestREQUIRETLSParameterRejectedWithoutTLS tests that MAIL FROM with REQUIRETLS
// parameter is rejected when TLS is not active.
func TestREQUIRETLSParameterRejectedWithoutTLS(t *testing.T) {
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	config := testServerConfig()
	config.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	// MAIL FROM with REQUIRETLS should be rejected without TLS
	client.send("MAIL FROM:<sender@example.com> REQUIRETLS")
	client.expectCode(554) // Transaction failed - TLS required

	client.send("QUIT")
	client.expectCode(221)
}

// TestTLSRequiredHeaderProcessing tests that TLS-Required: No header is processed
// and stored in the envelope for relay handling.
func TestTLSRequiredHeaderProcessing(t *testing.T) {
	var receivedMail *Mail
	config := testServerConfig()
	config.Callbacks = &Callbacks{
		OnMessage: func(ctx context.Context, conn *Connection, mail *Mail) error {
			receivedMail = mail
			return nil
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(250)

	client.send("RCPT TO:<admin@example.com>")
	client.expectCode(250)

	client.send("DATA")
	client.expectCode(354)

	// Send message with TLS-Required: No header
	client.send("From: sender@example.com")
	client.send("To: admin@example.com")
	client.send("Subject: Certificate problem")
	client.send("TLS-Required: No")
	client.send("")
	client.send("Your TLS certificate seems to be expired.")
	client.send(".")
	client.expectCode(250)

	client.send("QUIT")
	client.expectCode(221)

	// Verify the TLS-OPTIONAL flag was set
	if receivedMail == nil {
		t.Fatal("Expected to receive mail")
	}
	if receivedMail.Envelope.ExtensionParams == nil {
		t.Fatal("Expected ExtensionParams to be set")
	}
	if receivedMail.Envelope.ExtensionParams["TLS-OPTIONAL"] != "yes" {
		t.Error("Expected TLS-OPTIONAL flag to be set when TLS-Required: No header present")
	}
}

// ============================================================================
// VRFY and EXPN Command Tests
// ============================================================================

func TestVRFY(t *testing.T) {
	t.Run("WithoutCallback", func(t *testing.T) {
		config := testServerConfig()
		server, addr := startTestServer(t, config)
		defer server.Close()

		client := newTestClient(t, addr)
		defer client.close()

		client.expectCode(220)
		client.send("EHLO client.example.com")
		client.expectMultilineCode(250)

		// VRFY without callback returns 252 (cannot verify)
		client.send("VRFY user@example.com")
		client.expectCode(252) // Cannot VRFY user

		client.send("QUIT")
		client.expectCode(221)
	})

	t.Run("WithCallback", func(t *testing.T) {
		config := testServerConfig()
		config.Callbacks = &Callbacks{
			OnVerify: func(ctx context.Context, conn *Connection, address string) (MailboxAddress, error) {
				if address == "valid@example.com" {
					return MailboxAddress{LocalPart: "valid", Domain: "example.com"}, nil
				}
				return MailboxAddress{}, fmt.Errorf("user not found")
			},
		}
		server, addr := startTestServer(t, config)
		defer server.Close()

		client := newTestClient(t, addr)
		defer client.close()

		client.expectCode(220)
		client.send("EHLO client.example.com")
		client.expectMultilineCode(250)

		// Valid address
		client.send("VRFY valid@example.com")
		resp := client.expectCode(250)
		if !strings.Contains(resp, "valid@example.com") {
			t.Errorf("Expected verified address in response, got: %s", resp)
		}

		// Invalid address
		client.send("VRFY invalid@example.com")
		client.expectCode(550) // User not found

		client.send("QUIT")
		client.expectCode(221)
	})

	t.Run("SyntaxError", func(t *testing.T) {
		config := testServerConfig()
		server, addr := startTestServer(t, config)
		defer server.Close()

		client := newTestClient(t, addr)
		defer client.close()

		client.expectCode(220)
		client.send("EHLO client.example.com")
		client.expectMultilineCode(250)

		// VRFY without argument
		client.send("VRFY")
		client.expectCode(501) // Syntax error

		client.send("QUIT")
		client.expectCode(221)
	})
}

func TestEXPN(t *testing.T) {
	t.Run("WithoutCallback", func(t *testing.T) {
		config := testServerConfig()
		server, addr := startTestServer(t, config)
		defer server.Close()

		client := newTestClient(t, addr)
		defer client.close()

		client.expectCode(220)
		client.send("EHLO client.example.com")
		client.expectMultilineCode(250)

		// EXPN without callback returns 252 (cannot expand)
		client.send("EXPN staff")
		client.expectCode(252) // Cannot EXPN list

		client.send("QUIT")
		client.expectCode(221)
	})

	t.Run("WithCallback", func(t *testing.T) {
		config := testServerConfig()
		config.Callbacks = &Callbacks{
			OnExpand: func(ctx context.Context, conn *Connection, listName string) ([]MailboxAddress, error) {
				if listName == "staff" {
					return []MailboxAddress{
						{LocalPart: "alice", Domain: "example.com"},
						{LocalPart: "bob", Domain: "example.com"},
					}, nil
				}
				return nil, fmt.Errorf("list not found")
			},
		}
		server, addr := startTestServer(t, config)
		defer server.Close()

		client := newTestClient(t, addr)
		defer client.close()

		client.expectCode(220)
		client.send("EHLO client.example.com")
		client.expectMultilineCode(250)

		// Valid list
		client.send("EXPN staff")
		lines := client.expectMultilineCode(250)
		if len(lines) < 2 {
			t.Errorf("Expected multiline response with list members, got %d lines", len(lines))
		}

		// Invalid list
		client.send("EXPN nonexistent")
		client.expectCode(550) // List not found

		client.send("QUIT")
		client.expectCode(221)
	})

	t.Run("SyntaxError", func(t *testing.T) {
		config := testServerConfig()
		server, addr := startTestServer(t, config)
		defer server.Close()

		client := newTestClient(t, addr)
		defer client.close()

		client.expectCode(220)
		client.send("EHLO client.example.com")
		client.expectMultilineCode(250)

		// EXPN without argument
		client.send("EXPN")
		client.expectCode(501) // Syntax error

		client.send("QUIT")
		client.expectCode(221)
	})
}

// ============================================================================
// Callback Tests - Additional
// ============================================================================

func TestOnDisconnectCallback(t *testing.T) {
	disconnectCalled := false
	var mu sync.Mutex

	config := testServerConfig()
	config.Callbacks = &Callbacks{
		OnDisconnect: func(ctx context.Context, conn *Connection) {
			mu.Lock()
			disconnectCalled = true
			mu.Unlock()
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	client.expectCode(220)
	client.send("QUIT")
	client.expectCode(221)
	client.close()

	// Wait a bit for disconnect callback to be called
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	if !disconnectCalled {
		t.Error("OnDisconnect callback was not called")
	}
	mu.Unlock()
}

func TestOnResetCallback(t *testing.T) {
	resetCalled := false
	var mu sync.Mutex

	config := testServerConfig()
	config.Callbacks = &Callbacks{
		OnReset: func(ctx context.Context, conn *Connection) {
			mu.Lock()
			resetCalled = true
			mu.Unlock()
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)
	client.send("MAIL FROM:<sender@example.com>")
	client.expectCode(250)

	// RSET should trigger callback
	client.send("RSET")
	client.expectCode(250)

	mu.Lock()
	if !resetCalled {
		t.Error("OnReset callback was not called")
	}
	mu.Unlock()

	client.send("QUIT")
	client.expectCode(221)
}

// ============================================================================
// Mail Loop Detection Tests
// ============================================================================

func TestMailLoopDetection(t *testing.T) {
	t.Run("Enabled", func(t *testing.T) {
		config := testServerConfig()
		config.MaxReceivedHeaders = 3 // Low limit for testing

		server, addr := startTestServer(t, config)
		defer server.Close()

		client := newTestClient(t, addr)
		defer client.close()

		client.expectCode(220)
		client.send("EHLO client.example.com")
		client.expectMultilineCode(250)
		client.send("MAIL FROM:<sender@example.com>")
		client.expectCode(250)
		client.send("RCPT TO:<recipient@example.com>")
		client.expectCode(250)
		client.send("DATA")
		client.expectCode(354)

		// Send message with too many Received headers (simulating loop)
		client.send("Received: from hop1.example.com by hop2.example.com")
		client.send("Received: from hop2.example.com by hop3.example.com")
		client.send("Received: from hop3.example.com by hop4.example.com")
		client.send("Received: from hop4.example.com by hop5.example.com")
		client.send("Subject: Test")
		client.send("")
		client.send("Body")
		client.send(".")

		// Should be rejected due to loop detection
		resp := client.readLine()
		code := 0
		fmt.Sscanf(resp, "%d", &code)
		if code != 554 {
			t.Errorf("Expected 554 for mail loop, got: %s", resp)
		}

		client.send("QUIT")
		client.expectCode(221)
	})

	t.Run("Disabled", func(t *testing.T) {
		var receivedMail *Mail
		var mu sync.Mutex

		config := testServerConfig()
		config.MaxReceivedHeaders = 0 // Disabled

		config.Callbacks = &Callbacks{
			OnMessage: func(ctx context.Context, conn *Connection, mail *Mail) error {
				mu.Lock()
				receivedMail = mail
				mu.Unlock()
				return nil
			},
		}

		server, addr := startTestServer(t, config)
		defer server.Close()

		client := newTestClient(t, addr)
		defer client.close()

		client.expectCode(220)
		client.send("EHLO client.example.com")
		client.expectMultilineCode(250)
		client.send("MAIL FROM:<sender@example.com>")
		client.expectCode(250)
		client.send("RCPT TO:<recipient@example.com>")
		client.expectCode(250)
		client.send("DATA")
		client.expectCode(354)

		// Many Received headers should be accepted when detection is disabled
		for i := range 10 {
			client.send(fmt.Sprintf("Received: from hop%d.example.com by hop%d.example.com", i, i+1))
		}
		client.send("Subject: Test")
		client.send("")
		client.send("Body")
		client.send(".")
		client.expectCode(250)

		mu.Lock()
		if receivedMail == nil {
			t.Error("Expected to receive mail when loop detection is disabled")
		}
		mu.Unlock()

		client.send("QUIT")
		client.expectCode(221)
	})
}

// ============================================================================
// AUTH Cancellation Tests
// ============================================================================

func TestAuthCancellation(t *testing.T) {
	authAttempted := false
	var mu sync.Mutex

	config := testServerConfig()
	config.AuthMechanisms = []string{"PLAIN"}
	config.Callbacks = &Callbacks{
		OnAuth: func(ctx context.Context, conn *Connection, mechanism, identity, password string) error {
			mu.Lock()
			authAttempted = true
			mu.Unlock()
			return nil
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	// Start AUTH PLAIN without initial response
	client.send("AUTH PLAIN")
	client.expectCode(334) // Challenge

	// Cancel with "*"
	client.send("*")
	resp := client.readLine()
	code := 0
	fmt.Sscanf(resp, "%d", &code)
	if code < 400 || code >= 600 {
		t.Errorf("Expected 4xx or 5xx code for cancelled auth, got: %s", resp)
	}

	// Auth callback should not be called for cancelled auth
	mu.Lock()
	if authAttempted {
		t.Error("OnAuth callback should not be called when auth is cancelled")
	}
	mu.Unlock()

	client.send("QUIT")
	client.expectCode(221)
}

// ============================================================================
// BDAT with BINARYMIME Tests
// ============================================================================

func TestBDATWithBinaryMIME(t *testing.T) {
	var receivedMail *Mail
	var mu sync.Mutex

	config := testServerConfig()
	config.EnableChunking = true
	config.Callbacks = &Callbacks{
		OnMessage: func(ctx context.Context, conn *Connection, mail *Mail) error {
			mu.Lock()
			receivedMail = mail
			mu.Unlock()
			return nil
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	lines := client.expectMultilineCode(250)

	// Verify BINARYMIME is advertised
	foundBinaryMIME := false
	for _, line := range lines {
		if strings.Contains(line, "BINARYMIME") {
			foundBinaryMIME = true
			break
		}
	}
	if !foundBinaryMIME {
		t.Error("Expected BINARYMIME to be advertised when CHUNKING is enabled")
	}

	// Use BODY=BINARYMIME
	client.send("MAIL FROM:<sender@example.com> BODY=BINARYMIME")
	client.expectCode(250)
	client.send("RCPT TO:<recipient@example.com>")
	client.expectCode(250)

	// Send binary data using BDAT
	// Include some bytes that would be invalid in 7bit (NUL, high bytes)
	binaryData := []byte("Subject: Binary test\r\n\r\nBinary data: \x00\x01\x02\xff\xfe")
	client.send(fmt.Sprintf("BDAT %d LAST", len(binaryData)))
	client.sendRaw(binaryData)
	client.expectCode(250)

	mu.Lock()
	if receivedMail == nil {
		t.Error("Expected to receive mail")
	} else if receivedMail.Envelope.BodyType != BodyTypeBinaryMIME {
		t.Errorf("Expected body type BINARYMIME, got %s", receivedMail.Envelope.BodyType)
	}
	mu.Unlock()

	client.send("QUIT")
	client.expectCode(221)
}

func TestBinaryMIMERequiresChunking(t *testing.T) {
	config := testServerConfig()
	config.EnableChunking = false // BINARYMIME requires CHUNKING

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	// BODY=BINARYMIME should fail when CHUNKING is disabled
	client.send("MAIL FROM:<sender@example.com> BODY=BINARYMIME")
	client.expectCode(504) // Parameter not implemented

	client.send("QUIT")
	client.expectCode(221)
}

// ============================================================================
// MaxErrors Tests
// ============================================================================

func TestMaxErrorsLimit(t *testing.T) {
	config := testServerConfig()
	config.MaxErrors = 3

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)

	// Generate errors up to the limit
	for i := range 3 {
		client.send("INVALID_COMMAND")
		resp := client.readLine()
		code := 0
		fmt.Sscanf(resp, "%d", &code)
		if code < 400 {
			t.Errorf("Error %d: Expected error code, got: %s", i+1, resp)
		}
	}

	// Next error should disconnect
	client.send("ANOTHER_INVALID")

	// Connection should be closed or we get a 421 (service not available)
	resp, err := client.reader.ReadString('\n')
	if err == nil {
		code := 0
		fmt.Sscanf(resp, "%d", &code)
		if code != 421 {
			t.Errorf("Expected 421 or connection close after max errors, got: %s", resp)
		}
	}
	// If err != nil, connection was closed as expected
}

// ============================================================================
// MaxCommands Tests
// ============================================================================

func TestMaxCommandsLimit(t *testing.T) {
	config := testServerConfig()
	config.MaxCommands = 5

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)

	// Send commands up to the limit
	for i := range 5 {
		client.send("NOOP")
		resp := client.readLine()
		code := 0
		fmt.Sscanf(resp, "%d", &code)
		if code != 250 {
			t.Errorf("Command %d: Expected 250, got: %s", i+1, resp)
		}
	}

	// Next command should fail or disconnect
	client.send("NOOP")
	resp, err := client.reader.ReadString('\n')
	if err == nil {
		code := 0
		fmt.Sscanf(resp, "%d", &code)
		// Could be 421 (service not available) or 503 (bad sequence)
		if code < 400 {
			t.Errorf("Expected error after max commands, got: %s", resp)
		}
	}
}

// ============================================================================
// Pipelining Tests
// ============================================================================

func TestPipelining(t *testing.T) {
	t.Run("Advertised", func(t *testing.T) {
		config := testServerConfig()
		server, addr := startTestServer(t, config)
		defer server.Close()

		client := newTestClient(t, addr)
		defer client.close()

		client.expectCode(220)
		client.send("EHLO client.example.com")
		lines := client.expectMultilineCode(250)

		found := false
		for _, line := range lines {
			if strings.Contains(line, "PIPELINING") {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected PIPELINING extension to be advertised")
		}

		client.send("QUIT")
		client.expectCode(221)
	})

	t.Run("PipelinedCommands", func(t *testing.T) {
		var receivedMail *Mail
		var mu sync.Mutex

		config := testServerConfig()
		config.Callbacks = &Callbacks{
			OnMessage: func(ctx context.Context, conn *Connection, mail *Mail) error {
				mu.Lock()
				receivedMail = mail
				mu.Unlock()
				return nil
			},
		}

		server, addr := startTestServer(t, config)
		defer server.Close()

		client := newTestClient(t, addr)
		defer client.close()

		client.expectCode(220)
		client.send("EHLO client.example.com")
		client.expectMultilineCode(250)

		// Send pipelined commands (multiple commands without waiting for responses)
		client.sendRaw([]byte("MAIL FROM:<sender@example.com>\r\nRCPT TO:<recipient@example.com>\r\nDATA\r\n"))

		// Read all three responses
		client.expectCode(250) // MAIL FROM
		client.expectCode(250) // RCPT TO
		client.expectCode(354) // DATA

		// Send data and terminator
		client.send("Subject: Pipelined Test")
		client.send("")
		client.send("Body")
		client.send(".")
		client.expectCode(250)

		mu.Lock()
		if receivedMail == nil {
			t.Error("Expected to receive mail via pipelining")
		}
		mu.Unlock()

		client.send("QUIT")
		client.expectCode(221)
	})
}

// ============================================================================
// Enhanced Status Codes Tests
// ============================================================================

func TestEnhancedStatusCodes(t *testing.T) {
	t.Run("Advertised", func(t *testing.T) {
		config := testServerConfig()
		server, addr := startTestServer(t, config)
		defer server.Close()

		client := newTestClient(t, addr)
		defer client.close()

		client.expectCode(220)
		client.send("EHLO client.example.com")
		lines := client.expectMultilineCode(250)

		found := false
		for _, line := range lines {
			if strings.Contains(line, "ENHANCEDSTATUSCODES") {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected ENHANCEDSTATUSCODES extension to be advertised")
		}

		client.send("QUIT")
		client.expectCode(221)
	})

	t.Run("InResponses", func(t *testing.T) {
		config := testServerConfig()
		server, addr := startTestServer(t, config)
		defer server.Close()

		client := newTestClient(t, addr)
		defer client.close()

		client.expectCode(220)
		client.send("EHLO client.example.com")
		client.expectMultilineCode(250)
		client.send("MAIL FROM:<sender@example.com>")
		resp := client.expectCode(250)

		// Response should contain enhanced status code like "2.1.0"
		if !strings.Contains(resp, "2.1.") {
			t.Errorf("Expected enhanced status code in response, got: %s", resp)
		}

		client.send("QUIT")
		client.expectCode(221)
	})
}

// ============================================================================
// Connection Info Tests
// ============================================================================

func TestConnectionInfoAvailableInCallbacks(t *testing.T) {
	var capturedRemoteAddr string
	var capturedLocalAddr string
	var mu sync.Mutex

	config := testServerConfig()
	config.Callbacks = &Callbacks{
		OnConnect: func(ctx context.Context, conn *Connection) error {
			mu.Lock()
			capturedRemoteAddr = conn.RemoteAddr().String()
			capturedLocalAddr = conn.LocalAddr().String()
			mu.Unlock()
			return nil
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)

	mu.Lock()
	if capturedRemoteAddr == "" {
		t.Error("Expected RemoteAddr to be captured")
	}
	if capturedLocalAddr == "" {
		t.Error("Expected LocalAddr to be captured")
	}
	mu.Unlock()

	client.send("QUIT")
	client.expectCode(221)
}

// ============================================================================
// Server Hostname Validation Tests
// ============================================================================

func TestServerRequiresHostname(t *testing.T) {
	config := ServerConfig{
		// Hostname not set
		Addr: "127.0.0.1:0",
	}

	_, err := NewServer(config)
	if err == nil {
		t.Error("Expected error when hostname is not set")
	}
	if !strings.Contains(err.Error(), "hostname") {
		t.Errorf("Expected hostname error, got: %v", err)
	}
}

// ============================================================================
// Null Sender (Bounce) Tests
// ============================================================================

func TestNullSender(t *testing.T) {
	var receivedMail *Mail
	var mu sync.Mutex

	config := testServerConfig()
	config.Callbacks = &Callbacks{
		OnMessage: func(ctx context.Context, conn *Connection, mail *Mail) error {
			mu.Lock()
			receivedMail = mail
			mu.Unlock()
			return nil
		},
	}

	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)
	client.send("EHLO client.example.com")
	client.expectMultilineCode(250)

	// Null sender (empty reverse-path) used for bounce messages
	client.send("MAIL FROM:<>")
	client.expectCode(250)
	client.send("RCPT TO:<recipient@example.com>")
	client.expectCode(250)
	client.send("DATA")
	client.expectCode(354)
	client.send("Subject: Bounce notification")
	client.send("")
	client.send("Your message could not be delivered.")
	client.send(".")
	client.expectCode(250)

	mu.Lock()
	if receivedMail == nil {
		t.Error("Expected to receive mail with null sender")
	} else if !receivedMail.Envelope.From.IsNull() {
		t.Errorf("Expected null sender, got: %v", receivedMail.Envelope.From)
	}
	mu.Unlock()

	client.send("QUIT")
	client.expectCode(221)
}

// ============================================================================
// Case Insensitivity Tests
// ============================================================================

func TestCommandsCaseInsensitive(t *testing.T) {
	config := testServerConfig()
	server, addr := startTestServer(t, config)
	defer server.Close()

	client := newTestClient(t, addr)
	defer client.close()

	client.expectCode(220)

	// Test various case combinations
	client.send("ehlo client.example.com") // lowercase
	client.expectMultilineCode(250)

	client.send("mail from:<sender@example.com>") // lowercase
	client.expectCode(250)

	client.send("RCPT TO:<recipient@example.com>") // uppercase
	client.expectCode(250)

	client.send("rSeT") // mixed case
	client.expectCode(250)

	client.send("NoOp") // mixed case
	client.expectCode(250)

	client.send("quit") // lowercase
	client.expectCode(221)
}
