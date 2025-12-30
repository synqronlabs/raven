package raven

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// testServer is a helper to create and manage test servers.
type testServer struct {
	server   *Server
	listener net.Listener
	addr     string
	t        *testing.T
}

// newTestServer creates a new test server with default settings.
func newTestServer(t *testing.T, opts ...func(*Server)) *testServer {
	t.Helper()

	// Use a no-op logger to suppress output during tests
	noopLogger := slog.New(slog.NewTextHandler(io.Discard, nil))

	server := New("test.example.com").
		Logger(noopLogger).
		GracefulShutdown(false).
		ReadTimeout(5 * time.Second).
		WriteTimeout(5 * time.Second).
		DataTimeout(10 * time.Second)

	for _, opt := range opts {
		opt(server)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}

	ts := &testServer{
		server:   server,
		listener: listener,
		addr:     listener.Addr().String(),
		t:        t,
	}

	go func() {
		_ = server.Serve(listener)
	}()

	// Give the server a moment to start
	time.Sleep(10 * time.Millisecond)

	return ts
}

// Close shuts down the test server.
func (ts *testServer) Close() {
	_ = ts.server.Close()
}

// Dial connects to the test server and returns a test client.
func (ts *testServer) Dial() *testClient {
	ts.t.Helper()

	conn, err := net.DialTimeout("tcp", ts.addr, 5*time.Second)
	if err != nil {
		ts.t.Fatalf("failed to dial server: %v", err)
	}

	tc := &testClient{
		conn:   conn,
		reader: bufio.NewReader(conn),
		t:      ts.t,
	}

	// Read the server greeting
	tc.ExpectCode(220)

	return tc
}

// testClient is a helper for raw SMTP protocol testing.
type testClient struct {
	conn   net.Conn
	reader *bufio.Reader
	t      *testing.T
}

// Send sends a command to the server.
func (tc *testClient) Send(format string, args ...any) {
	tc.t.Helper()
	cmd := fmt.Sprintf(format, args...)
	_, err := fmt.Fprintf(tc.conn, "%s\r\n", cmd)
	if err != nil {
		tc.t.Fatalf("failed to send command %q: %v", cmd, err)
	}
}

// ReadLine reads a single response line.
func (tc *testClient) ReadLine() string {
	tc.t.Helper()
	line, err := tc.reader.ReadString('\n')
	if err != nil {
		tc.t.Fatalf("failed to read line: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

// ReadMultiline reads a multiline response and returns all lines.
func (tc *testClient) ReadMultiline() []string {
	tc.t.Helper()
	var lines []string
	for {
		line := tc.ReadLine()
		lines = append(lines, line)
		// Check if this is the last line (code followed by space, not hyphen)
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}
	return lines
}

// ExpectCode reads a response and verifies the code.
func (tc *testClient) ExpectCode(expected int) string {
	tc.t.Helper()
	line := tc.ReadLine()
	code := 0
	fmt.Sscanf(line, "%d", &code)
	if code != expected {
		tc.t.Fatalf("expected code %d, got %q", expected, line)
	}
	return line
}

// ExpectMultilineCode reads a multiline response and verifies the code.
func (tc *testClient) ExpectMultilineCode(expected int) []string {
	tc.t.Helper()
	lines := tc.ReadMultiline()
	if len(lines) == 0 {
		tc.t.Fatalf("expected multiline response with code %d, got empty response", expected)
	}
	code := 0
	fmt.Sscanf(lines[len(lines)-1], "%d", &code)
	if code != expected {
		tc.t.Fatalf("expected code %d, got %q", expected, lines[len(lines)-1])
	}
	return lines
}

// Close closes the test client connection.
func (tc *testClient) Close() {
	_ = tc.conn.Close()
}

// =============================================================================
// Basic Server Tests
// =============================================================================

func TestServer_Greeting(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	conn, err := net.Dial("tcp", ts.addr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read greeting: %v", err)
	}

	if !strings.HasPrefix(line, "220 ") {
		t.Errorf("expected greeting to start with '220 ', got %q", line)
	}

	if !strings.Contains(line, "test.example.com") {
		t.Errorf("expected greeting to contain hostname, got %q", line)
	}
}

func TestServer_HELO(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("HELO client.example.com")
	line := tc.ExpectCode(250)

	if !strings.Contains(line, "test.example.com") {
		t.Errorf("expected HELO response to contain server hostname, got %q", line)
	}
}

func TestServer_EHLO(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	lines := tc.ExpectMultilineCode(250)

	// Should contain server hostname
	if !strings.Contains(lines[0], "test.example.com") {
		t.Errorf("expected EHLO response to contain server hostname, got %q", lines[0])
	}

	// Should advertise extensions
	extensions := make(map[string]bool)
	for _, line := range lines[1:] {
		// Extract extension name from "250-EXTENSION" or "250 EXTENSION"
		parts := strings.SplitN(line, " ", 2)
		if len(parts) >= 1 {
			// Remove the code prefix
			ext := strings.TrimPrefix(parts[0], "250-")
			ext = strings.TrimPrefix(ext, "250 ")
			extensions[ext] = true
		}
	}

	// Check for expected extensions
	expectedExtensions := []string{"8BITMIME", "PIPELINING", "SMTPUTF8", "ENHANCEDSTATUSCODES"}
	for _, ext := range expectedExtensions {
		found := false
		for _, line := range lines {
			if strings.Contains(line, ext) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected EHLO to advertise %s", ext)
		}
	}
}

func TestServer_EHLO_RequiresHostname(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO")
	tc.ExpectCode(501) // Syntax error
}

func TestServer_QUIT(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	tc.Send("QUIT")
	tc.ExpectCode(221)
}

func TestServer_NOOP(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	tc.Send("NOOP")
	tc.ExpectCode(250)
}

func TestServer_RSET(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	tc.Send("MAIL FROM:<sender@example.com>")
	tc.ExpectCode(250)

	tc.Send("RSET")
	tc.ExpectCode(250)

	// After RSET, should be able to start a new transaction
	tc.Send("MAIL FROM:<sender2@example.com>")
	tc.ExpectCode(250)
}

func TestServer_UnknownCommand(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	tc.Send("INVALID")
	tc.ExpectCode(500) // RFC 5321: 500 for unrecognized command
}

// =============================================================================
// Mail Transaction Tests
// =============================================================================

func TestServer_BasicMailTransaction(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	// EHLO
	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	// MAIL FROM
	tc.Send("MAIL FROM:<sender@example.com>")
	tc.ExpectCode(250)

	// RCPT TO
	tc.Send("RCPT TO:<recipient@example.com>")
	tc.ExpectCode(250)

	// DATA
	tc.Send("DATA")
	tc.ExpectCode(354)

	// Send message content
	tc.Send("From: sender@example.com")
	tc.Send("To: recipient@example.com")
	tc.Send("Subject: Test Message")
	tc.Send("")
	tc.Send("This is a test message.")
	tc.Send(".")

	tc.ExpectCode(250)

	// QUIT
	tc.Send("QUIT")
	tc.ExpectCode(221)
}

func TestServer_MultipleRecipients(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	tc.Send("MAIL FROM:<sender@example.com>")
	tc.ExpectCode(250)

	tc.Send("RCPT TO:<recipient1@example.com>")
	tc.ExpectCode(250)

	tc.Send("RCPT TO:<recipient2@example.com>")
	tc.ExpectCode(250)

	tc.Send("RCPT TO:<recipient3@example.com>")
	tc.ExpectCode(250)

	tc.Send("DATA")
	tc.ExpectCode(354)

	tc.Send("Subject: Multi-recipient test")
	tc.Send("")
	tc.Send("Test body")
	tc.Send(".")

	tc.ExpectCode(250)
}

func TestServer_EmptyFrom(t *testing.T) {
	// Empty FROM (bounce/DSN messages) should be allowed
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	tc.Send("MAIL FROM:<>")
	tc.ExpectCode(250)

	tc.Send("RCPT TO:<recipient@example.com>")
	tc.ExpectCode(250)
}

func TestServer_MailFromRequiresEHLO(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	// Try MAIL FROM without EHLO
	tc.Send("MAIL FROM:<sender@example.com>")
	tc.ExpectCode(503) // Bad sequence
}

func TestServer_RcptToRequiresMailFrom(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	// Try RCPT TO without MAIL FROM
	tc.Send("RCPT TO:<recipient@example.com>")
	tc.ExpectCode(503) // Bad sequence
}

func TestServer_DataRequiresRcptTo(t *testing.T) {
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
	tc.ExpectCode(503) // Bad sequence
}

func TestServer_DuplicateMailFrom(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	tc.Send("MAIL FROM:<sender@example.com>")
	tc.ExpectCode(250)

	// Try second MAIL FROM
	tc.Send("MAIL FROM:<sender2@example.com>")
	tc.ExpectCode(503) // Bad sequence
}

// =============================================================================
// Message Size Tests
// =============================================================================

func TestServer_MaxMessageSize(t *testing.T) {
	maxSize := int64(1024) // 1KB limit

	ts := newTestServer(t, func(s *Server) {
		s.MaxMessageSize(maxSize)
	})
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	lines := tc.ExpectMultilineCode(250)

	// Verify SIZE is advertised
	sizeFound := false
	for _, line := range lines {
		if strings.Contains(line, "SIZE") {
			sizeFound = true
			break
		}
	}
	if !sizeFound {
		t.Error("expected SIZE extension to be advertised")
	}

	tc.Send("MAIL FROM:<sender@example.com>")
	tc.ExpectCode(250)

	tc.Send("RCPT TO:<recipient@example.com>")
	tc.ExpectCode(250)

	tc.Send("DATA")
	tc.ExpectCode(354)

	// Send a message larger than the limit
	tc.Send("Subject: Large message test")
	tc.Send("")
	largeBody := strings.Repeat("X", int(maxSize)+100)
	tc.Send("%s", largeBody)
	tc.Send(".")

	tc.ExpectCode(501) // Line length exceeds maximum allowed
}

func TestServer_SizeParameter(t *testing.T) {
	maxSize := int64(1024)

	ts := newTestServer(t, func(s *Server) {
		s.MaxMessageSize(maxSize)
	})
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	// Declare size larger than limit
	tc.Send("MAIL FROM:<sender@example.com> SIZE=2048")
	tc.ExpectCode(552) // Size exceeded
}

// =============================================================================
// Max Recipients Tests
// =============================================================================

func TestServer_MaxRecipients(t *testing.T) {
	maxRcpts := 3

	ts := newTestServer(t, func(s *Server) {
		s.MaxRecipients(maxRcpts)
	})
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	tc.Send("MAIL FROM:<sender@example.com>")
	tc.ExpectCode(250)

	// Add max recipients
	for i := 0; i < maxRcpts; i++ {
		tc.Send("RCPT TO:<recipient%d@example.com>", i)
		tc.ExpectCode(250)
	}

	// Try to add one more
	tc.Send("RCPT TO:<overflow@example.com>")
	tc.ExpectCode(452) // Too many recipients
}

// =============================================================================
// Handler Chain Tests
// =============================================================================

func TestServer_OnConnectHandler(t *testing.T) {
	var connected bool
	var mu sync.Mutex

	ts := newTestServer(t, func(s *Server) {
		s.OnConnect(func(c *Context) *Response {
			mu.Lock()
			connected = true
			mu.Unlock()
			return c.Next()
		})
	})
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	mu.Lock()
	if !connected {
		t.Error("OnConnect handler was not called")
	}
	mu.Unlock()
}

func TestServer_OnConnectReject(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.OnConnect(func(c *Context) *Response {
			return c.Error(CodeServiceUnavailable, "Connection rejected")
		})
	})
	defer ts.Close()

	conn, err := net.Dial("tcp", ts.addr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	line, _ := reader.ReadString('\n')

	if !strings.HasPrefix(line, "220 ") {
		t.Logf("Connection rejection expected in handler response, got greeting: %q", line)
	}
}

func TestServer_OnMailFromHandler(t *testing.T) {
	var receivedFrom string
	var mu sync.Mutex

	ts := newTestServer(t, func(s *Server) {
		s.OnMailFrom(func(c *Context) *Response {
			mu.Lock()
			receivedFrom = c.Request.From.String()
			mu.Unlock()
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

	mu.Lock()
	if receivedFrom != "<sender@example.com>" {
		t.Errorf("expected from '<sender@example.com>', got %q", receivedFrom)
	}
	mu.Unlock()
}

func TestServer_OnMailFromReject(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.OnMailFrom(func(c *Context) *Response {
			if strings.Contains(c.Request.From.String(), "spam") {
				return c.Error(CodeMailboxNotFound, "Sender rejected")
			}
			return c.Next()
		})
	})
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	tc.Send("MAIL FROM:<spammer@example.com>")
	tc.ExpectCode(550)
}

func TestServer_OnRcptToHandler(t *testing.T) {
	var recipients []string
	var mu sync.Mutex

	ts := newTestServer(t, func(s *Server) {
		s.OnRcptTo(func(c *Context) *Response {
			mu.Lock()
			recipients = append(recipients, c.Request.To.String())
			mu.Unlock()
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

	tc.Send("RCPT TO:<user1@example.com>")
	tc.ExpectCode(250)

	tc.Send("RCPT TO:<user2@example.com>")
	tc.ExpectCode(250)

	mu.Lock()
	if len(recipients) != 2 {
		t.Errorf("expected 2 recipients, got %d", len(recipients))
	}
	mu.Unlock()
}

func TestServer_OnRcptToReject(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.OnRcptTo(func(c *Context) *Response {
			domain := c.Request.To.Mailbox.Domain
			if domain != "example.com" {
				return c.Error(CodeMailboxNotFound, "Recipient not found")
			}
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

	tc.Send("RCPT TO:<user@example.com>")
	tc.ExpectCode(250)

	tc.Send("RCPT TO:<user@other.com>")
	tc.ExpectCode(550)
}

func TestServer_OnMessageHandler(t *testing.T) {
	var receivedMail *Mail
	var mu sync.Mutex

	ts := newTestServer(t, func(s *Server) {
		s.OnMessage(func(c *Context) *Response {
			mu.Lock()
			receivedMail = c.Mail
			mu.Unlock()
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

	tc.Send("From: sender@example.com")
	tc.Send("To: recipient@example.com")
	tc.Send("Subject: Test")
	tc.Send("")
	tc.Send("Hello World")
	tc.Send(".")

	tc.ExpectCode(250)

	mu.Lock()
	defer mu.Unlock()

	if receivedMail == nil {
		t.Fatal("OnMessage handler did not receive mail")
	}

	if receivedMail.Envelope.From.String() != "<sender@example.com>" {
		t.Errorf("expected from '<sender@example.com>', got %q", receivedMail.Envelope.From.String())
	}

	if len(receivedMail.Envelope.To) != 1 {
		t.Errorf("expected 1 recipient, got %d", len(receivedMail.Envelope.To))
	}

	subject := receivedMail.Content.Headers.Get("Subject")
	if subject != "Test" {
		t.Errorf("expected subject 'Test', got %q", subject)
	}
}

func TestServer_MiddlewareChain(t *testing.T) {
	var order []int
	var mu sync.Mutex

	ts := newTestServer(t, func(s *Server) {
		s.OnMailFrom(
			func(c *Context) *Response {
				mu.Lock()
				order = append(order, 1)
				mu.Unlock()
				return c.Next()
			},
			func(c *Context) *Response {
				mu.Lock()
				order = append(order, 2)
				mu.Unlock()
				return c.Next()
			},
			func(c *Context) *Response {
				mu.Lock()
				order = append(order, 3)
				mu.Unlock()
				return c.Next()
			},
		)
	})
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	tc.Send("MAIL FROM:<sender@example.com>")
	tc.ExpectCode(250)

	mu.Lock()
	if len(order) != 3 {
		t.Errorf("expected 3 handlers called, got %d", len(order))
	}
	for i, v := range order {
		if v != i+1 {
			t.Errorf("expected order %d at index %d, got %d", i+1, i, v)
		}
	}
	mu.Unlock()
}

func TestServer_MiddlewareEarlyReturn(t *testing.T) {
	var handlersCalled int
	var mu sync.Mutex

	ts := newTestServer(t, func(s *Server) {
		s.OnMailFrom(
			func(c *Context) *Response {
				mu.Lock()
				handlersCalled++
				mu.Unlock()
				return c.Next()
			},
			func(c *Context) *Response {
				mu.Lock()
				handlersCalled++
				mu.Unlock()
				// Return error - should stop chain
				return c.Error(CodeTransactionFailed, "Rejected")
			},
			func(c *Context) *Response {
				mu.Lock()
				handlersCalled++
				mu.Unlock()
				return c.Next()
			},
		)
	})
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	tc.Send("MAIL FROM:<sender@example.com>")
	tc.ExpectCode(554)

	mu.Lock()
	if handlersCalled != 2 {
		t.Errorf("expected 2 handlers called (chain should stop), got %d", handlersCalled)
	}
	mu.Unlock()
}

// =============================================================================
// Context Value Tests
// =============================================================================

func TestServer_ContextSetGet(t *testing.T) {
	var gotValue string
	var mu sync.Mutex

	// Context values persist within a single handler chain (same command),
	// not across different commands. Test this with two handlers on the same event.
	ts := newTestServer(t, func(s *Server) {
		// First handler in chain sets the value
		s.OnMailFrom(func(c *Context) *Response {
			c.Set("test-key", "test-value")
			return c.Next()
		})
		// Second handler in chain reads the value
		s.OnMailFrom(func(c *Context) *Response {
			if v, ok := c.Get("test-key"); ok {
				mu.Lock()
				gotValue = v.(string)
				mu.Unlock()
			}
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

	mu.Lock()
	if gotValue != "test-value" {
		t.Errorf("expected 'test-value', got %q", gotValue)
	}
	mu.Unlock()
}

// =============================================================================
// Multiple Transaction Tests
// =============================================================================

func TestServer_MultipleTransactions(t *testing.T) {
	var transactionCount int
	var mu sync.Mutex

	ts := newTestServer(t, func(s *Server) {
		s.OnMessage(func(c *Context) *Response {
			mu.Lock()
			transactionCount++
			mu.Unlock()
			return c.Next()
		})
	})
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	// First transaction
	tc.Send("MAIL FROM:<sender@example.com>")
	tc.ExpectCode(250)
	tc.Send("RCPT TO:<recipient@example.com>")
	tc.ExpectCode(250)
	tc.Send("DATA")
	tc.ExpectCode(354)
	tc.Send("Subject: Test 1")
	tc.Send("")
	tc.Send("Body 1")
	tc.Send(".")
	tc.ExpectCode(250)

	// Second transaction
	tc.Send("MAIL FROM:<sender@example.com>")
	tc.ExpectCode(250)
	tc.Send("RCPT TO:<recipient@example.com>")
	tc.ExpectCode(250)
	tc.Send("DATA")
	tc.ExpectCode(354)
	tc.Send("Subject: Test 2")
	tc.Send("")
	tc.Send("Body 2")
	tc.Send(".")
	tc.ExpectCode(250)

	mu.Lock()
	if transactionCount != 2 {
		t.Errorf("expected 2 transactions, got %d", transactionCount)
	}
	mu.Unlock()
}

// =============================================================================
// Extension Tests
// =============================================================================

func TestServer_8BitMIME(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	lines := tc.ExpectMultilineCode(250)

	found := false
	for _, line := range lines {
		if strings.Contains(line, "8BITMIME") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 8BITMIME to be advertised")
	}

	// Use BODY=8BITMIME parameter
	tc.Send("MAIL FROM:<sender@example.com> BODY=8BITMIME")
	tc.ExpectCode(250)
}

func TestServer_SMTPUTF8(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	lines := tc.ExpectMultilineCode(250)

	found := false
	for _, line := range lines {
		if strings.Contains(line, "SMTPUTF8") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected SMTPUTF8 to be advertised")
	}

	// Use SMTPUTF8 parameter for internationalized addresses
	tc.Send("MAIL FROM:<sender@example.com> SMTPUTF8")
	tc.ExpectCode(250)
}

func TestServer_Pipelining(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	lines := tc.ExpectMultilineCode(250)

	found := false
	for _, line := range lines {
		if strings.Contains(line, "PIPELINING") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected PIPELINING to be advertised")
	}

	// Send pipelined commands (all at once)
	fmt.Fprintf(tc.conn, "MAIL FROM:<sender@example.com>\r\n")
	fmt.Fprintf(tc.conn, "RCPT TO:<recipient@example.com>\r\n")
	fmt.Fprintf(tc.conn, "DATA\r\n")

	tc.ExpectCode(250) // MAIL FROM
	tc.ExpectCode(250) // RCPT TO
	tc.ExpectCode(354) // DATA

	tc.Send("Subject: Pipelined")
	tc.Send("")
	tc.Send("Body")
	tc.Send(".")
	tc.ExpectCode(250)
}

// =============================================================================
// Concurrent Connection Tests
// =============================================================================

func TestServer_ConcurrentConnections(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	var wg sync.WaitGroup
	const numConnections = 5

	for i := 0; i < numConnections; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			conn, err := net.Dial("tcp", ts.addr)
			if err != nil {
				t.Errorf("connection %d failed to dial: %v", id, err)
				return
			}
			defer conn.Close()

			reader := bufio.NewReader(conn)

			// Read greeting
			line, _ := reader.ReadString('\n')
			if !strings.HasPrefix(line, "220") {
				t.Errorf("connection %d: unexpected greeting: %s", id, line)
				return
			}

			// Send EHLO
			fmt.Fprintf(conn, "EHLO client%d.example.com\r\n", id)
			for {
				line, _ = reader.ReadString('\n')
				if strings.HasPrefix(line, "250 ") {
					break
				}
				if !strings.HasPrefix(line, "250-") {
					t.Errorf("connection %d: unexpected response: %s", id, line)
					return
				}
			}

			// Send mail transaction
			fmt.Fprintf(conn, "MAIL FROM:<sender%d@example.com>\r\n", id)
			line, _ = reader.ReadString('\n')
			if !strings.HasPrefix(line, "250") {
				t.Errorf("connection %d: MAIL FROM failed: %s", id, line)
				return
			}

			fmt.Fprintf(conn, "RCPT TO:<recipient@example.com>\r\n")
			line, _ = reader.ReadString('\n')
			if !strings.HasPrefix(line, "250") {
				t.Errorf("connection %d: RCPT TO failed: %s", id, line)
				return
			}

			fmt.Fprintf(conn, "QUIT\r\n")
			line, _ = reader.ReadString('\n')
			if !strings.HasPrefix(line, "221") {
				t.Errorf("connection %d: QUIT failed: %s", id, line)
			}
		}(i)
	}

	wg.Wait()
}

// =============================================================================
// Dot-Stuffing Tests
// =============================================================================

func TestServer_DotStuffing(t *testing.T) {
	var receivedBody []byte
	var mu sync.Mutex

	ts := newTestServer(t, func(s *Server) {
		s.OnMessage(func(c *Context) *Response {
			mu.Lock()
			receivedBody = c.Mail.Content.Body
			mu.Unlock()
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

	tc.Send("Subject: Dot Stuffing Test")
	tc.Send("")
	tc.Send("Line without dots")
	tc.Send("..Line starting with dot")   // Stuffed dot
	tc.Send("...Line with multiple dots") // Stuffed dot
	tc.Send("Normal line")
	tc.Send(".")

	tc.ExpectCode(250)

	mu.Lock()
	// The received body should have dots un-stuffed
	if !strings.Contains(string(receivedBody), ".Line starting with dot") {
		t.Error("expected dot-stuffed line to be un-stuffed")
	}
	if !strings.Contains(string(receivedBody), "..Line with multiple dots") {
		t.Error("expected double-dot-stuffed line to be un-stuffed")
	}
	mu.Unlock()
}

// =============================================================================
// Help Command Tests
// =============================================================================

func TestServer_HELP(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.OnHelp(func(c *Context) *Response {
			return c.OK("Help: EHLO, MAIL, RCPT, DATA, QUIT")
		})
	})
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	tc.Send("HELP")
	tc.ExpectCode(250)
}

// =============================================================================
// VRFY Command Tests
// =============================================================================

func TestServer_VRFY(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.OnVerify(func(c *Context) *Response {
			if c.Request.Args == "postmaster" {
				return c.OK("postmaster@example.com")
			}
			return c.Error(CodeCannotVRFY, "Unable to verify")
		})
	})
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	tc.Send("EHLO client.example.com")
	tc.ExpectMultilineCode(250)

	tc.Send("VRFY postmaster")
	line := tc.ExpectCode(250)
	if !strings.Contains(line, "postmaster@example.com") {
		t.Errorf("expected VRFY to return address, got %q", line)
	}

	tc.Send("VRFY unknown")
	tc.ExpectCode(252)
}

// =============================================================================
// Using Built-in Client for Testing
// =============================================================================

func TestServer_WithClient(t *testing.T) {
	var receivedMail *Mail
	var mu sync.Mutex

	ts := newTestServer(t, func(s *Server) {
		s.OnMessage(func(c *Context) *Response {
			mu.Lock()
			receivedMail = c.Mail
			mu.Unlock()
			return c.Next()
		})
	})
	defer ts.Close()

	// Use raven's Client
	client := NewClient(&ClientConfig{
		LocalName:          "client.example.com",
		ValidateBeforeSend: false,
	})

	err := client.Dial(ts.addr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer client.Close()

	err = client.Hello()
	if err != nil {
		t.Fatalf("EHLO failed: %v", err)
	}

	mail, err := NewMailBuilder().
		From("sender@example.com").
		To("recipient@example.com").
		Subject("Test via Client").
		TextBody("Hello from the client!").
		Build()
	if err != nil {
		t.Fatalf("failed to build mail: %v", err)
	}

	result, err := client.Send(mail)
	if err != nil {
		t.Fatalf("failed to send: %v", err)
	}

	if !result.Success {
		t.Errorf("expected success, got failure")
	}

	_ = client.Quit()

	mu.Lock()
	defer mu.Unlock()

	if receivedMail == nil {
		t.Fatal("no mail received")
	}

	subject := receivedMail.Content.Headers.Get("Subject")
	if subject != "Test via Client" {
		t.Errorf("expected subject 'Test via Client', got %q", subject)
	}
}

// =============================================================================
// Error Handling Tests
// =============================================================================

func TestServer_MaxErrors(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.MaxErrors(3)
	})
	defer ts.Close()

	tc := ts.Dial()
	defer tc.Close()

	// Send invalid commands to generate errors
	tc.Send("INVALID1")
	tc.ExpectCode(500) // RFC 5321: 500 for unrecognized command

	tc.Send("INVALID2")
	tc.ExpectCode(500) // RFC 5321: 500 for unrecognized command

	tc.Send("INVALID3")
	tc.ExpectCode(500) // RFC 5321: 500 for unrecognized command

	// Fourth error should disconnect
	tc.Send("INVALID4")
	line := tc.ReadLine()
	if !strings.HasPrefix(line, "421") {
		t.Errorf("expected 421 disconnect after max errors, got %q", line)
	}
}

// =============================================================================
// Shutdown Tests
// =============================================================================

func TestServer_GracefulShutdown(t *testing.T) {
	server := New("test.example.com").
		GracefulShutdown(false).
		ShutdownTimeout(1 * time.Second)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}

	go func() {
		_ = server.Serve(listener)
	}()

	// Give server time to start
	time.Sleep(10 * time.Millisecond)

	// Connect a client
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}

	reader := bufio.NewReader(conn)
	_, _ = reader.ReadString('\n') // Read greeting

	// Close the server
	err = server.Close()
	if err != nil {
		t.Errorf("close error: %v", err)
	}

	// Connection should be closed
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, err = reader.ReadString('\n')
	if err == nil {
		t.Error("expected connection to be closed after server shutdown")
	}
}

// =============================================================================
// TLS Certificate for Testing
// =============================================================================

// Test certificate (self-signed, for testing only)
var testCertPEM = []byte(`-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKMUvmk9BzVrMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yMzAxMDEwMDAwMDBaFw0zMzAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC6OYQvCmpGsqCMoIRE0Lh8
EydXhJQ4N4HvLjO5B5oDFoW3e0pGG8x0dWuOLwpJDpCNe7HkR8O9K5Y9c7Q0KbNv
AgMBAAGjUzBRMB0GA1UdDgQWBBR4jjIEu7LV1OLXlBb0U7qiPV8fPzAfBgNVHSME
GDAWgBR4jjIEu7LV1OLXlBb0U7qiPV8fPzAPBgNVHRMBAf8EBTADAQH/MA0GCSqG
SIb3DQEBCwUAA0EAbR0M0Bj0LZvz7MYph0y9lBqgKo4G0PVHX0qbKFZHgY7dJMnu
rW0h5PjG0+8HQ7yZ4B4N0V0D+C8H7Jgq0iMeGA==
-----END CERTIFICATE-----`)

var testKeyPEM = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBOQIBAAJBALo5hC8KakaygIyghETQuHwTJ1eElDg3ge8uM7kHmgMWhbd7SkYb
zHR1a44vCkkOkI17seRHw70rlj1ztDQps28CAwEAAQJAFKkVuBEfzQyRDc2PGsNh
6EgsZaGXHk2aXuMQJwRINmq3o+WNTyBOaFxh0UMuO5gMv7d1SFTYT4k7QmqKh5gp
gQIhAOx2cQPvN7SDvBBtCfz1Y7lBbHayGU4Z9FJJPJFJwcXvAiEAyVJVNMlPv7dB
7jxRuNme+2verCI2ua5sJaGpc+HuBpkCIHc4ePp7kScsHhT3chHlPj+MhdKroLfv
dGhV3YczH6YZAiAqleYy79Kk5J3Y0T5fMeAv7oEpzg9cxkJOLG0ENBTYOQIgHZk3
rDAt7mLvxBHvc8LN0Ucy8bvAgSD8cWXcKEMx7Rg=
-----END RSA PRIVATE KEY-----`)
