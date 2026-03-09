package server_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/synqronlabs/raven/server"
)

// =============================================================================
// Test Helpers
// =============================================================================

// testBackend is a simple Backend for testing.
type testBackend struct {
	sessionFactory func(c *server.Conn) (server.Session, error)
}

func (b *testBackend) NewSession(c *server.Conn) (server.Session, error) {
	if b.sessionFactory != nil {
		return b.sessionFactory(c)
	}
	return &testSession{}, nil
}

// testSession is a simple Session for testing.
type testSession struct {
	from       string
	recipients []string
	data       []byte
	t          *testing.T

	// completed tracks completed transactions (from, to, data copied before reset)
	completed []testTransaction

	// For testing rejection behavior
	rejectMail func(from string) error
	rejectRcpt func(to string) error
}

type testTransaction struct {
	from       string
	recipients []string
	data       []byte
}

func (s *testSession) Mail(from string, _ *server.MailOptions) error {
	if s.rejectMail != nil {
		if err := s.rejectMail(from); err != nil {
			return err
		}
	}
	s.from = from
	return nil
}

func (s *testSession) Rcpt(to string, _ *server.RcptOptions) error {
	if s.rejectRcpt != nil {
		if err := s.rejectRcpt(to); err != nil {
			return err
		}
	}
	s.recipients = append(s.recipients, to)
	return nil
}

func (s *testSession) Data(r io.Reader) error {
	var err error
	s.data, err = io.ReadAll(r)
	if err == nil {
		// Save completed transaction before Reset clears it
		s.completed = append(s.completed, testTransaction{
			from:       s.from,
			recipients: append([]string(nil), s.recipients...),
			data:       append([]byte(nil), s.data...),
		})
	}
	return err
}

func (s *testSession) Reset() {
	s.from = ""
	s.recipients = nil
	s.data = nil
}

func (s *testSession) Logout() error {
	return nil
}

// testServer wraps a server.Server for testing.
type testServer struct {
	srv      *server.Server
	listener net.Listener
	cancel   context.CancelFunc
	t        *testing.T
}

func newTestServer(t *testing.T, backend server.Backend, cfg server.ServerConfig) *testServer {
	t.Helper()

	if cfg.Domain == "" {
		cfg.Domain = "test.example.com"
	}

	srv := server.NewServer(backend, cfg)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		if err := srv.Serve(ctx, l); err != nil {
			_ = err
		}
	}()

	// Give server time to start
	time.Sleep(10 * time.Millisecond)

	return &testServer{
		srv:      srv,
		listener: l,
		cancel:   cancel,
		t:        t,
	}
}

func (ts *testServer) dial() *testClient {
	ts.t.Helper()

	conn, err := net.DialTimeout("tcp", ts.listener.Addr().String(), 5*time.Second)
	if err != nil {
		ts.t.Fatalf("dial failed: %v", err)
	}

	tc := &testClient{
		conn:   conn,
		reader: bufio.NewReader(conn),
		t:      ts.t,
	}

	// Read greeting
	tc.expectCode(220)

	return tc
}

func (ts *testServer) close() {
	ts.cancel()
	ts.listener.Close()
}

// testClient is a helper for raw SMTP protocol testing.
type testClient struct {
	conn   net.Conn
	reader *bufio.Reader
	t      *testing.T
}

func (c *testClient) send(format string, args ...any) {
	cmd := fmt.Sprintf(format, args...)
	_, err := fmt.Fprintf(c.conn, "%s\r\n", cmd)
	if err != nil {
		c.t.Fatalf("send failed: %v", err)
	}
}

func (c *testClient) readLine() string {
	line, err := c.reader.ReadString('\n')
	if err != nil {
		c.t.Fatalf("readLine failed: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

func (c *testClient) expectCode(code int) string {
	line := c.readLine()
	var gotCode int
	if _, err := fmt.Sscanf(line, "%d", &gotCode); err != nil {
		c.t.Fatalf("failed to parse SMTP status code from %q: %v", line, err)
	}
	if gotCode != code {
		c.t.Fatalf("expected code %d, got: %s", code, line)
	}
	return line
}

func (c *testClient) expectMultilineCode(code int) []string {
	var lines []string
	for {
		line := c.readLine()
		lines = append(lines, line)
		var gotCode int
		if _, err := fmt.Sscanf(line, "%d", &gotCode); err != nil {
			c.t.Fatalf("failed to parse SMTP status code from %q: %v", line, err)
		}
		if gotCode != code {
			c.t.Fatalf("expected code %d, got: %s", code, line)
		}
		// Check if last line (space after code vs dash)
		if len(line) > 3 && line[3] == ' ' {
			break
		}
	}
	return lines
}

func (c *testClient) close() {
	c.conn.Close()
}

// =============================================================================
// Basic Server Tests
// =============================================================================

func TestServer_Greeting(t *testing.T) {
	backend := &testBackend{}
	ts := newTestServer(t, backend, server.ServerConfig{
		Domain: "mail.example.com",
	})
	defer ts.close()

	conn, err := net.Dial("tcp", ts.listener.Addr().String())
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read greeting failed: %v", err)
	}

	if !strings.HasPrefix(line, "220 ") {
		t.Errorf("expected greeting to start with '220 ', got %q", line)
	}
	if !strings.Contains(line, "mail.example.com") {
		t.Errorf("expected greeting to contain hostname, got %q", line)
	}
}

func TestServer_HELO(t *testing.T) {
	backend := &testBackend{}
	ts := newTestServer(t, backend, server.ServerConfig{})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("HELO client.example.com")
	line := tc.expectCode(250)

	if !strings.Contains(line, "test.example.com") {
		t.Errorf("expected HELO response to contain server hostname, got %q", line)
	}
}

func TestServer_EHLO(t *testing.T) {
	backend := &testBackend{}
	ts := newTestServer(t, backend, server.ServerConfig{
		EnableSMTPUTF8: true,
	})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.example.com")
	lines := tc.expectMultilineCode(250)

	// Should contain server hostname
	if !strings.Contains(lines[0], "test.example.com") {
		t.Errorf("expected EHLO response to contain server hostname, got %q", lines[0])
	}

	// Check for expected extensions
	extensions := strings.Join(lines, " ")
	expected := []string{"8BITMIME", "PIPELINING", "SMTPUTF8", "ENHANCEDSTATUSCODES"}
	for _, ext := range expected {
		if !strings.Contains(extensions, ext) {
			t.Errorf("expected EHLO to advertise %s, got: %v", ext, lines)
		}
	}
}

func TestServer_EHLO_RequiresHostname(t *testing.T) {
	backend := &testBackend{}
	ts := newTestServer(t, backend, server.ServerConfig{})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO")
	tc.expectCode(501) // Syntax error
}

func TestServer_QUIT(t *testing.T) {
	backend := &testBackend{}
	ts := newTestServer(t, backend, server.ServerConfig{})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.example.com")
	tc.expectMultilineCode(250)

	tc.send("QUIT")
	tc.expectCode(221)
}

func TestServer_NOOP(t *testing.T) {
	backend := &testBackend{}
	ts := newTestServer(t, backend, server.ServerConfig{})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.example.com")
	tc.expectMultilineCode(250)

	tc.send("NOOP")
	tc.expectCode(250)
}

func TestServer_RSET(t *testing.T) {
	backend := &testBackend{}
	ts := newTestServer(t, backend, server.ServerConfig{})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.example.com")
	tc.expectMultilineCode(250)

	tc.send("MAIL FROM:<sender@example.com>")
	tc.expectCode(250)

	tc.send("RSET")
	tc.expectCode(250)

	// After RSET, should be able to start a new transaction
	tc.send("MAIL FROM:<sender2@example.com>")
	tc.expectCode(250)
}

func TestServer_UnknownCommand(t *testing.T) {
	backend := &testBackend{}
	ts := newTestServer(t, backend, server.ServerConfig{})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.example.com")
	tc.expectMultilineCode(250)

	tc.send("INVALID")
	tc.expectCode(500) // Command not recognized
}

// =============================================================================
// Mail Transaction Tests
// =============================================================================

func TestServer_BasicMailTransaction(t *testing.T) {
	sessions := make([]*testSession, 0)
	var mu sync.Mutex
	backend := &testBackend{
		sessionFactory: func(_ *server.Conn) (server.Session, error) {
			s := &testSession{}
			mu.Lock()
			sessions = append(sessions, s)
			mu.Unlock()
			return s, nil
		},
	}
	ts := newTestServer(t, backend, server.ServerConfig{})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.example.com")
	tc.expectMultilineCode(250)

	tc.send("MAIL FROM:<sender@example.com>")
	tc.expectCode(250)

	tc.send("RCPT TO:<recipient@example.com>")
	tc.expectCode(250)

	tc.send("DATA")
	tc.expectCode(354)

	tc.send("From: sender@example.com")
	tc.send("To: recipient@example.com")
	tc.send("Subject: Test Message")
	tc.send("")
	tc.send("This is a test message.")
	tc.send(".")
	tc.expectCode(250)

	tc.send("QUIT")
	tc.expectCode(221)

	// Give server time to process
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(sessions) == 0 {
		t.Fatal("no session was created")
	}
	s := sessions[0]
	if len(s.completed) == 0 {
		t.Fatal("no completed transaction")
	}
	tx := s.completed[0]
	if tx.from != "sender@example.com" {
		t.Errorf("expected from 'sender@example.com', got %q", tx.from)
	}
	if len(tx.recipients) != 1 || tx.recipients[0] != "recipient@example.com" {
		t.Errorf("expected 1 recipient 'recipient@example.com', got %v", tx.recipients)
	}
}

func TestServer_MultipleRecipients(t *testing.T) {
	sessions := make([]*testSession, 0)
	var mu sync.Mutex
	backend := &testBackend{
		sessionFactory: func(_ *server.Conn) (server.Session, error) {
			s := &testSession{}
			mu.Lock()
			sessions = append(sessions, s)
			mu.Unlock()
			return s, nil
		},
	}
	ts := newTestServer(t, backend, server.ServerConfig{})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.example.com")
	tc.expectMultilineCode(250)

	tc.send("MAIL FROM:<sender@example.com>")
	tc.expectCode(250)

	tc.send("RCPT TO:<recipient1@example.com>")
	tc.expectCode(250)

	tc.send("RCPT TO:<recipient2@example.com>")
	tc.expectCode(250)

	tc.send("RCPT TO:<recipient3@example.com>")
	tc.expectCode(250)

	tc.send("DATA")
	tc.expectCode(354)

	tc.send("Subject: Multi-recipient test")
	tc.send("")
	tc.send("Test body")
	tc.send(".")
	tc.expectCode(250)

	// Give server time to process
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(sessions) == 0 {
		t.Fatal("no session was created")
	}
	s := sessions[0]
	if len(s.completed) == 0 {
		t.Fatal("no completed transaction")
	}
	tx := s.completed[0]
	if len(tx.recipients) != 3 {
		t.Errorf("expected 3 recipients, got %d: %v", len(tx.recipients), tx.recipients)
	}
}

func TestServer_EmptyFrom(t *testing.T) {
	// Empty FROM (bounce/DSN messages) should be allowed
	backend := &testBackend{}
	ts := newTestServer(t, backend, server.ServerConfig{})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.example.com")
	tc.expectMultilineCode(250)

	tc.send("MAIL FROM:<>")
	tc.expectCode(250)

	tc.send("RCPT TO:<recipient@example.com>")
	tc.expectCode(250)
}

// =============================================================================
// Bad Sequence Tests
// =============================================================================

func TestServer_MailFromRequiresEHLO(t *testing.T) {
	backend := &testBackend{}
	ts := newTestServer(t, backend, server.ServerConfig{})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	// Try MAIL FROM without EHLO
	tc.send("MAIL FROM:<sender@example.com>")
	tc.expectCode(503) // Bad sequence
}

func TestServer_RcptToRequiresMailFrom(t *testing.T) {
	backend := &testBackend{}
	ts := newTestServer(t, backend, server.ServerConfig{})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.example.com")
	tc.expectMultilineCode(250)

	// Try RCPT TO without MAIL FROM
	tc.send("RCPT TO:<recipient@example.com>")
	tc.expectCode(503) // Bad sequence
}

func TestServer_DataRequiresRcptTo(t *testing.T) {
	backend := &testBackend{}
	ts := newTestServer(t, backend, server.ServerConfig{})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.example.com")
	tc.expectMultilineCode(250)

	tc.send("MAIL FROM:<sender@example.com>")
	tc.expectCode(250)

	// Try DATA without RCPT TO
	tc.send("DATA")
	tc.expectCode(503) // Bad sequence
}

func TestServer_DuplicateMailFrom(t *testing.T) {
	backend := &testBackend{}
	ts := newTestServer(t, backend, server.ServerConfig{})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.example.com")
	tc.expectMultilineCode(250)

	tc.send("MAIL FROM:<sender@example.com>")
	tc.expectCode(250)

	// Try second MAIL FROM
	tc.send("MAIL FROM:<sender2@example.com>")
	tc.expectCode(503) // Bad sequence
}

// =============================================================================
// Message Size Tests
// =============================================================================

func TestServer_MaxMessageBytes(t *testing.T) {
	backend := &testBackend{}
	ts := newTestServer(t, backend, server.ServerConfig{
		MaxMessageBytes: 1024, // 1KB limit
	})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.example.com")
	lines := tc.expectMultilineCode(250)

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

	tc.send("MAIL FROM:<sender@example.com>")
	tc.expectCode(250)

	tc.send("RCPT TO:<recipient@example.com>")
	tc.expectCode(250)

	tc.send("DATA")
	tc.expectCode(354)

	// Send a message larger than the limit using many short lines
	// Each line is ~80 chars, need >1024 total
	tc.send("Subject: Large message test")
	tc.send("")
	for i := 0; i < 20; i++ {
		tc.send("%s", strings.Repeat("X", 70)) // 20 * 72 (incl CRLF) = 1440 bytes
	}
	tc.send(".")

	// Should get an error (552 or 554)
	line := tc.readLine()
	var code int
	if _, err := fmt.Sscanf(line, "%d", &code); err != nil {
		t.Fatalf("failed to parse SMTP status code from %q: %v", line, err)
	}
	if code != 552 && code != 554 {
		t.Errorf("expected 552 or 554 for message too large, got: %s", line)
	}
}

func TestServer_SizeParameter(t *testing.T) {
	backend := &testBackend{}
	ts := newTestServer(t, backend, server.ServerConfig{
		MaxMessageBytes: 1024, // 1KB limit
	})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.example.com")
	tc.expectMultilineCode(250)

	// Declare size larger than limit
	tc.send("MAIL FROM:<sender@example.com> SIZE=2048")
	tc.expectCode(552) // Size exceeded
}

// =============================================================================
// Max Recipients Tests
// =============================================================================

func TestServer_MaxRecipients(t *testing.T) {
	backend := &testBackend{}
	ts := newTestServer(t, backend, server.ServerConfig{
		MaxRecipients: 3,
	})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.example.com")
	tc.expectMultilineCode(250)

	tc.send("MAIL FROM:<sender@example.com>")
	tc.expectCode(250)

	// Add max recipients
	for i := 0; i < 3; i++ {
		tc.send("RCPT TO:<recipient%d@example.com>", i)
		tc.expectCode(250)
	}

	// Try to add one more
	tc.send("RCPT TO:<overflow@example.com>")
	tc.expectCode(452) // Too many recipients
}

// =============================================================================
// Multiple Transaction Tests
// =============================================================================

func TestServer_MultipleTransactions(t *testing.T) {
	sessions := make([]*testSession, 0)
	var mu sync.Mutex
	backend := &testBackend{
		sessionFactory: func(_ *server.Conn) (server.Session, error) {
			s := &testSession{}
			mu.Lock()
			sessions = append(sessions, s)
			mu.Unlock()
			return s, nil
		},
	}
	ts := newTestServer(t, backend, server.ServerConfig{})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.example.com")
	tc.expectMultilineCode(250)

	// First transaction
	tc.send("MAIL FROM:<sender@example.com>")
	tc.expectCode(250)
	tc.send("RCPT TO:<recipient@example.com>")
	tc.expectCode(250)
	tc.send("DATA")
	tc.expectCode(354)
	tc.send("Subject: Test 1")
	tc.send("")
	tc.send("Body 1")
	tc.send(".")
	tc.expectCode(250)

	// Second transaction
	tc.send("MAIL FROM:<sender@example.com>")
	tc.expectCode(250)
	tc.send("RCPT TO:<recipient@example.com>")
	tc.expectCode(250)
	tc.send("DATA")
	tc.expectCode(354)
	tc.send("Subject: Test 2")
	tc.send("")
	tc.send("Body 2")
	tc.send(".")
	tc.expectCode(250)

	// Give server time to process
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(sessions) == 0 {
		t.Fatal("no session created")
	}
	s := sessions[0]
	if len(s.completed) != 2 {
		t.Errorf("expected 2 transactions, got %d", len(s.completed))
	}
}

// =============================================================================
// Extension Tests
// =============================================================================

func TestServer_8BitMIME(t *testing.T) {
	backend := &testBackend{}
	ts := newTestServer(t, backend, server.ServerConfig{})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.example.com")
	lines := tc.expectMultilineCode(250)

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
	tc.send("MAIL FROM:<sender@example.com> BODY=8BITMIME")
	tc.expectCode(250)
}

func TestServer_SMTPUTF8(t *testing.T) {
	backend := &testBackend{}
	ts := newTestServer(t, backend, server.ServerConfig{
		EnableSMTPUTF8: true,
	})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.example.com")
	lines := tc.expectMultilineCode(250)

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
	tc.send("MAIL FROM:<sender@example.com> SMTPUTF8")
	tc.expectCode(250)
}

func TestServer_SMTPUTF8_Enforcement(t *testing.T) {
	t.Run("non-ASCII rejected without SMTPUTF8", func(t *testing.T) {
		backend := &testBackend{}
		ts := newTestServer(t, backend, server.ServerConfig{
			EnableSMTPUTF8: true,
		})
		defer ts.close()

		tc := ts.dial()
		defer tc.close()

		tc.send("EHLO client.example.com")
		tc.expectMultilineCode(250)

		// Try to send non-ASCII address without SMTPUTF8 parameter
		tc.send("MAIL FROM:<用户@example.com>")
		tc.expectCode(501) // Should be rejected
	})

	t.Run("non-ASCII accepted with SMTPUTF8", func(t *testing.T) {
		backend := &testBackend{}
		ts := newTestServer(t, backend, server.ServerConfig{
			EnableSMTPUTF8: true,
		})
		defer ts.close()

		tc := ts.dial()
		defer tc.close()

		tc.send("EHLO client.example.com")
		tc.expectMultilineCode(250)

		// With SMTPUTF8 parameter, non-ASCII should be accepted
		tc.send("MAIL FROM:<用户@example.com> SMTPUTF8")
		tc.expectCode(250)

		// Recipient should also accept UTF8 now
		tc.send("RCPT TO:<收件人@example.com>")
		tc.expectCode(250)
	})

	t.Run("IDN domain converted to punycode", func(t *testing.T) {
		backend := &testBackend{}
		ts := newTestServer(t, backend, server.ServerConfig{
			EnableSMTPUTF8: true,
		})
		defer ts.close()

		tc := ts.dial()
		defer tc.close()

		tc.send("EHLO client.example.com")
		tc.expectMultilineCode(250)

		// IDN domain should be accepted and converted
		tc.send("MAIL FROM:<user@例え.jp> SMTPUTF8")
		tc.expectCode(250)
	})

	t.Run("SMTPUTF8 disabled rejects non-ASCII", func(t *testing.T) {
		backend := &testBackend{}
		ts := newTestServer(t, backend, server.ServerConfig{
			EnableSMTPUTF8: false, // Disabled
		})
		defer ts.close()

		tc := ts.dial()
		defer tc.close()

		tc.send("EHLO client.example.com")
		tc.expectMultilineCode(250)

		// SMTPUTF8 parameter should be rejected
		tc.send("MAIL FROM:<user@example.com> SMTPUTF8")
		tc.expectCode(555) // SMTPUTF8 not supported
	})
}

func TestServer_Pipelining(t *testing.T) {
	backend := &testBackend{}
	ts := newTestServer(t, backend, server.ServerConfig{})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.example.com")
	lines := tc.expectMultilineCode(250)

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

	tc.expectCode(250) // MAIL FROM
	tc.expectCode(250) // RCPT TO
	tc.expectCode(354) // DATA

	tc.send("Subject: Pipelined")
	tc.send("")
	tc.send("Body")
	tc.send(".")
	tc.expectCode(250)
}

// =============================================================================
// Concurrent Connection Tests
// =============================================================================

func TestServer_ConcurrentConnections(t *testing.T) {
	backend := &testBackend{}
	ts := newTestServer(t, backend, server.ServerConfig{})
	defer ts.close()

	var wg sync.WaitGroup
	const numConnections = 5

	for i := 0; i < numConnections; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			conn, err := net.Dial("tcp", ts.listener.Addr().String())
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
	sessions := make([]*testSession, 0)
	var mu sync.Mutex
	backend := &testBackend{
		sessionFactory: func(_ *server.Conn) (server.Session, error) {
			s := &testSession{}
			mu.Lock()
			sessions = append(sessions, s)
			mu.Unlock()
			return s, nil
		},
	}
	ts := newTestServer(t, backend, server.ServerConfig{})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.example.com")
	tc.expectMultilineCode(250)

	tc.send("MAIL FROM:<sender@example.com>")
	tc.expectCode(250)

	tc.send("RCPT TO:<recipient@example.com>")
	tc.expectCode(250)

	tc.send("DATA")
	tc.expectCode(354)

	tc.send("Subject: Dot Stuffing Test")
	tc.send("")
	tc.send("Line without dots")
	tc.send("..Line starting with dot")   // Stuffed dot
	tc.send("...Line with multiple dots") // Stuffed dot
	tc.send("Normal line")
	tc.send(".")
	tc.expectCode(250)

	// Give server time to process
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(sessions) == 0 {
		t.Fatal("no session created")
	}
	s := sessions[0]
	if len(s.completed) == 0 {
		t.Fatal("no completed transaction")
	}
	body := string(s.completed[0].data)

	// The received body should have dots un-stuffed
	if !strings.Contains(body, ".Line starting with dot") {
		t.Errorf("expected dot-stuffed line to be un-stuffed, got: %s", body)
	}
	if !strings.Contains(body, "..Line with multiple dots") {
		t.Errorf("expected double-dot-stuffed line to be un-stuffed, got: %s", body)
	}
}

// =============================================================================
// Session Rejection Tests
// =============================================================================

func TestServer_SessionRejectsMailFrom(t *testing.T) {
	backend := &testBackend{
		sessionFactory: func(_ *server.Conn) (server.Session, error) {
			return &testSession{
				rejectMail: func(from string) error {
					if strings.Contains(from, "spam") {
						return &server.SMTPError{
							Code:    550,
							Message: "Sender rejected",
						}
					}
					return nil
				},
			}, nil
		},
	}
	ts := newTestServer(t, backend, server.ServerConfig{})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.example.com")
	tc.expectMultilineCode(250)

	tc.send("MAIL FROM:<spammer@example.com>")
	tc.expectCode(550)

	// Valid sender should work
	tc.send("MAIL FROM:<valid@example.com>")
	tc.expectCode(250)
}

func TestServer_SessionRejectsRcptTo(t *testing.T) {
	backend := &testBackend{
		sessionFactory: func(_ *server.Conn) (server.Session, error) {
			return &testSession{
				rejectRcpt: func(to string) error {
					if !strings.HasSuffix(to, "@example.com") {
						return &server.SMTPError{
							Code:    550,
							Message: "Recipient not found",
						}
					}
					return nil
				},
			}, nil
		},
	}
	ts := newTestServer(t, backend, server.ServerConfig{})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.example.com")
	tc.expectMultilineCode(250)

	tc.send("MAIL FROM:<sender@example.com>")
	tc.expectCode(250)

	tc.send("RCPT TO:<user@example.com>")
	tc.expectCode(250)

	tc.send("RCPT TO:<user@other.com>")
	tc.expectCode(550)
}

// =============================================================================
// BODY Parameter Tests
// =============================================================================

func TestServer_BodyParameter(t *testing.T) {
	testCases := []struct {
		name    string
		body    string
		wantOK  bool
		wantErr int
	}{
		{"7BIT", "BODY=7BIT", true, 0},
		{"8BITMIME", "BODY=8BITMIME", true, 0},
		{"lowercase 8bitmime", "BODY=8bitmime", true, 0},
		{"invalid body type", "BODY=INVALID", false, 501}, // 501 syntax error for invalid value
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			backend := &testBackend{}
			ts := newTestServer(t, backend, server.ServerConfig{})
			defer ts.close()

			client := ts.dial()
			defer client.close()

			client.send("EHLO client.test")
			client.expectMultilineCode(250)

			client.send("MAIL FROM:<sender@example.com> %s", tc.body)
			if tc.wantOK {
				client.expectCode(250)
			} else {
				client.expectCode(tc.wantErr)
			}
		})
	}
}

// =============================================================================
// MAIL FROM Syntax Tests
// =============================================================================

func TestServer_MailFromSyntax(t *testing.T) {
	testCases := []struct {
		name    string
		from    string
		wantOK  bool
		wantErr int
	}{
		{"simple address", "MAIL FROM:<user@example.com>", true, 0},
		{"empty from (bounce)", "MAIL FROM:<>", true, 0},
		{"with SIZE param", "MAIL FROM:<user@example.com> SIZE=1024", true, 0},
		{"with BODY param", "MAIL FROM:<user@example.com> BODY=8BITMIME", true, 0},
		{"with SMTPUTF8", "MAIL FROM:<user@example.com> SMTPUTF8", true, 0},
		{"missing angle brackets", "MAIL FROM:user@example.com", false, 501},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			backend := &testBackend{}
			ts := newTestServer(t, backend, server.ServerConfig{
				EnableSMTPUTF8: true,
			})
			defer ts.close()

			client := ts.dial()
			defer client.close()

			client.send("EHLO client.test")
			client.expectMultilineCode(250)

			client.send("%s", tc.from)
			if tc.wantOK {
				client.expectCode(250)
			} else {
				client.expectCode(tc.wantErr)
			}
		})
	}
}

// =============================================================================
// RCPT TO Syntax Tests
// =============================================================================

func TestServer_RcptToSyntax(t *testing.T) {
	testCases := []struct {
		name    string
		to      string
		wantOK  bool
		wantErr int
	}{
		{"simple address", "RCPT TO:<user@example.com>", true, 0},
		{"subdomain", "RCPT TO:<user@sub.example.com>", true, 0},
		{"with plus addressing", "RCPT TO:<user+tag@example.com>", true, 0},
		{"missing angle brackets", "RCPT TO:user@example.com", false, 501},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			backend := &testBackend{}
			ts := newTestServer(t, backend, server.ServerConfig{})
			defer ts.close()

			client := ts.dial()
			defer client.close()

			client.send("EHLO client.test")
			client.expectMultilineCode(250)

			client.send("MAIL FROM:<sender@example.com>")
			client.expectCode(250)

			client.send("%s", tc.to)
			if tc.wantOK {
				client.expectCode(250)
			} else {
				client.expectCode(tc.wantErr)
			}
		})
	}
}

// =============================================================================
// RFC 5321 Compliance Tests (Phase 4)
// =============================================================================

// --- VRFY / EXPN ---

func TestServer_VRFY_Default502(t *testing.T) {
	backend := &testBackend{}
	ts := newTestServer(t, backend, server.ServerConfig{})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.test")
	tc.expectMultilineCode(250)

	tc.send("VRFY user@example.com")
	tc.expectCode(502)
}

// vrfySession implements VRFYSession.
type vrfySession struct {
	testSession
}

func (s *vrfySession) Verify(address string) (string, error) {
	return "<" + address + ">", nil
}

func TestServer_VRFY_WithSession(t *testing.T) {
	backend := &testBackend{
		sessionFactory: func(_ *server.Conn) (server.Session, error) {
			return &vrfySession{}, nil
		},
	}
	ts := newTestServer(t, backend, server.ServerConfig{})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.test")
	tc.expectMultilineCode(250)

	tc.send("VRFY user@example.com")
	line := tc.expectCode(250)
	if !strings.Contains(line, "user@example.com") {
		t.Errorf("VRFY response should contain address, got %q", line)
	}
}

func TestServer_EXPN_Default502(t *testing.T) {
	backend := &testBackend{}
	ts := newTestServer(t, backend, server.ServerConfig{})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.test")
	tc.expectMultilineCode(250)

	tc.send("EXPN admins")
	tc.expectCode(502)
}

// expnSession implements EXPNSession.
type expnSession struct {
	testSession
}

func (s *expnSession) Expand(_ string) ([]string, error) {
	return []string{"<alice@example.com>", "<bob@example.com>"}, nil
}

func TestServer_EXPN_WithSession(t *testing.T) {
	backend := &testBackend{
		sessionFactory: func(_ *server.Conn) (server.Session, error) {
			return &expnSession{}, nil
		},
	}
	ts := newTestServer(t, backend, server.ServerConfig{})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.test")
	tc.expectMultilineCode(250)

	tc.send("EXPN admins")
	lines := tc.expectMultilineCode(250)
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 EXPN response lines, got %d", len(lines))
	}
}

// --- Source Route in MAIL FROM (integration) ---

func TestServer_MailFrom_SourceRoute(t *testing.T) {
	sess := &testSession{t: t}
	backend := &testBackend{
		sessionFactory: func(_ *server.Conn) (server.Session, error) {
			return sess, nil
		},
	}
	ts := newTestServer(t, backend, server.ServerConfig{})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.test")
	tc.expectMultilineCode(250)

	// Source-routed address: relay prefix should be stripped
	tc.send("MAIL FROM:<@relay1,@relay2:sender@example.com>")
	tc.expectCode(250)

	if sess.from != "sender@example.com" {
		t.Errorf("expected from = %q, got %q", "sender@example.com", sess.from)
	}
}

// --- Received Header ---

func TestServer_ReceivedHeader(t *testing.T) {
	sess := &testSession{t: t}
	backend := &testBackend{
		sessionFactory: func(_ *server.Conn) (server.Session, error) {
			return sess, nil
		},
	}
	ts := newTestServer(t, backend, server.ServerConfig{
		Domain: "mx.example.com",
	})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.test")
	tc.expectMultilineCode(250)

	tc.send("MAIL FROM:<sender@example.com>")
	tc.expectCode(250)

	tc.send("RCPT TO:<rcpt@example.com>")
	tc.expectCode(250)

	tc.send("DATA")
	tc.expectCode(354)

	tc.send("Subject: test\r\n\r\nBody here.\r\n.")
	tc.expectCode(250)

	if len(sess.completed) == 0 {
		t.Fatal("no completed transactions")
	}
	data := string(sess.completed[0].data)
	if !strings.HasPrefix(data, "Received: from client.test") {
		t.Errorf("expected data to start with Received header, got:\n%s", data[:min(len(data), 200)])
	}
	if !strings.Contains(data, "by mx.example.com with ESMTP") {
		t.Errorf("expected Received header to contain server domain and protocol, got:\n%s", data[:min(len(data), 200)])
	}
	if !strings.Contains(data, " id ") {
		t.Errorf("expected Received header to contain id clause, got:\n%s", data[:min(len(data), 200)])
	}
}

// --- Loop Detection ---

func TestServer_LoopDetection(t *testing.T) {
	backend := &testBackend{}
	ts := newTestServer(t, backend, server.ServerConfig{
		MaxReceivedHeaders: 3,
	})
	defer ts.close()

	// Message with 2 existing Received headers + 1 prepended = 3 → reject
	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.test")
	tc.expectMultilineCode(250)

	tc.send("MAIL FROM:<sender@example.com>")
	tc.expectCode(250)

	tc.send("RCPT TO:<rcpt@example.com>")
	tc.expectCode(250)

	tc.send("DATA")
	tc.expectCode(354)

	// Send message with 2 existing Received headers (+ 1 prepended by server = 3 >= max 3)
	tc.send("Received: from hop1 by hop1.example.com\r\nReceived: from hop2 by hop2.example.com\r\nSubject: loop test\r\n\r\nBody.\r\n.")
	tc.expectCode(554)
}

func TestServer_LoopDetection_BelowThreshold(t *testing.T) {
	backend := &testBackend{}
	ts := newTestServer(t, backend, server.ServerConfig{
		MaxReceivedHeaders: 5,
	})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.test")
	tc.expectMultilineCode(250)

	tc.send("MAIL FROM:<sender@example.com>")
	tc.expectCode(250)

	tc.send("RCPT TO:<rcpt@example.com>")
	tc.expectCode(250)

	tc.send("DATA")
	tc.expectCode(354)

	// 2 existing Received headers + 1 prepended = 3, below max of 5 → OK
	tc.send("Received: from hop1 by hop1.example.com\r\nReceived: from hop2 by hop2.example.com\r\nSubject: ok\r\n\r\nBody.\r\n.")
	tc.expectCode(250)
}

// --- BDAT / CHUNKING ---

// chunkingSession implements ChunkingSession for testing.
type chunkingSession struct {
	testSession
	chunks [][]byte
}

func (s *chunkingSession) Chunk(data []byte, _ bool) error {
	s.chunks = append(s.chunks, append([]byte(nil), data...))
	return nil
}

func TestServer_BDAT_ReceivedHeader(t *testing.T) {
	sess := &chunkingSession{}
	backend := &testBackend{
		sessionFactory: func(_ *server.Conn) (server.Session, error) {
			return sess, nil
		},
	}
	ts := newTestServer(t, backend, server.ServerConfig{
		Domain:         "mx.example.com",
		EnableCHUNKING: true,
	})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.test")
	tc.expectMultilineCode(250)

	tc.send("MAIL FROM:<sender@example.com>")
	tc.expectCode(250)

	tc.send("RCPT TO:<rcpt@example.com>")
	tc.expectCode(250)

	msg := "Subject: test\r\n\r\nBody here."
	tc.send("BDAT %d LAST", len(msg))
	fmt.Fprint(tc.conn, msg)
	tc.expectCode(250)

	if len(sess.chunks) == 0 {
		t.Fatal("no chunks received")
	}
	data := string(sess.chunks[0])
	if !strings.HasPrefix(data, "Received: from client.test") {
		t.Errorf("expected first chunk to start with Received header, got:\n%s", data[:min(len(data), 200)])
	}
	if !strings.Contains(data, "by mx.example.com with ESMTP") {
		t.Errorf("expected Received header to contain domain and protocol, got:\n%s", data[:min(len(data), 200)])
	}
	if !strings.Contains(data, " id ") {
		t.Errorf("expected Received header to contain id clause, got:\n%s", data[:min(len(data), 200)])
	}
}

func TestServer_BDAT_LoopDetection(t *testing.T) {
	sess := &chunkingSession{}
	backend := &testBackend{
		sessionFactory: func(_ *server.Conn) (server.Session, error) {
			return sess, nil
		},
	}
	ts := newTestServer(t, backend, server.ServerConfig{
		EnableCHUNKING:     true,
		MaxReceivedHeaders: 3,
	})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.test")
	tc.expectMultilineCode(250)

	tc.send("MAIL FROM:<sender@example.com>")
	tc.expectCode(250)

	tc.send("RCPT TO:<rcpt@example.com>")
	tc.expectCode(250)

	// 2 existing Received headers in data + 1 prepended = 3 >= max 3 → reject
	msg := "Received: from hop1 by hop1.example.com\r\nReceived: from hop2 by hop2.example.com\r\nSubject: test\r\n\r\nBody."
	tc.send("BDAT %d LAST", len(msg))
	fmt.Fprint(tc.conn, msg)
	tc.expectCode(554)
}

func TestServer_BDAT_LoopDetection_BelowThreshold(t *testing.T) {
	sess := &chunkingSession{}
	backend := &testBackend{
		sessionFactory: func(_ *server.Conn) (server.Session, error) {
			return sess, nil
		},
	}
	ts := newTestServer(t, backend, server.ServerConfig{
		EnableCHUNKING:     true,
		MaxReceivedHeaders: 5,
	})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.test")
	tc.expectMultilineCode(250)

	tc.send("MAIL FROM:<sender@example.com>")
	tc.expectCode(250)

	tc.send("RCPT TO:<rcpt@example.com>")
	tc.expectCode(250)

	msg := "Received: from hop1 by hop1.example.com\r\nSubject: ok\r\n\r\nBody."
	tc.send("BDAT %d LAST", len(msg))
	fmt.Fprint(tc.conn, msg)
	tc.expectCode(250)
}
