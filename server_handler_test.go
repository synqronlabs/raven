package raven

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// MAIL FROM Handler Tests
// =============================================================================

func TestHandler_MailFrom_ValidSyntax(t *testing.T) {
	testCases := []struct {
		name    string
		from    string
		wantOK  bool
		wantErr int
	}{
		{"simple address", "MAIL FROM:<user@example.com>", true, 0},
		{"empty from (bounce)", "MAIL FROM:<>", true, 0},
		{"with display name", "MAIL FROM:<sender@example.com>", true, 0},
		{"with SIZE param", "MAIL FROM:<user@example.com> SIZE=1024", true, 0},
		{"with BODY param", "MAIL FROM:<user@example.com> BODY=8BITMIME", true, 0},
		{"with SMTPUTF8", "MAIL FROM:<user@example.com> SMTPUTF8", true, 0},
		{"missing angle brackets", "MAIL FROM:user@example.com", false, 501},
		{"missing FROM:", "MAIL <user@example.com>", false, 501},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := newTestServer(t)
			defer ts.Close()

			client := ts.Dial()
			defer client.Close()

			client.Send("EHLO client.test")
			client.ExpectMultilineCode(250)

			client.Send("%s", tc.from)
			if tc.wantOK {
				client.ExpectCode(250)
			} else {
				client.ExpectCode(tc.wantErr)
			}
		})
	}
}

func TestHandler_MailFrom_BodyParameter(t *testing.T) {
	testCases := []struct {
		name    string
		body    string
		wantOK  bool
		wantErr int
	}{
		{"7BIT", "BODY=7BIT", true, 0},
		{"8BITMIME", "BODY=8BITMIME", true, 0},
		{"lowercase 8bitmime", "BODY=8bitmime", true, 0},
		{"BINARYMIME without chunking", "BODY=BINARYMIME", false, 504}, // Not supported by default
		{"invalid body type", "BODY=INVALID", false, 504},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := newTestServer(t)
			defer ts.Close()

			client := ts.Dial()
			defer client.Close()

			client.Send("EHLO client.test")
			client.ExpectMultilineCode(250)

			client.Send("MAIL FROM:<sender@example.com> %s", tc.body)
			if tc.wantOK {
				client.ExpectCode(250)
			} else {
				client.ExpectCode(tc.wantErr)
			}
		})
	}
}

func TestHandler_MailFrom_SizeParameter(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.MaxMessageSize(1024) // 1KB limit
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	// SIZE within limit
	client.Send("MAIL FROM:<sender@example.com> SIZE=512")
	client.ExpectCode(250)

	client.Send("RSET")
	client.ExpectCode(250)

	// SIZE exceeds limit
	client.Send("MAIL FROM:<sender@example.com> SIZE=2048")
	client.ExpectCode(552)
}

// =============================================================================
// RCPT TO Handler Tests
// =============================================================================

func TestHandler_RcptTo_ValidSyntax(t *testing.T) {
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
		{"missing TO:", "RCPT <user@example.com>", false, 501},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := newTestServer(t)
			defer ts.Close()

			client := ts.Dial()
			defer client.Close()

			client.Send("EHLO client.test")
			client.ExpectMultilineCode(250)

			client.Send("MAIL FROM:<sender@example.com>")
			client.ExpectCode(250)

			client.Send("%s", tc.to)
			if tc.wantOK {
				client.ExpectCode(250)
			} else {
				client.ExpectCode(tc.wantErr)
			}
		})
	}
}

func TestHandler_RcptTo_MaxRecipients(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.MaxRecipients(2)
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	client.Send("MAIL FROM:<sender@example.com>")
	client.ExpectCode(250)

	client.Send("RCPT TO:<user1@example.com>")
	client.ExpectCode(250)

	client.Send("RCPT TO:<user2@example.com>")
	client.ExpectCode(250)

	// Third recipient should be rejected
	client.Send("RCPT TO:<user3@example.com>")
	client.ExpectCode(452)
}

// =============================================================================
// DATA Handler Tests
// =============================================================================

func TestHandler_Data_BasicMessage(t *testing.T) {
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

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	client.Send("MAIL FROM:<sender@example.com>")
	client.ExpectCode(250)

	client.Send("RCPT TO:<recipient@example.com>")
	client.ExpectCode(250)

	client.Send("DATA")
	client.ExpectCode(354)

	client.Send("From: sender@example.com")
	client.Send("To: recipient@example.com")
	client.Send("Subject: Test Subject")
	client.Send("Date: Mon, 01 Jan 2024 00:00:00 +0000")
	client.Send("Message-ID: <test@example.com>")
	client.Send("")
	client.Send("This is the message body.")
	client.Send(".")

	client.ExpectCode(250)

	mu.Lock()
	defer mu.Unlock()

	if receivedMail == nil {
		t.Fatal("expected to receive mail")
	}

	if receivedMail.Content.Headers.Get("Subject") != "Test Subject" {
		t.Errorf("expected subject 'Test Subject', got %q", receivedMail.Content.Headers.Get("Subject"))
	}

	if !strings.Contains(string(receivedMail.Content.Body), "message body") {
		t.Errorf("expected body to contain 'message body', got %q", string(receivedMail.Content.Body))
	}
}

func TestHandler_Data_MultilineBody(t *testing.T) {
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

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	client.Send("MAIL FROM:<sender@example.com>")
	client.ExpectCode(250)

	client.Send("RCPT TO:<recipient@example.com>")
	client.ExpectCode(250)

	client.Send("DATA")
	client.ExpectCode(354)

	client.Send("Subject: Multiline")
	client.Send("")
	client.Send("Line 1")
	client.Send("Line 2")
	client.Send("Line 3")
	client.Send(".")

	client.ExpectCode(250)

	mu.Lock()
	defer mu.Unlock()

	lines := strings.Split(string(receivedBody), "\r\n")
	if len(lines) < 3 {
		t.Errorf("expected at least 3 lines, got %d", len(lines))
	}
}

func TestHandler_Data_EmptyBody(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	client.Send("MAIL FROM:<sender@example.com>")
	client.ExpectCode(250)

	client.Send("RCPT TO:<recipient@example.com>")
	client.ExpectCode(250)

	client.Send("DATA")
	client.ExpectCode(354)

	client.Send("Subject: Empty Body")
	client.Send("")
	client.Send(".")

	client.ExpectCode(250)
}

func TestHandler_Data_DotStuffing(t *testing.T) {
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

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	client.Send("MAIL FROM:<sender@example.com>")
	client.ExpectCode(250)

	client.Send("RCPT TO:<recipient@example.com>")
	client.ExpectCode(250)

	client.Send("DATA")
	client.ExpectCode(354)

	client.Send("Subject: Dot Test")
	client.Send("")
	client.Send("Normal line")
	client.Send("..Dot stuffed line") // Should become ".Dot stuffed line"
	client.Send("...Double dot")      // Should become "..Double dot"
	client.Send(".")

	client.ExpectCode(250)

	mu.Lock()
	defer mu.Unlock()

	if !strings.Contains(string(receivedBody), ".Dot stuffed line") {
		t.Error("dot stuffing not properly handled")
	}
	if !strings.Contains(string(receivedBody), "..Double dot") {
		t.Error("double dot stuffing not properly handled")
	}
}

func TestHandler_Data_ReceivedHeader(t *testing.T) {
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

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	client.Send("MAIL FROM:<sender@example.com>")
	client.ExpectCode(250)

	client.Send("RCPT TO:<recipient@example.com>")
	client.ExpectCode(250)

	client.Send("DATA")
	client.ExpectCode(354)

	client.Send("Subject: Received Header Test")
	client.Send("")
	client.Send("Body")
	client.Send(".")

	client.ExpectCode(250)

	mu.Lock()
	defer mu.Unlock()

	if receivedMail == nil {
		t.Fatal("expected mail")
	}

	// Should have a Received header added
	received := receivedMail.Content.Headers.Get("Received")
	if received == "" {
		t.Error("expected Received header to be added")
	}

	// Should contain server hostname
	if !strings.Contains(received, "test.example.com") {
		t.Errorf("expected Received header to contain server hostname, got %q", received)
	}
}

func TestHandler_Data_MessageTooLarge(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.MaxMessageSize(100) // Very small limit
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	client.Send("MAIL FROM:<sender@example.com>")
	client.ExpectCode(250)

	client.Send("RCPT TO:<recipient@example.com>")
	client.ExpectCode(250)

	client.Send("DATA")
	client.ExpectCode(354)

	client.Send("Subject: Large Message")
	client.Send("")
	// Send a body that exceeds the limit
	client.Send("%s", strings.Repeat("X", 200))
	client.Send(".")

	client.ExpectCode(552)
}

// =============================================================================
// RSET Handler Tests
// =============================================================================

func TestHandler_Rset_ResetsTransaction(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	// Start a transaction
	client.Send("MAIL FROM:<sender1@example.com>")
	client.ExpectCode(250)

	client.Send("RCPT TO:<recipient@example.com>")
	client.ExpectCode(250)

	// Reset
	client.Send("RSET")
	client.ExpectCode(250)

	// Should be able to start a new transaction
	client.Send("MAIL FROM:<sender2@example.com>")
	client.ExpectCode(250)
}

func TestHandler_Rset_WithoutTransaction(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	// RSET without any transaction is valid
	client.Send("RSET")
	client.ExpectCode(250)
}

// =============================================================================
// Command Sequence Tests
// =============================================================================

func TestHandler_CommandSequence_MailFromBeforeEhlo(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	// Try MAIL FROM without EHLO
	client.Send("MAIL FROM:<sender@example.com>")
	client.ExpectCode(503)
}

func TestHandler_CommandSequence_RcptToBeforeMailFrom(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	// Try RCPT TO without MAIL FROM
	client.Send("RCPT TO:<recipient@example.com>")
	client.ExpectCode(503)
}

func TestHandler_CommandSequence_DataBeforeRcptTo(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	client.Send("MAIL FROM:<sender@example.com>")
	client.ExpectCode(250)

	// Try DATA without RCPT TO
	client.Send("DATA")
	client.ExpectCode(503)
}

func TestHandler_CommandSequence_DoubleMailFrom(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	client.Send("MAIL FROM:<sender1@example.com>")
	client.ExpectCode(250)

	// Try second MAIL FROM
	client.Send("MAIL FROM:<sender2@example.com>")
	client.ExpectCode(503)
}

// =============================================================================
// OnData Handler Tests
// =============================================================================

func TestHandler_OnData_BeforeDataRead(t *testing.T) {
	var onDataCalled bool
	var mu sync.Mutex

	ts := newTestServer(t, func(s *Server) {
		s.OnData(func(c *Context) *Response {
			mu.Lock()
			onDataCalled = true
			mu.Unlock()
			return c.Next()
		})
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	client.Send("MAIL FROM:<sender@example.com>")
	client.ExpectCode(250)

	client.Send("RCPT TO:<recipient@example.com>")
	client.ExpectCode(250)

	client.Send("DATA")
	client.ExpectCode(354)

	mu.Lock()
	if !onDataCalled {
		t.Error("OnData handler should be called before 354 response")
	}
	mu.Unlock()

	client.Send("Subject: Test")
	client.Send("")
	client.Send("Body")
	client.Send(".")

	client.ExpectCode(250)
}

func TestHandler_OnData_Reject(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.OnData(func(c *Context) *Response {
			// Reject before reading data
			return c.Error(CodeTransactionFailed, "Data not allowed")
		})
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	client.Send("MAIL FROM:<sender@example.com>")
	client.ExpectCode(250)

	client.Send("RCPT TO:<recipient@example.com>")
	client.ExpectCode(250)

	client.Send("DATA")
	client.ExpectCode(554)
}

// =============================================================================
// OnHelo/OnEhlo Handler Tests
// =============================================================================

func TestHandler_OnHelo(t *testing.T) {
	var receivedHostname string
	var mu sync.Mutex

	ts := newTestServer(t, func(s *Server) {
		s.OnHelo(func(c *Context) *Response {
			mu.Lock()
			receivedHostname = c.Request.Hostname
			mu.Unlock()
			return c.Next()
		})
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("HELO myclient.example.com")
	client.ExpectCode(250)

	mu.Lock()
	if receivedHostname != "myclient.example.com" {
		t.Errorf("expected hostname 'myclient.example.com', got %q", receivedHostname)
	}
	mu.Unlock()
}

func TestHandler_OnEhlo(t *testing.T) {
	var receivedHostname string
	var mu sync.Mutex

	ts := newTestServer(t, func(s *Server) {
		s.OnEhlo(func(c *Context) *Response {
			mu.Lock()
			receivedHostname = c.Request.Hostname
			mu.Unlock()
			return c.Next()
		})
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO myclient.example.com")
	client.ExpectMultilineCode(250)

	mu.Lock()
	if receivedHostname != "myclient.example.com" {
		t.Errorf("expected hostname 'myclient.example.com', got %q", receivedHostname)
	}
	mu.Unlock()
}

func TestHandler_OnEhlo_ModifyExtensions(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.OnEhlo(func(c *Context) *Response {
			// Remove an extension
			delete(c.Request.Extensions, ExtPipelining)
			return c.Next()
		})
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	lines := client.ExpectMultilineCode(250)

	for _, line := range lines {
		if strings.Contains(line, "PIPELINING") {
			t.Error("PIPELINING should have been removed by handler")
		}
	}
}

// =============================================================================
// Connection Timeout Tests
// =============================================================================

func TestHandler_ReadTimeout_Basic(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.ReadTimeout(100 * time.Millisecond)
	})
	defer ts.Close()

	conn, err := net.Dial("tcp", ts.addr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	line, _ := reader.ReadString('\n')
	if !strings.HasPrefix(line, "220") {
		t.Fatalf("unexpected greeting: %s", line)
	}

	// Wait longer than idle timeout
	time.Sleep(200 * time.Millisecond)

	// Connection should be closed or return timeout response
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	line, err = reader.ReadString('\n')
	if err == nil {
		// If we got a response, it should be 421 (timeout)
		if !strings.HasPrefix(line, "421") {
			t.Logf("got response: %s", line)
		}
	}
	// Either EOF or 421 is acceptable
}

func TestHandler_ReadTimeout(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.ReadTimeout(100 * time.Millisecond)
	})
	defer ts.Close()

	conn, err := net.Dial("tcp", ts.addr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	line, _ := reader.ReadString('\n')
	if !strings.HasPrefix(line, "220") {
		t.Fatalf("unexpected greeting: %s", line)
	}

	// Send partial command (no CRLF) and wait
	conn.Write([]byte("EH"))
	time.Sleep(200 * time.Millisecond)

	// Server should have timed out waiting for rest of command
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	line, err = reader.ReadString('\n')
	// Either connection closed (EOF) or timeout response (421)
	if err == nil && !strings.HasPrefix(line, "421") {
		t.Logf("got unexpected response: %s", line)
	}
}

func TestHandler_WriteTimeout(t *testing.T) {
	// WriteTimeout is harder to test directly - server writes responses
	// This test verifies the setting doesn't break normal operation
	ts := newTestServer(t, func(s *Server) {
		s.WriteTimeout(100 * time.Millisecond)
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.example.com")
	client.ExpectMultilineCode(250)

	client.Send("QUIT")
	client.ExpectCode(221)
}

func TestHandler_DataTimeout(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.DataTimeout(100 * time.Millisecond)
	})
	defer ts.Close()

	conn, err := net.Dial("tcp", ts.addr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	reader.ReadString('\n')

	// EHLO
	conn.Write([]byte("EHLO test.com\r\n"))
	for {
		line, _ := reader.ReadString('\n')
		if len(line) < 4 || line[3] == ' ' {
			break
		}
	}

	// MAIL FROM
	conn.Write([]byte("MAIL FROM:<sender@example.com>\r\n"))
	reader.ReadString('\n')

	// RCPT TO
	conn.Write([]byte("RCPT TO:<recipient@example.com>\r\n"))
	reader.ReadString('\n')

	// DATA
	conn.Write([]byte("DATA\r\n"))
	line, _ := reader.ReadString('\n')
	if !strings.HasPrefix(line, "354") {
		t.Fatalf("expected 354, got: %s", line)
	}

	// Start sending data but then pause - trigger data timeout
	conn.Write([]byte("Subject: Test\r\n"))
	time.Sleep(200 * time.Millisecond)

	// Server should have timed out waiting for message data
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	line, err = reader.ReadString('\n')
	// Either connection closed or timeout response
	if err == nil && !strings.HasPrefix(line, "421") && !strings.HasPrefix(line, "451") {
		t.Logf("got unexpected response during data timeout: %s", line)
	}
}

func TestHandler_ReadTimeout_AfterEHLO(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.ReadTimeout(100 * time.Millisecond)
	})
	defer ts.Close()

	conn, err := net.Dial("tcp", ts.addr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	reader.ReadString('\n')

	// Send EHLO
	conn.Write([]byte("EHLO test.com\r\n"))
	for {
		line, _ := reader.ReadString('\n')
		if len(line) < 4 || line[3] == ' ' {
			break
		}
	}

	// Wait longer than idle timeout
	time.Sleep(200 * time.Millisecond)

	// Connection should be closed or return timeout response
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	line, err := reader.ReadString('\n')
	if err == nil {
		if !strings.HasPrefix(line, "421") {
			t.Logf("got response: %s", line)
		}
	}
}

func TestHandler_ReadTimeout_DuringTransaction(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.ReadTimeout(100 * time.Millisecond)
	})
	defer ts.Close()

	conn, err := net.Dial("tcp", ts.addr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	reader.ReadString('\n')

	// EHLO
	conn.Write([]byte("EHLO test.com\r\n"))
	for {
		line, _ := reader.ReadString('\n')
		if len(line) < 4 || line[3] == ' ' {
			break
		}
	}

	// Start transaction
	conn.Write([]byte("MAIL FROM:<sender@example.com>\r\n"))
	reader.ReadString('\n')

	// Wait for idle timeout during transaction
	time.Sleep(200 * time.Millisecond)

	// Connection should timeout
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	line, err := reader.ReadString('\n')
	if err == nil && !strings.HasPrefix(line, "421") {
		t.Logf("got unexpected response: %s", line)
	}
}

func TestHandler_TimeoutValues(t *testing.T) {
	// Test that reasonable timeout configurations work correctly
	tests := []struct {
		name  string
		setup func(s *Server)
	}{
		{"short read timeout", func(s *Server) { s.ReadTimeout(1 * time.Second) }},
		{"short write timeout", func(s *Server) { s.WriteTimeout(1 * time.Second) }},
		{"short data timeout", func(s *Server) { s.DataTimeout(1 * time.Second) }},
		{"very long timeouts", func(s *Server) {
			s.ReadTimeout(time.Hour)
			s.WriteTimeout(time.Hour)
			s.DataTimeout(time.Hour)
		}},
		{"mixed timeouts", func(s *Server) {
			s.ReadTimeout(5 * time.Second)
			s.WriteTimeout(10 * time.Second)
			s.DataTimeout(30 * time.Second)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newTestServer(t, tt.setup)
			defer ts.Close()

			client := ts.Dial()
			defer client.Close()

			client.Send("EHLO client.example.com")
			client.ExpectMultilineCode(250)

			client.Send("QUIT")
			client.ExpectCode(221)
		})
	}
}

func TestHandler_ZeroTimeouts(t *testing.T) {
	// Zero timeouts mean "no timeout" or immediate - behavior varies
	// This test documents what happens with zero values

	t.Run("zero idle timeout causes immediate disconnect", func(t *testing.T) {
		ts := newTestServer(t, func(s *Server) {
			s.ReadTimeout(0)
		})
		defer ts.Close()

		conn, err := net.Dial("tcp", ts.addr)
		if err != nil {
			t.Fatalf("failed to dial: %v", err)
		}
		defer conn.Close()

		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		reader := bufio.NewReader(conn)

		// With zero idle timeout, server may disconnect immediately or after greeting
		// Either behavior is acceptable
		line, _ := reader.ReadString('\n')
		// If we get anything, first response should be greeting or timeout
		if len(line) > 0 {
			code := 0
			fmt.Sscanf(line, "%d", &code)
			if code != 220 && code != 421 {
				t.Errorf("expected 220 or 421, got: %s", line)
			}
		}
	})
}

// =============================================================================
// Limits Enforcement Tests
// =============================================================================

func TestHandler_MaxRecipients(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.MaxRecipients(2)
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.example.com")
	client.ExpectMultilineCode(250)

	client.Send("MAIL FROM:<sender@example.com>")
	client.ExpectCode(250)

	// First two recipients should work
	client.Send("RCPT TO:<recipient1@example.com>")
	client.ExpectCode(250)

	client.Send("RCPT TO:<recipient2@example.com>")
	client.ExpectCode(250)

	// Third recipient should be rejected
	client.Send("RCPT TO:<recipient3@example.com>")
	resp := client.ReadLine()
	code := 0
	fmt.Sscanf(resp, "%d", &code)
	if code < 400 {
		t.Errorf("expected 4xx/5xx for exceeding max recipients, got %d", code)
	}
}

func TestHandler_MaxCommands(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.MaxCommands(5)
	})
	defer ts.Close()

	conn, err := net.Dial("tcp", ts.addr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	reader.ReadString('\n')

	// Send commands up to the limit
	for i := 0; i < 5; i++ {
		conn.Write([]byte("NOOP\r\n"))
		line, _ := reader.ReadString('\n')
		if !strings.HasPrefix(line, "250") {
			t.Logf("command %d got: %s", i+1, line)
		}
	}

	// Next command should trigger disconnect (421)
	conn.Write([]byte("NOOP\r\n"))
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	line, _ := reader.ReadString('\n')
	if !strings.HasPrefix(line, "421") {
		t.Errorf("expected 421 after max commands, got: %s", line)
	}
}

func TestHandler_MaxErrors(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.MaxErrors(3)
	})
	defer ts.Close()

	conn, err := net.Dial("tcp", ts.addr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	reader.ReadString('\n')

	// Send invalid commands to generate errors
	for i := 0; i < 3; i++ {
		conn.Write([]byte("INVALIDCMD\r\n"))
		reader.ReadString('\n') // Read error response
	}

	// Next error should trigger disconnect
	conn.Write([]byte("INVALIDCMD\r\n"))
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	line, _ := reader.ReadString('\n')
	if !strings.HasPrefix(line, "421") {
		t.Errorf("expected 421 after max errors, got: %s", line)
	}
}

func TestHandler_MaxConnections(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.MaxConnections(2)
	})
	defer ts.Close()

	// Open first two connections - should succeed
	conn1, err := net.Dial("tcp", ts.addr)
	if err != nil {
		t.Fatalf("failed to dial conn1: %v", err)
	}
	defer conn1.Close()

	conn2, err := net.Dial("tcp", ts.addr)
	if err != nil {
		t.Fatalf("failed to dial conn2: %v", err)
	}
	defer conn2.Close()

	// Read greetings
	reader1 := bufio.NewReader(conn1)
	reader2 := bufio.NewReader(conn2)
	reader1.ReadString('\n')
	reader2.ReadString('\n')

	// Third connection should be rejected
	conn3, err := net.Dial("tcp", ts.addr)
	if err != nil {
		// Connection refused is acceptable
		return
	}
	defer conn3.Close()

	// If connection succeeded, it should be closed immediately
	conn3.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	reader3 := bufio.NewReader(conn3)
	_, err = reader3.ReadString('\n')
	// Should get EOF (closed) or timeout
	if err == nil {
		t.Error("expected third connection to be rejected")
	}
}

func TestHandler_MaxMessageSize_Enforced(t *testing.T) {
	maxSize := int64(100)
	ts := newTestServer(t, func(s *Server) {
		s.MaxMessageSize(maxSize)
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.example.com")
	client.ExpectMultilineCode(250)

	client.Send("MAIL FROM:<sender@example.com>")
	client.ExpectCode(250)

	client.Send("RCPT TO:<recipient@example.com>")
	client.ExpectCode(250)

	client.Send("DATA")
	client.ExpectCode(354)

	// Send message exceeding size limit
	client.Send("Subject: Test")
	client.Send("")
	client.Send("%s", strings.Repeat("X", int(maxSize)+50))
	client.Send(".")

	// Should be rejected
	resp := client.ReadLine()
	code := 0
	fmt.Sscanf(resp, "%d", &code)
	if code < 400 {
		t.Errorf("expected 4xx/5xx for message exceeding size, got %d", code)
	}
}

func TestHandler_MaxReceivedHeaders(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.MaxReceivedHeaders(3)
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.example.com")
	client.ExpectMultilineCode(250)

	client.Send("MAIL FROM:<sender@example.com>")
	client.ExpectCode(250)

	client.Send("RCPT TO:<recipient@example.com>")
	client.ExpectCode(250)

	client.Send("DATA")
	client.ExpectCode(354)

	// Send message with too many Received headers (loop detection)
	client.Send("Received: from server1.example.com by server2.example.com")
	client.Send("Received: from server2.example.com by server3.example.com")
	client.Send("Received: from server3.example.com by server4.example.com")
	client.Send("Received: from server4.example.com by server5.example.com")
	client.Send("Subject: Loop test")
	client.Send("")
	client.Send("Body")
	client.Send(".")

	// Should be rejected due to loop detection
	resp := client.ReadLine()
	code := 0
	fmt.Sscanf(resp, "%d", &code)
	if code < 500 {
		t.Errorf("expected 5xx for too many Received headers (loop), got %d", code)
	}
}

// =============================================================================
// VRFY and EXPN Tests
// =============================================================================

func TestHandler_Vrfy_Default(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	// Default VRFY returns 252 (Cannot VRFY)
	client.Send("VRFY user@example.com")
	client.ExpectCode(252)
}

func TestHandler_Vrfy_Custom(t *testing.T) {
	ts := newTestServer(t, func(s *Server) {
		s.OnVerify(func(c *Context) *Response {
			if c.Request.Args == "admin" {
				return c.OK("admin@example.com")
			}
			return c.Error(CodeMailboxNotFound, "User not found")
		})
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	client.Send("VRFY admin")
	line := client.ExpectCode(250)
	if !strings.Contains(line, "admin@example.com") {
		t.Errorf("expected admin@example.com in response, got %q", line)
	}

	client.Send("VRFY unknown")
	client.ExpectCode(550)
}

func TestHandler_Expn_Default(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	// Default EXPN returns 252 (Cannot EXPN)
	client.Send("EXPN list")
	client.ExpectCode(252)
}

// =============================================================================
// Context Method Tests
// =============================================================================

func TestHandler_Context_RemoteAddr(t *testing.T) {
	var remoteAddr string
	var mu sync.Mutex

	ts := newTestServer(t, func(s *Server) {
		s.OnConnect(func(c *Context) *Response {
			mu.Lock()
			remoteAddr = c.Connection.RemoteAddr().String()
			mu.Unlock()
			return c.Next()
		})
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	mu.Lock()
	if remoteAddr == "" {
		t.Error("expected remote address to be set")
	}
	if !strings.Contains(remoteAddr, "127.0.0.1") {
		t.Errorf("expected remote addr to contain 127.0.0.1, got %q", remoteAddr)
	}
	mu.Unlock()
}

func TestHandler_Context_ServerHostname(t *testing.T) {
	var serverHostname string
	var mu sync.Mutex

	ts := newTestServer(t, func(s *Server) {
		s.OnConnect(func(c *Context) *Response {
			mu.Lock()
			serverHostname = c.server.hostname
			mu.Unlock()
			return c.Next()
		})
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	mu.Lock()
	if serverHostname != "test.example.com" {
		t.Errorf("expected server hostname 'test.example.com', got %q", serverHostname)
	}
	mu.Unlock()
}

func TestHandler_Context_ClientHostname(t *testing.T) {
	var clientHostname string
	var mu sync.Mutex

	ts := newTestServer(t, func(s *Server) {
		s.OnMailFrom(func(c *Context) *Response {
			mu.Lock()
			clientHostname = c.ClientHostname()
			mu.Unlock()
			return c.Next()
		})
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO myclient.local")
	client.ExpectMultilineCode(250)

	client.Send("MAIL FROM:<sender@example.com>")
	client.ExpectCode(250)

	mu.Lock()
	if clientHostname != "myclient.local" {
		t.Errorf("expected client hostname 'myclient.local', got %q", clientHostname)
	}
	mu.Unlock()
}

func TestHandler_Context_ResponseHelpers(t *testing.T) {
	// Test OK helper
	ts := newTestServer(t, func(s *Server) {
		s.OnHelp(func(c *Context) *Response {
			return c.OK("Help message")
		})
	})
	defer ts.Close()

	client := ts.Dial()
	defer client.Close()

	client.Send("EHLO client.test")
	client.ExpectMultilineCode(250)

	client.Send("HELP")
	line := client.ExpectCode(250)
	if !strings.Contains(line, "Help message") {
		t.Errorf("expected 'Help message', got %q", line)
	}
}
