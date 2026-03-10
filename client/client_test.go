package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	ravenmail "github.com/synqronlabs/raven/mail"
)

// --- Mock SMTP server infrastructure ---

type mockSMTPServer struct {
	listener net.Listener
	handler  func(conn net.Conn)
	wg       sync.WaitGroup
	mu       sync.Mutex
	closed   bool
}

func newMockSMTPServer(t *testing.T, handler func(conn net.Conn)) *mockSMTPServer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &mockSMTPServer{listener: l, handler: handler}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				s.mu.Lock()
				closed := s.closed
				s.mu.Unlock()
				if closed {
					return
				}
				continue
			}
			s.wg.Go(func() {
				defer conn.Close()
				handler(conn)
			})
		}
	}()
	return s
}

func (s *mockSMTPServer) addr() string {
	return s.listener.Addr().String()
}

func (s *mockSMTPServer) close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.listener.Close()
	s.wg.Wait()
}

// smtpGreeting writes a standard 220 greeting.
func smtpGreeting(w *bufio.Writer) {
	w.WriteString("220 mock.example.com ESMTP\r\n")
	w.Flush()
}

// smtpEHLO handles an EHLO command and responds with given extensions.
func smtpEHLO(w *bufio.Writer, extensions []string) {
	if len(extensions) == 0 {
		w.WriteString("250 mock.example.com\r\n")
	} else {
		w.WriteString("250-mock.example.com\r\n")
		for i, ext := range extensions {
			if i == len(extensions)-1 {
				w.WriteString("250 " + ext + "\r\n")
			} else {
				w.WriteString("250-" + ext + "\r\n")
			}
		}
	}
	w.Flush()
}

// readLine reads one CRLF-terminated line from the buffered reader.
func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

// --- basicSMTPHandler: a configurable mock SMTP handler ---

type basicSMTPHandler struct {
	extensions       []string
	rejectRcptTo     map[string]bool // reject these recipients
	dataResponseCode int             // e.g. 250
	dataResponseMsg  string
	authMechanisms   string
	rejectAuth       bool
}

func (h *basicSMTPHandler) handle(conn net.Conn) {
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	smtpGreeting(w)

	for {
		line, err := readLine(r)
		if err != nil {
			return
		}

		cmd := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			exts := h.extensions
			if h.authMechanisms != "" {
				exts = append(exts, "AUTH "+h.authMechanisms)
			}
			smtpEHLO(w, exts)

		case strings.HasPrefix(cmd, "HELO"):
			w.WriteString("250 mock.example.com\r\n")
			w.Flush()

		case strings.HasPrefix(cmd, "MAIL FROM:"):
			w.WriteString("250 2.1.0 Ok\r\n")
			w.Flush()

		case strings.HasPrefix(cmd, "RCPT TO:"):
			addr := line[len("RCPT TO:"):]
			addr = strings.TrimSpace(addr)
			if h.rejectRcptTo != nil && h.rejectRcptTo[addr] {
				w.WriteString("550 5.1.1 User unknown\r\n")
			} else {
				w.WriteString("250 2.1.5 Ok\r\n")
			}
			w.Flush()

		case cmd == "DATA":
			w.WriteString("354 Start mail input\r\n")
			w.Flush()
			// Read until ".\r\n"
			for {
				dataLine, err := readLine(r)
				if err != nil {
					return
				}
				if dataLine == "." {
					break
				}
			}
			code := h.dataResponseCode
			if code == 0 {
				code = 250
			}
			msg := h.dataResponseMsg
			if msg == "" {
				msg = "2.0.0 Ok: queued as MOCK123"
			}
			w.WriteString(fmt.Sprintf("%d %s\r\n", code, msg))
			w.Flush()

		case cmd == "RSET":
			w.WriteString("250 2.0.0 Ok\r\n")
			w.Flush()

		case cmd == "NOOP":
			w.WriteString("250 2.0.0 Ok\r\n")
			w.Flush()

		case cmd == "QUIT":
			w.WriteString("221 2.0.0 Bye\r\n")
			w.Flush()
			return

		case strings.HasPrefix(cmd, "VRFY"):
			arg := strings.TrimSpace(line[4:])
			w.WriteString(fmt.Sprintf("250 <%s@example.com>\r\n", arg))
			w.Flush()

		case strings.HasPrefix(cmd, "EXPN"):
			w.WriteString("250-user1@example.com\r\n")
			w.WriteString("250 user2@example.com\r\n")
			w.Flush()

		case strings.HasPrefix(cmd, "AUTH PLAIN"):
			if h.rejectAuth {
				w.WriteString("535 5.7.8 Authentication failed\r\n")
			} else {
				w.WriteString("235 2.7.0 Authentication successful\r\n")
			}
			w.Flush()

		case cmd == "AUTH LOGIN":
			if h.rejectAuth {
				w.WriteString("535 5.7.8 Authentication failed\r\n")
				w.Flush()
			} else {
				w.WriteString("334 VXNlcm5hbWU6\r\n") // "Username:" base64
				w.Flush()
				_, err := readLine(r)
				if err != nil {
					return
				}
				w.WriteString("334 UGFzc3dvcmQ6\r\n") // "Password:" base64
				w.Flush()
				_, err = readLine(r)
				if err != nil {
					return
				}
				w.WriteString("235 2.7.0 Authentication successful\r\n")
				w.Flush()
			}

		case strings.HasPrefix(cmd, "STARTTLS"):
			w.WriteString("220 2.0.0 Ready for TLS\r\n")
			w.Flush()
			// We won't actually do TLS in this mock; the client will fail.
			return

		case strings.HasPrefix(cmd, "BDAT"):
			// Parse size
			parts := strings.Fields(line)
			size := 0
			if len(parts) >= 2 {
				fmt.Sscanf(parts[1], "%d", &size)
			}
			// Read exactly size bytes
			buf := make([]byte, size)
			io.ReadFull(r, buf)
			w.WriteString("250 2.0.0 Ok\r\n")
			w.Flush()

		default:
			w.WriteString("502 5.5.1 Command not recognized\r\n")
			w.Flush()
		}
	}
}

// --- Tests for NewClient ---

func TestNewClient_NilConfig(t *testing.T) {
	c := NewClient(nil)
	if c.config == nil {
		t.Fatal("expected non-nil config")
	}
	if c.config.LocalName != "localhost" {
		t.Errorf("expected LocalName 'localhost', got %q", c.config.LocalName)
	}
	if c.extensions == nil {
		t.Fatal("expected initialized extensions map")
	}
}

func TestNewClient_EmptyLocalName(t *testing.T) {
	c := NewClient(&ClientConfig{})
	if c.config.LocalName != "localhost" {
		t.Errorf("expected LocalName 'localhost', got %q", c.config.LocalName)
	}
}

func TestNewClient_CustomConfig(t *testing.T) {
	config := &ClientConfig{
		LocalName:      "custom.local",
		ConnectTimeout: 10 * time.Second,
	}
	c := NewClient(config)
	if c.config.LocalName != "custom.local" {
		t.Errorf("expected LocalName 'custom.local', got %q", c.config.LocalName)
	}
}

// --- Tests for ClientResponse.Error ---

func TestClientResponse_Error_Success(t *testing.T) {
	resp := &ClientResponse{Code: 250, Message: "Ok"}
	if err := resp.Error(); err != nil {
		t.Errorf("expected nil error for success, got %v", err)
	}
}

func TestClientResponse_Error_Intermediate(t *testing.T) {
	resp := &ClientResponse{Code: 354, Message: "Start input"}
	if err := resp.Error(); err != nil {
		t.Errorf("expected nil error for intermediate, got %v", err)
	}
}

func TestClientResponse_Error_Transient(t *testing.T) {
	resp := &ClientResponse{Code: 421, Message: "Service not available"}
	err := resp.Error()
	if err == nil {
		t.Fatal("expected error for 421")
	}
	var smtpErr *SMTPError
	if !isSmtpError(err, &smtpErr) {
		t.Fatal("expected *SMTPError")
	}
	if smtpErr.Code != 421 {
		t.Errorf("expected code 421, got %d", smtpErr.Code)
	}
}

func TestClientResponse_Error_Permanent(t *testing.T) {
	resp := &ClientResponse{Code: 550, Message: "Mailbox not found", EnhancedCode: "5.1.1"}
	err := resp.Error()
	if err == nil {
		t.Fatal("expected error for 550")
	}
	var smtpErr *SMTPError
	if !isSmtpError(err, &smtpErr) {
		t.Fatal("expected *SMTPError")
	}
	if smtpErr.Code != 550 {
		t.Errorf("expected code 550, got %d", smtpErr.Code)
	}
	if smtpErr.EnhancedCode != "5.1.1" {
		t.Errorf("expected enhanced code 5.1.1, got %q", smtpErr.EnhancedCode)
	}
}

func isSmtpError(err error, target **SMTPError) bool {
	e, ok := err.(*SMTPError)
	if ok && target != nil {
		*target = e
	}
	return ok
}

// --- Tests for SMTPError string formatting ---

func TestSMTPError_WithoutEnhancedCode(t *testing.T) {
	err := &SMTPError{Code: 421, Message: "Try again"}
	s := err.Error()
	if !strings.Contains(s, "421") || !strings.Contains(s, "Try again") {
		t.Errorf("unexpected error string: %s", s)
	}
	if strings.Contains(s, ".") && strings.Count(s, ".") > 0 {
		// Enhanced codes have dots; just check format looks right
	}
}

func TestSMTPError_WithEnhancedCode(t *testing.T) {
	err := &SMTPError{Code: 550, EnhancedCode: "5.1.1", Message: "User unknown"}
	s := err.Error()
	if !strings.Contains(s, "5.1.1") {
		t.Errorf("expected enhanced code in string: %s", s)
	}
}

func TestSMTPError_IsTransient_True(t *testing.T) {
	err := &SMTPError{Code: 450}
	if !err.IsTransient() {
		t.Error("expected transient for 450")
	}
	if err.IsPermanent() {
		t.Error("should not be permanent for 450")
	}
}

func TestSMTPError_IsPermanent_True(t *testing.T) {
	err := &SMTPError{Code: 550}
	if !err.IsPermanent() {
		t.Error("expected permanent for 550")
	}
	if err.IsTransient() {
		t.Error("should not be transient for 550")
	}
}

func TestSMTPError_BoundaryValues(t *testing.T) {
	tests := []struct {
		code      int
		transient bool
		permanent bool
	}{
		{399, false, false},
		{400, true, false},
		{499, true, false},
		{500, false, true},
		{599, false, true},
		{600, false, false},
	}
	for _, tt := range tests {
		err := &SMTPError{Code: tt.code}
		if err.IsTransient() != tt.transient {
			t.Errorf("code %d: IsTransient() = %v, want %v", tt.code, err.IsTransient(), tt.transient)
		}
		if err.IsPermanent() != tt.permanent {
			t.Errorf("code %d: IsPermanent() = %v, want %v", tt.code, err.IsPermanent(), tt.permanent)
		}
	}
}

// --- Tests for parseEnhancedCode ---

func TestParseEnhancedCode(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"2.0.0 Ok", "2.0.0"},
		{"5.1.1 User unknown", "5.1.1"},
		{"4.7.0 Try again later", "4.7.0"},
		{"Ok", ""},
		{"", ""},
		{"abc", ""},
		{"2.0 short", ""},
		{"2.0.0", "2.0.0"},
		{"notanum.0.0 test", ""},
		{"2.notanum.0 test", ""},
		{"2.0.notanum test", ""},
		{"12.34.56 large numbers", "12.34.56"},
	}

	for _, tt := range tests {
		result := parseEnhancedCode(tt.input)
		if result != tt.expected {
			t.Errorf("parseEnhancedCode(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// --- Tests for base64Encode ---

func TestBase64Encode(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"f", "Zg=="},
		{"fo", "Zm8="},
		{"foo", "Zm9v"},
		{"foobar", "Zm9vYmFy"},
		{"Hello, World!", "SGVsbG8sIFdvcmxkIQ=="},
		{"\x00user\x00pass", "AHVzZXIAcGFzcw=="},
	}
	for _, tt := range tests {
		result := base64Encode([]byte(tt.input))
		if result != tt.expected {
			t.Errorf("base64Encode(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

// --- Tests for parseExtensions ---

func TestParseExtensions(t *testing.T) {
	c := &Client{
		extensions: make(map[ravenmail.Extension]string),
	}

	lines := []string{
		"mock.example.com Hello",
		"SIZE 10485760",
		"PIPELINING",
		"8BITMIME",
		"AUTH PLAIN LOGIN",
		"STARTTLS",
		"ENHANCEDSTATUSCODES",
		"SMTPUTF8",
		"DSN",
		"CHUNKING",
		"BINARYMIME",
	}

	c.parseExtensions(lines)

	checks := map[ravenmail.Extension]string{
		ravenmail.ExtSize:                "10485760",
		ravenmail.ExtPipelining:          "",
		ravenmail.Ext8BitMIME:            "",
		ravenmail.ExtAuth:                "PLAIN LOGIN",
		ravenmail.ExtSTARTTLS:            "",
		ravenmail.ExtEnhancedStatusCodes: "",
		ravenmail.ExtSMTPUTF8:            "",
		ravenmail.ExtDSN:                 "",
		ravenmail.ExtChunking:            "",
		ravenmail.ExtBinaryMIME:          "",
	}

	for ext, wantParam := range checks {
		got, ok := c.extensions[ext]
		if !ok {
			t.Errorf("parseExtensions: missing extension %s", ext)
			continue
		}
		if got != wantParam {
			t.Errorf("parseExtensions: ext %s = %q, want %q", ext, got, wantParam)
		}
	}
}

func TestParseExtensions_Empty(t *testing.T) {
	c := &Client{extensions: make(map[ravenmail.Extension]string)}
	c.parseExtensions([]string{"mock.example.com Hello"})
	if len(c.extensions) != 0 {
		t.Errorf("expected 0 extensions, got %d", len(c.extensions))
	}
}

func TestParseExtensions_SingleLine(t *testing.T) {
	c := &Client{extensions: make(map[ravenmail.Extension]string)}
	c.parseExtensions([]string{"mock.example.com", "PIPELINING"})
	if _, ok := c.extensions[ravenmail.ExtPipelining]; !ok {
		t.Error("expected PIPELINING extension")
	}
}

// --- Tests for ServerCapabilities ---

func TestServerCapabilities_HasExtension(t *testing.T) {
	caps := &ServerCapabilities{
		Extensions: map[ravenmail.Extension]string{
			ravenmail.ExtPipelining: "",
		},
	}
	if !caps.HasExtension(ravenmail.ExtPipelining) {
		t.Error("expected PIPELINING to be present")
	}
	if caps.HasExtension(ravenmail.ExtSTARTTLS) {
		t.Error("expected STARTTLS to be absent")
	}
}

func TestServerCapabilities_GetExtensionParam(t *testing.T) {
	caps := &ServerCapabilities{
		Extensions: map[ravenmail.Extension]string{
			ravenmail.ExtSize: "10485760",
		},
	}
	if caps.GetExtensionParam(ravenmail.ExtSize) != "10485760" {
		t.Error("expected SIZE param '10485760'")
	}
	if caps.GetExtensionParam(ravenmail.ExtPipelining) != "" {
		t.Error("expected empty param for absent extension")
	}
}

func TestServerCapabilities_SupportsAuth(t *testing.T) {
	caps := &ServerCapabilities{
		Auth: []string{"PLAIN", "LOGIN"},
	}
	if !caps.SupportsAuth("PLAIN") {
		t.Error("expected PLAIN to be supported")
	}
	if !caps.SupportsAuth("plain") {
		t.Error("expected case-insensitive match for PLAIN")
	}
	if !caps.SupportsAuth("LOGIN") {
		t.Error("expected LOGIN to be supported")
	}
	if caps.SupportsAuth("CRAM-MD5") {
		t.Error("expected CRAM-MD5 to not be supported")
	}
}

func TestServerCapabilities_SupportsAuth_Empty(t *testing.T) {
	caps := &ServerCapabilities{}
	if caps.SupportsAuth("PLAIN") {
		t.Error("expected no auth mechanisms")
	}
}

func TestServerCapabilities_String(t *testing.T) {
	caps := &ServerCapabilities{
		IsESMTP:  true,
		Hostname: "mail.example.com",
		MaxSize:  10485760,
		Extensions: map[ravenmail.Extension]string{
			ravenmail.ExtPipelining: "",
			ravenmail.ExtSize:       "10485760",
		},
		Auth: []string{"PLAIN", "LOGIN"},
	}
	s := caps.String()
	if !strings.Contains(s, "ESMTP: true") {
		t.Error("expected ESMTP in string")
	}
	if !strings.Contains(s, "mail.example.com") {
		t.Error("expected hostname in string")
	}
	if !strings.Contains(s, "PLAIN") {
		t.Error("expected auth mechanisms in string")
	}
	if !strings.Contains(s, "10485760") {
		t.Error("expected max size in string")
	}
}

func TestServerCapabilities_String_NoMaxSize(t *testing.T) {
	caps := &ServerCapabilities{
		IsESMTP:    false,
		Extensions: map[ravenmail.Extension]string{},
	}
	s := caps.String()
	if strings.Contains(s, "Max Size") {
		t.Error("should not show max size when 0")
	}
}

// --- Tests for Client.Capabilities ---

func TestClient_Capabilities(t *testing.T) {
	c := &Client{
		isESMTP:  true,
		greeting: "Hello",
		extensions: map[ravenmail.Extension]string{
			ravenmail.ExtSTARTTLS:            "",
			ravenmail.ExtAuth:                "PLAIN LOGIN",
			ravenmail.ExtSize:                "52428800",
			ravenmail.ExtPipelining:          "",
			ravenmail.Ext8BitMIME:            "",
			ravenmail.ExtSMTPUTF8:            "",
			ravenmail.ExtDSN:                 "",
			ravenmail.ExtChunking:            "",
			ravenmail.ExtBinaryMIME:          "",
			ravenmail.ExtEnhancedStatusCodes: "",
		},
	}

	caps := c.Capabilities()
	if !caps.IsESMTP {
		t.Error("expected IsESMTP")
	}
	if !caps.TLS {
		t.Error("expected TLS")
	}
	if !caps.Pipelining {
		t.Error("expected Pipelining")
	}
	if !caps.EightBitMIME {
		t.Error("expected EightBitMIME")
	}
	if !caps.SMTPUTF8 {
		t.Error("expected SMTPUTF8")
	}
	if !caps.DSN {
		t.Error("expected DSN")
	}
	if !caps.Chunking {
		t.Error("expected Chunking")
	}
	if !caps.BinaryMIME {
		t.Error("expected BinaryMIME")
	}
	if !caps.EnhancedStatusCodes {
		t.Error("expected EnhancedStatusCodes")
	}
	if caps.MaxSize != 52428800 {
		t.Errorf("MaxSize = %d, want 52428800", caps.MaxSize)
	}
	if len(caps.Auth) != 2 || caps.Auth[0] != "PLAIN" || caps.Auth[1] != "LOGIN" {
		t.Errorf("Auth = %v, want [PLAIN LOGIN]", caps.Auth)
	}
}

func TestClient_Capabilities_InvalidSize(t *testing.T) {
	c := &Client{
		extensions: map[ravenmail.Extension]string{
			ravenmail.ExtSize: "notanumber",
		},
	}
	caps := c.Capabilities()
	if caps.MaxSize != 0 {
		t.Errorf("expected MaxSize 0 for invalid size, got %d", caps.MaxSize)
	}
}

// --- Tests for Client.Extensions / HasExtension / GetExtensionParam ---

func TestClient_Extensions_ReturnsCopy(t *testing.T) {
	c := &Client{
		extensions: map[ravenmail.Extension]string{
			ravenmail.ExtPipelining: "",
		},
	}
	exts := c.Extensions()
	exts[ravenmail.ExtSTARTTLS] = "" // modify copy
	if c.HasExtension(ravenmail.ExtSTARTTLS) {
		t.Error("modifying Extensions() return should not affect client")
	}
}

func TestClient_HasExtension(t *testing.T) {
	c := &Client{
		extensions: map[ravenmail.Extension]string{
			ravenmail.ExtPipelining: "",
		},
	}
	if !c.HasExtension(ravenmail.ExtPipelining) {
		t.Error("expected PIPELINING")
	}
	if c.HasExtension(ravenmail.ExtSTARTTLS) {
		t.Error("expected no STARTTLS")
	}
}

func TestClient_GetExtensionParam(t *testing.T) {
	c := &Client{
		extensions: map[ravenmail.Extension]string{
			ravenmail.ExtSize: "10485760",
		},
	}
	if c.GetExtensionParam(ravenmail.ExtSize) != "10485760" {
		t.Error("expected SIZE 10485760")
	}
	if c.GetExtensionParam(ravenmail.ExtPipelining) != "" {
		t.Error("expected empty param")
	}
}

// --- Tests for Client accessor methods ---

func TestClient_IsTLS(t *testing.T) {
	c := &Client{isTLS: true}
	if !c.IsTLS() {
		t.Error("expected IsTLS true")
	}
	c2 := &Client{}
	if c2.IsTLS() {
		t.Error("expected IsTLS false")
	}
}

func TestClient_IsESMTP(t *testing.T) {
	c := &Client{isESMTP: true}
	if !c.IsESMTP() {
		t.Error("expected IsESMTP true")
	}
}

func TestClient_IsAuthenticated(t *testing.T) {
	c := &Client{authenticated: true}
	if !c.IsAuthenticated() {
		t.Error("expected IsAuthenticated true")
	}
}

func TestClient_Greeting(t *testing.T) {
	c := &Client{greeting: "Hello there"}
	if c.Greeting() != "Hello there" {
		t.Errorf("expected greeting 'Hello there', got %q", c.Greeting())
	}
}

func TestClient_LastResponse(t *testing.T) {
	resp := &ClientResponse{Code: 250, Message: "Ok"}
	c := &Client{lastResponse: resp}
	if c.LastResponse() != resp {
		t.Error("expected same response pointer")
	}
}

func TestClient_LastResponse_Nil(t *testing.T) {
	c := &Client{}
	if c.LastResponse() != nil {
		t.Error("expected nil lastResponse")
	}
}

// --- Tests for Client.MaxSize ---

func TestClient_MaxSize(t *testing.T) {
	c := &Client{
		extensions: map[ravenmail.Extension]string{
			ravenmail.ExtSize: "52428800",
		},
	}
	if c.MaxSize() != 52428800 {
		t.Errorf("expected 52428800, got %d", c.MaxSize())
	}
}

func TestClient_MaxSize_NotAdvertised(t *testing.T) {
	c := &Client{extensions: map[ravenmail.Extension]string{}}
	if c.MaxSize() != 0 {
		t.Errorf("expected 0, got %d", c.MaxSize())
	}
}

func TestClient_MaxSize_EmptyParam(t *testing.T) {
	c := &Client{
		extensions: map[ravenmail.Extension]string{
			ravenmail.ExtSize: "",
		},
	}
	if c.MaxSize() != 0 {
		t.Errorf("expected 0 for empty size param, got %d", c.MaxSize())
	}
}

func TestClient_MaxSize_Invalid(t *testing.T) {
	c := &Client{
		extensions: map[ravenmail.Extension]string{
			ravenmail.ExtSize: "notanumber",
		},
	}
	if c.MaxSize() != 0 {
		t.Errorf("expected 0 for invalid size, got %d", c.MaxSize())
	}
}

// --- Connection integration tests with mock server ---

func TestClient_Dial_And_Hello(t *testing.T) {
	h := &basicSMTPHandler{
		extensions: []string{"SIZE 10485760", "PIPELINING", "8BITMIME", "ENHANCEDSTATUSCODES"},
	}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	c := NewClient(DefaultClientConfig())

	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	if !c.IsESMTP() {
		t.Error("expected ESMTP")
	}
	if !c.HasExtension(ravenmail.ExtPipelining) {
		t.Error("expected PIPELINING extension")
	}
	if !c.HasExtension(ravenmail.ExtSize) {
		t.Error("expected SIZE extension")
	}
}

func TestClient_Dial_ClosedClient(t *testing.T) {
	c := NewClient(nil)
	c.closed = true
	err := c.Dial("127.0.0.1:9999")
	if err != ErrClientClosed {
		t.Errorf("expected ErrClientClosed, got %v", err)
	}
}

func TestClient_DialTLS_ClosedClient(t *testing.T) {
	c := NewClient(nil)
	c.closed = true
	err := c.DialTLS("127.0.0.1:9999")
	if err != ErrClientClosed {
		t.Errorf("expected ErrClientClosed, got %v", err)
	}
}

func TestClient_Hello_NoConnection(t *testing.T) {
	c := NewClient(nil)
	err := c.Hello()
	if err != ErrNoConnection {
		t.Errorf("expected ErrNoConnection, got %v", err)
	}
}

func TestClient_Hello_FallbackToHELO(t *testing.T) {
	// Server rejects EHLO but accepts HELO
	srv := newMockSMTPServer(t, func(conn net.Conn) {
		r := bufio.NewReader(conn)
		w := bufio.NewWriter(conn)

		smtpGreeting(w)

		for {
			line, err := readLine(r)
			if err != nil {
				return
			}
			cmd := strings.ToUpper(line)
			switch {
			case strings.HasPrefix(cmd, "EHLO"):
				w.WriteString("502 5.5.1 Not supported\r\n")
				w.Flush()
			case strings.HasPrefix(cmd, "HELO"):
				w.WriteString("250 mock.example.com\r\n")
				w.Flush()
			case cmd == "QUIT":
				w.WriteString("221 Bye\r\n")
				w.Flush()
				return
			default:
				w.WriteString("502 5.5.1 Not supported\r\n")
				w.Flush()
			}
		}
	})
	defer srv.close()

	c := NewClient(DefaultClientConfig())
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	if c.IsESMTP() {
		t.Error("should not be ESMTP with HELO fallback")
	}
}

func TestClient_Greeting_AfterDial(t *testing.T) {
	h := &basicSMTPHandler{}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	c := NewClient(DefaultClientConfig())
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	greeting := c.Greeting()
	if greeting == "" {
		t.Error("expected non-empty greeting")
	}
}

func TestClient_Dial_BadGreeting(t *testing.T) {
	srv := newMockSMTPServer(t, func(conn net.Conn) {
		w := bufio.NewWriter(conn)
		w.WriteString("421 Service unavailable\r\n")
		w.Flush()
	})
	defer srv.close()

	c := NewClient(DefaultClientConfig())
	err := c.Dial(srv.addr())
	if err == nil {
		t.Fatal("expected error for 421 greeting")
	}
}

// --- Auth tests ---

func TestClient_Auth_PLAIN(t *testing.T) {
	h := &basicSMTPHandler{authMechanisms: "PLAIN LOGIN"}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	config := DefaultClientConfig()
	config.Auth = &ClientAuth{Username: "user", Password: "pass"}
	c := NewClient(config)

	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	if err := c.Auth(); err != nil {
		t.Fatalf("Auth: %v", err)
	}

	if !c.IsAuthenticated() {
		t.Error("expected authenticated")
	}
}

func TestClient_Auth_LOGIN(t *testing.T) {
	h := &basicSMTPHandler{authMechanisms: "LOGIN"}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	config := DefaultClientConfig()
	config.Auth = &ClientAuth{Username: "user", Password: "pass"}
	c := NewClient(config)

	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	if err := c.Auth(); err != nil {
		t.Fatalf("Auth LOGIN: %v", err)
	}
}

func TestClient_Auth_Rejected(t *testing.T) {
	h := &basicSMTPHandler{authMechanisms: "PLAIN LOGIN", rejectAuth: true}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	config := DefaultClientConfig()
	config.Auth = &ClientAuth{Username: "user", Password: "wrong"}
	c := NewClient(config)

	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	if err := c.Auth(); err == nil {
		t.Fatal("expected auth failure")
	}
}

func TestClient_Auth_NoCredentials(t *testing.T) {
	c := NewClient(DefaultClientConfig())
	c.conn = &net.TCPConn{} // stub
	err := c.Auth()
	if err == nil {
		t.Fatal("expected error for no credentials")
	}
}

func TestClient_Auth_NoConnection(t *testing.T) {
	config := DefaultClientConfig()
	config.Auth = &ClientAuth{Username: "u", Password: "p"}
	c := NewClient(config)
	err := c.Auth()
	if err != ErrNoConnection {
		t.Errorf("expected ErrNoConnection, got %v", err)
	}
}

func TestClient_Auth_ExtensionNotSupported(t *testing.T) {
	// Server doesn't offer AUTH
	h := &basicSMTPHandler{extensions: []string{"PIPELINING"}}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	config := DefaultClientConfig()
	config.Auth = &ClientAuth{Username: "user", Password: "pass"}
	c := NewClient(config)

	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	err := c.Auth()
	if err == nil {
		t.Fatal("expected error when AUTH not supported")
	}
}

func TestClient_Auth_NoSupportedMechanism(t *testing.T) {
	h := &basicSMTPHandler{extensions: []string{"AUTH XOAUTH2 CRAM-MD5"}}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	config := DefaultClientConfig()
	config.Auth = &ClientAuth{Username: "user", Password: "pass"}
	c := NewClient(config)

	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	err := c.Auth()
	if err == nil {
		t.Fatal("expected error for unsupported mechanisms")
	}
}

func TestClient_AuthWithMechanism(t *testing.T) {
	h := &basicSMTPHandler{authMechanisms: "PLAIN LOGIN"}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	config := DefaultClientConfig()
	config.Auth = &ClientAuth{Username: "user", Password: "pass"}
	c := NewClient(config)

	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	if err := c.AuthWithMechanism("PLAIN"); err != nil {
		t.Fatalf("AuthWithMechanism PLAIN: %v", err)
	}
}

func TestClient_AuthWithMechanism_Unsupported(t *testing.T) {
	config := DefaultClientConfig()
	config.Auth = &ClientAuth{Username: "u", Password: "p"}
	c := NewClient(config)
	c.conn = &net.TCPConn{} // stub
	err := c.AuthWithMechanism("GSSAPI")
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("expected unsupported mechanism error, got %v", err)
	}
}

func TestClient_AuthWithMechanism_NoConnection(t *testing.T) {
	config := DefaultClientConfig()
	config.Auth = &ClientAuth{Username: "u", Password: "p"}
	c := NewClient(config)
	err := c.AuthWithMechanism("PLAIN")
	if err != ErrNoConnection {
		t.Errorf("expected ErrNoConnection, got %v", err)
	}
}

func TestClient_AuthWithMechanism_NoCredentials(t *testing.T) {
	c := NewClient(DefaultClientConfig())
	c.conn = &net.TCPConn{} // stub
	err := c.AuthWithMechanism("PLAIN")
	if err == nil || !strings.Contains(err.Error(), "no authentication") {
		t.Errorf("expected no credentials error, got %v", err)
	}
}

// --- Reset / Noop / Quit / Close tests ---

func TestClient_Reset(t *testing.T) {
	h := &basicSMTPHandler{}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	c := NewClient(DefaultClientConfig())
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	if err := c.Reset(); err != nil {
		t.Fatalf("Reset: %v", err)
	}
}

func TestClient_Reset_NoConnection(t *testing.T) {
	c := NewClient(nil)
	if err := c.Reset(); err != ErrNoConnection {
		t.Errorf("expected ErrNoConnection, got %v", err)
	}
}

func TestClient_Noop(t *testing.T) {
	h := &basicSMTPHandler{}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	c := NewClient(DefaultClientConfig())
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	if err := c.Noop(); err != nil {
		t.Fatalf("Noop: %v", err)
	}
}

func TestClient_Noop_NoConnection(t *testing.T) {
	c := NewClient(nil)
	if err := c.Noop(); err != ErrNoConnection {
		t.Errorf("expected ErrNoConnection, got %v", err)
	}
}

func TestClient_Quit(t *testing.T) {
	h := &basicSMTPHandler{}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	c := NewClient(DefaultClientConfig())
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}

	if err := c.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	if err := c.Quit(); err != nil {
		t.Fatalf("Quit: %v", err)
	}
}

func TestClient_Quit_NoConnection(t *testing.T) {
	c := NewClient(nil)
	if err := c.Quit(); err != ErrNoConnection {
		t.Errorf("expected ErrNoConnection, got %v", err)
	}
}

func TestClient_Close(t *testing.T) {
	h := &basicSMTPHandler{}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	c := NewClient(DefaultClientConfig())
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Close again should be fine (nil conn)
	if err := c.Close(); err != nil {
		t.Fatalf("Close again: %v", err)
	}
}

// --- Send tests ---

func TestClient_Send_Success(t *testing.T) {
	h := &basicSMTPHandler{
		dataResponseMsg: "2.0.0 Ok: queued as TEST456",
	}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	c := NewClient(&ClientConfig{
		LocalName:          "localhost",
		ValidateBeforeSend: false,
	})

	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	mail := ravenmail.NewMailBuilder().
		From("sender@example.com").
		To("recipient@example.com").
		Subject("Test").
		TextBody("Hello World").
		MustBuild()

	result, err := c.Send(mail)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	if !result.Success {
		t.Error("expected success")
	}
	if result.MessageID != "TEST456" {
		t.Errorf("expected MessageID 'TEST456', got %q", result.MessageID)
	}
	if len(result.RecipientResults) != 1 {
		t.Fatalf("expected 1 recipient result, got %d", len(result.RecipientResults))
	}
	if !result.RecipientResults[0].Accepted {
		t.Error("expected recipient accepted")
	}
}

func TestClient_Send_NoConnection(t *testing.T) {
	c := NewClient(&ClientConfig{LocalName: "localhost"})
	mail := ravenmail.NewMailBuilder().
		From("a@b.com").To("c@d.com").Subject("test").TextBody("body").MustBuild()

	_, err := c.Send(mail)
	if err != ErrNoConnection {
		t.Errorf("expected ErrNoConnection, got %v", err)
	}
}

func TestClient_Send_NoRecipients(t *testing.T) {
	h := &basicSMTPHandler{}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	c := NewClient(&ClientConfig{LocalName: "localhost", ValidateBeforeSend: false})
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	mail := ravenmail.NewMail()
	mail.Envelope.From = ravenmail.Path{Mailbox: ravenmail.MailboxAddress{LocalPart: "sender", Domain: "example.com"}}

	_, err := c.Send(mail)
	if err != ErrNoRecipients {
		t.Errorf("expected ErrNoRecipients, got %v", err)
	}
}

func TestClient_Send_AllRecipientsRejected(t *testing.T) {
	h := &basicSMTPHandler{
		rejectRcptTo: map[string]bool{
			"<bad@example.com>": true,
		},
	}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	c := NewClient(&ClientConfig{LocalName: "localhost", ValidateBeforeSend: false})
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	mail := ravenmail.NewMailBuilder().
		From("sender@example.com").
		To("bad@example.com").
		Subject("Test").
		TextBody("Hello").
		MustBuild()

	_, err := c.Send(mail)
	if err == nil {
		t.Fatal("expected error for all rejected recipients")
	}
}

func TestClient_Send_PartialRecipientRejection(t *testing.T) {
	h := &basicSMTPHandler{
		rejectRcptTo: map[string]bool{
			"<bad@example.com>": true,
		},
	}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	c := NewClient(&ClientConfig{LocalName: "localhost", ValidateBeforeSend: false})
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	mail := ravenmail.NewMailBuilder().
		From("sender@example.com").
		To("good@example.com").
		To("bad@example.com").
		Subject("Test").
		TextBody("Hello").
		MustBuild()

	result, err := c.Send(mail)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	if !result.Success {
		t.Error("expected overall success (some recipients accepted)")
	}

	accepted := 0
	rejected := 0
	for _, rr := range result.RecipientResults {
		if rr.Accepted {
			accepted++
		} else {
			rejected++
		}
	}
	if accepted != 1 || rejected != 1 {
		t.Errorf("expected 1 accepted and 1 rejected, got %d accepted and %d rejected", accepted, rejected)
	}
}

// --- SendWithOptions tests ---

func TestClient_SendWithOptions_RequireAllRecipients(t *testing.T) {
	h := &basicSMTPHandler{
		rejectRcptTo: map[string]bool{
			"<bad@example.com>": true,
		},
	}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	c := NewClient(&ClientConfig{LocalName: "localhost", ValidateBeforeSend: false})
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	mail := ravenmail.NewMailBuilder().
		From("sender@example.com").
		To("good@example.com").
		To("bad@example.com").
		Subject("Test").
		TextBody("Hello").
		MustBuild()

	_, err := c.SendWithOptions(mail, SendOptions{RequireAllRecipients: true})
	if err == nil {
		t.Fatal("expected error when RequireAllRecipients and some rejected")
	}
}

func TestClient_SendWithOptions_NoConnection(t *testing.T) {
	c := NewClient(&ClientConfig{LocalName: "localhost"})
	mail := ravenmail.NewMailBuilder().
		From("a@b.com").To("c@d.com").Subject("t").TextBody("b").MustBuild()

	_, err := c.SendWithOptions(mail, SendOptions{})
	if err != ErrNoConnection {
		t.Errorf("expected ErrNoConnection, got %v", err)
	}
}

func TestClient_SendWithOptions_NoRecipients(t *testing.T) {
	h := &basicSMTPHandler{}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	c := NewClient(&ClientConfig{LocalName: "localhost", ValidateBeforeSend: false})
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	mail := ravenmail.NewMail()
	mail.Envelope.From = ravenmail.Path{Mailbox: ravenmail.MailboxAddress{LocalPart: "s", Domain: "e.com"}}

	_, err := c.SendWithOptions(mail, SendOptions{})
	if err != ErrNoRecipients {
		t.Errorf("expected ErrNoRecipients, got %v", err)
	}
}

// --- Verify / Expand tests ---

func TestClient_Verify(t *testing.T) {
	h := &basicSMTPHandler{}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	c := NewClient(DefaultClientConfig())
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	result, err := c.Verify("testuser")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty verify result")
	}
}

func TestClient_Verify_NoConnection(t *testing.T) {
	c := NewClient(nil)
	_, err := c.Verify("test")
	if err != ErrNoConnection {
		t.Errorf("expected ErrNoConnection, got %v", err)
	}
}

func TestClient_Expand(t *testing.T) {
	h := &basicSMTPHandler{}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	c := NewClient(DefaultClientConfig())
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	result, err := c.Expand("testlist")
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 expansion results, got %d", len(result))
	}
}

func TestClient_Expand_NoConnection(t *testing.T) {
	c := NewClient(nil)
	_, err := c.Expand("list")
	if err != ErrNoConnection {
		t.Errorf("expected ErrNoConnection, got %v", err)
	}
}

// --- RawCommand tests ---

func TestClient_RawCommand(t *testing.T) {
	h := &basicSMTPHandler{}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	c := NewClient(DefaultClientConfig())
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	resp, err := c.RawCommand("NOOP")
	if err != nil {
		t.Fatalf("RawCommand: %v", err)
	}
	if !resp.IsSuccess() {
		t.Errorf("expected success, got %d", resp.Code)
	}
}

func TestClient_RawCommand_NoConnection(t *testing.T) {
	c := NewClient(nil)
	_, err := c.RawCommand("NOOP")
	if err != ErrNoConnection {
		t.Errorf("expected ErrNoConnection, got %v", err)
	}
}

// --- PipelineCommands tests ---

func TestClient_PipelineCommands(t *testing.T) {
	h := &basicSMTPHandler{extensions: []string{"PIPELINING"}}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	c := NewClient(DefaultClientConfig())
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	responses, err := c.PipelineCommands([]string{"NOOP", "NOOP", "NOOP"})
	if err != nil {
		t.Fatalf("PipelineCommands: %v", err)
	}
	if len(responses) != 3 {
		t.Errorf("expected 3 responses, got %d", len(responses))
	}
	for i, resp := range responses {
		if !resp.IsSuccess() {
			t.Errorf("response %d: expected success, got %d", i, resp.Code)
		}
	}
}

func TestClient_PipelineCommands_NoConnection(t *testing.T) {
	c := NewClient(nil)
	_, err := c.PipelineCommands([]string{"NOOP"})
	if err != ErrNoConnection {
		t.Errorf("expected ErrNoConnection, got %v", err)
	}
}

func TestClient_PipelineCommands_NoPipeliningSupport(t *testing.T) {
	h := &basicSMTPHandler{extensions: []string{"SIZE 10485760"}}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	c := NewClient(DefaultClientConfig())
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	_, err := c.PipelineCommands([]string{"NOOP"})
	if err == nil {
		t.Fatal("expected error for missing PIPELINING")
	}
}

// --- StartTLS tests ---

func TestClient_StartTLS_NoConnection(t *testing.T) {
	c := NewClient(nil)
	c.extensions = map[ravenmail.Extension]string{}
	err := c.StartTLS()
	if err != ErrNoConnection {
		t.Errorf("expected ErrNoConnection, got %v", err)
	}
}

func TestClient_StartTLS_AlreadyTLS(t *testing.T) {
	h := &basicSMTPHandler{extensions: []string{"STARTTLS"}}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	c := NewClient(DefaultClientConfig())
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	c.isTLS = true
	err := c.StartTLS()
	if err != ErrTLSAlreadyActive {
		t.Errorf("expected ErrTLSAlreadyActive, got %v", err)
	}
}

func TestClient_StartTLS_NotSupported(t *testing.T) {
	h := &basicSMTPHandler{extensions: []string{"PIPELINING"}}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	c := NewClient(DefaultClientConfig())
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	err := c.StartTLS()
	if err != ErrTLSNotSupported {
		t.Errorf("expected ErrTLSNotSupported, got %v", err)
	}
}

// --- Pool tests ---

func TestPool_NewPool_DefaultSize(t *testing.T) {
	d := NewDialer("localhost", 25)
	p := NewPool(d, 0)
	if p.size != 5 {
		t.Errorf("expected default size 5, got %d", p.size)
	}
}

func TestPool_NewPool_NegativeSize(t *testing.T) {
	d := NewDialer("localhost", 25)
	p := NewPool(d, -1)
	if p.size != 5 {
		t.Errorf("expected default size 5, got %d", p.size)
	}
}

func TestPool_NewPool_CustomSize(t *testing.T) {
	d := NewDialer("localhost", 25)
	p := NewPool(d, 10)
	if p.size != 10 {
		t.Errorf("expected size 10, got %d", p.size)
	}
}

func TestPool_Close(t *testing.T) {
	d := NewDialer("localhost", 25)
	p := NewPool(d, 5)
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !p.closed {
		t.Error("expected pool to be closed")
	}
}

func TestPool_Get_ClosedPool(t *testing.T) {
	d := NewDialer("localhost", 25)
	p := NewPool(d, 5)
	p.Close()
	_, err := p.Get()
	if err != ErrClientClosed {
		t.Errorf("expected ErrClientClosed, got %v", err)
	}
}

func TestPool_Put_ClosedPool(t *testing.T) {
	h := &basicSMTPHandler{}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	host, portStr, _ := net.SplitHostPort(srv.addr())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	d := NewDialer(host, port)
	p := NewPool(d, 5)
	p.Close()

	// Create a client directly
	c := NewClient(DefaultClientConfig())
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// Put into closed pool should close the client
	p.Put(c)
}

// --- Dialer tests ---

func TestNewDialer_Defaults(t *testing.T) {
	d := NewDialer("mail.example.com", 465)
	if d.Host != "mail.example.com" {
		t.Errorf("expected Host 'mail.example.com', got %q", d.Host)
	}
	if d.Port != 465 {
		t.Errorf("expected Port 465, got %d", d.Port)
	}
	if d.ConnectTimeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", d.ConnectTimeout)
	}
	if d.ReadTimeout != 5*time.Minute {
		t.Errorf("expected 5m read timeout, got %v", d.ReadTimeout)
	}
	if d.WriteTimeout != 5*time.Minute {
		t.Errorf("expected 5m write timeout, got %v", d.WriteTimeout)
	}
}

func TestDialer_Dial(t *testing.T) {
	h := &basicSMTPHandler{extensions: []string{"SIZE 10485760"}}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	host, portStr, _ := net.SplitHostPort(srv.addr())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	d := NewDialer(host, port)
	client, err := d.Dial()
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	if !client.IsESMTP() {
		t.Error("expected ESMTP")
	}
}

func TestDialer_Dial_WithLocalName(t *testing.T) {
	h := &basicSMTPHandler{}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	host, portStr, _ := net.SplitHostPort(srv.addr())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	d := NewDialer(host, port)
	d.LocalName = "my.client.example.com"
	client, err := d.Dial()
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
}

func TestDialer_DialAndSend(t *testing.T) {
	h := &basicSMTPHandler{dataResponseMsg: "2.0.0 Ok: queued as ABC"}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	host, portStr, _ := net.SplitHostPort(srv.addr())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	d := NewDialer(host, port)

	mail := ravenmail.NewMailBuilder().
		From("sender@example.com").
		To("recipient@example.com").
		Subject("Test").
		TextBody("Hello").
		MustBuild()

	result, err := d.DialAndSend(mail)
	if err != nil {
		t.Fatalf("DialAndSend: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
}

func TestDialer_DialAndSendMultiple(t *testing.T) {
	h := &basicSMTPHandler{dataResponseMsg: "2.0.0 Ok: queued as MSG"}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	host, portStr, _ := net.SplitHostPort(srv.addr())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	d := NewDialer(host, port)

	mails := []*ravenmail.Mail{
		ravenmail.NewMailBuilder().
			From("a@b.com").To("c@d.com").Subject("Test 1").TextBody("Body 1").MustBuild(),
		ravenmail.NewMailBuilder().
			From("a@b.com").To("e@f.com").Subject("Test 2").TextBody("Body 2").MustBuild(),
	}

	results, err := d.DialAndSendMultiple(mails)
	if err != nil {
		t.Fatalf("DialAndSendMultiple: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for i, r := range results {
		if !r.Success {
			t.Errorf("mail %d: expected success", i)
		}
	}
}

func TestDialer_Dial_ConnectionRefused(t *testing.T) {
	d := NewDialer("127.0.0.1", 1) // Port 1 likely refused
	d.ConnectTimeout = 1 * time.Second
	_, err := d.Dial()
	if err == nil {
		t.Fatal("expected connection error")
	}
}

func TestDialer_Dial_WithAuth(t *testing.T) {
	h := &basicSMTPHandler{authMechanisms: "PLAIN LOGIN"}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	host, portStr, _ := net.SplitHostPort(srv.addr())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	d := NewDialer(host, port)
	d.Auth = &ClientAuth{Username: "user", Password: "pass"}

	client, err := d.Dial()
	if err != nil {
		t.Fatalf("Dial with auth: %v", err)
	}
	defer client.Close()

	if !client.IsAuthenticated() {
		t.Error("expected authenticated")
	}
}

// --- Debug output tests ---

func TestClient_DebugOutput(t *testing.T) {
	h := &basicSMTPHandler{}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	var buf strings.Builder
	config := &ClientConfig{
		LocalName:   "localhost",
		Debug:       true,
		DebugWriter: &buf,
	}

	c := NewClient(config)
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	debugOutput := buf.String()
	if !strings.Contains(debugOutput, "EHLO") {
		t.Error("expected EHLO in debug output")
	}
	if !strings.Contains(debugOutput, "S:") {
		t.Error("expected server response in debug output")
	}
}

// --- dotStuff edge cases ---

func TestDotStuff_EmptyInput(t *testing.T) {
	result := dotStuff([]byte{})
	if len(result) != 0 {
		t.Error("expected empty output for empty input")
	}
}

func TestDotStuff_NoDots(t *testing.T) {
	input := []byte("Hello World\r\n")
	result := dotStuff(input)
	// Should return original slice when no dots at line start
	if string(result) != string(input) {
		t.Errorf("expected unchanged output, got %q", result)
	}
}

func TestDotStuff_DotAtVeryStart(t *testing.T) {
	input := []byte(".\r\n")
	result := dotStuff(input)
	if string(result) != "..\r\n" {
		t.Errorf("expected '..\\r\\n', got %q", result)
	}
}

func TestDotStuff_MultipleDotLines(t *testing.T) {
	input := []byte(".first\r\n.second\r\n.third\r\n")
	result := dotStuff(input)
	if string(result) != "..first\r\n..second\r\n..third\r\n" {
		t.Errorf("unexpected result: %q", result)
	}
}

func TestDotStuff_MixedContent(t *testing.T) {
	input := []byte("Normal line\r\n.dot line\r\nAnother normal\r\n.another dot\r\n")
	result := dotStuff(input)
	expected := "Normal line\r\n..dot line\r\nAnother normal\r\n..another dot\r\n"
	if string(result) != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

// --- extractMessageID edge cases ---

func TestExtractMessageID_AngleBracketIncomplete(t *testing.T) {
	result := extractMessageID("<incomplete")
	if result != "" {
		t.Errorf("expected empty for incomplete angle bracket, got %q", result)
	}
}

func TestExtractMessageID_QueuedAsMultipleWords(t *testing.T) {
	result := extractMessageID("Ok: queued as ABC123 extra")
	if result != "ABC123" {
		t.Errorf("expected 'ABC123', got %q", result)
	}
}

func TestExtractMessageID_IdEqualsPattern(t *testing.T) {
	result := extractMessageID("message id=XYZ789 accepted")
	if result != "XYZ789" {
		t.Errorf("expected 'XYZ789', got %q", result)
	}
}

func TestExtractMessageID_WhitespaceOnly(t *testing.T) {
	result := extractMessageID("   ")
	if result != "" {
		t.Errorf("expected empty for whitespace, got %q", result)
	}
}

// --- Additional resolveLocalAddr edge cases ---

func TestResolveLocalAddr_IPv6Loopback(t *testing.T) {
	addr, err := resolveLocalAddr("::1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr.IP.String() != "::1" {
		t.Errorf("expected ::1, got %s", addr.IP.String())
	}
}

func TestResolveLocalAddr_IPv4WithPort(t *testing.T) {
	addr, err := resolveLocalAddr("192.168.1.1:1234")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr.IP.String() != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %s", addr.IP.String())
	}
	if addr.Port != 1234 {
		t.Errorf("expected port 1234, got %d", addr.Port)
	}
}

// --- Client.selectAuthMechanism edge cases ---

func TestSelectAuthMechanism_EmptyServerMechanisms(t *testing.T) {
	config := DefaultClientConfig()
	config.Auth = &ClientAuth{Username: "u", Password: "p"}
	c := &Client{config: config}

	result := c.selectAuthMechanism(nil)
	if result != "" {
		t.Errorf("expected empty for nil server mechanisms, got %q", result)
	}
}

func TestSelectAuthMechanism_EmptyClientAndServerMechanisms(t *testing.T) {
	config := DefaultClientConfig()
	config.Auth = &ClientAuth{Username: "u", Password: "p"}
	c := &Client{config: config}

	result := c.selectAuthMechanism([]string{})
	if result != "" {
		t.Errorf("expected empty for empty server mechanisms, got %q", result)
	}
}

func TestSelectAuthMechanism_CaseInsensitive(t *testing.T) {
	config := DefaultClientConfig()
	config.Auth = &ClientAuth{Username: "u", Password: "p"}
	c := &Client{config: config}

	result := c.selectAuthMechanism([]string{"plain", "login"})
	if result != "PLAIN" {
		t.Errorf("expected PLAIN (case-insensitive), got %q", result)
	}
}

func TestSelectAuthMechanism_ClientPreference_CaseInsensitive(t *testing.T) {
	config := DefaultClientConfig()
	config.Auth = &ClientAuth{
		Username:   "u",
		Password:   "p",
		Mechanisms: []string{"login"},
	}
	c := &Client{config: config}

	result := c.selectAuthMechanism([]string{"PLAIN", "LOGIN"})
	if result != "LOGIN" {
		t.Errorf("expected LOGIN, got %q", result)
	}
}

func TestSelectAuthMechanism_ClientPreference_NoMatch(t *testing.T) {
	config := DefaultClientConfig()
	config.Auth = &ClientAuth{
		Username:   "u",
		Password:   "p",
		Mechanisms: []string{"XOAUTH2"},
	}
	c := &Client{config: config}

	result := c.selectAuthMechanism([]string{"PLAIN", "LOGIN"})
	if result != "" {
		t.Errorf("expected empty when no match, got %q", result)
	}
}

// --- SendMultiple tests ---

func TestClient_SendMultiple(t *testing.T) {
	h := &basicSMTPHandler{dataResponseMsg: "2.0.0 Ok: queued as MULTI"}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	c := NewClient(&ClientConfig{LocalName: "localhost", ValidateBeforeSend: false})
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	mails := []*ravenmail.Mail{
		ravenmail.NewMailBuilder().
			From("a@b.com").To("c@d.com").Subject("One").TextBody("one").MustBuild(),
		ravenmail.NewMailBuilder().
			From("a@b.com").To("e@f.com").Subject("Two").TextBody("two").MustBuild(),
	}

	results, err := c.SendMultiple(mails)
	if err != nil {
		t.Fatalf("SendMultiple: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for i, r := range results {
		if !r.Success {
			t.Errorf("mail %d: expected success", i)
		}
	}
}

// --- RawData tests ---

func TestClient_RawData_NoConnection(t *testing.T) {
	c := NewClient(nil)
	_, err := c.RawData([]byte("test"))
	if err != ErrNoConnection {
		t.Errorf("expected ErrNoConnection, got %v", err)
	}
}

// --- StreamData tests ---

func TestClient_StreamData_NoConnection(t *testing.T) {
	c := NewClient(nil)
	_, err := c.StreamData(strings.NewReader("test"))
	if err != ErrNoConnection {
		t.Errorf("expected ErrNoConnection, got %v", err)
	}
}

// --- Send with BDAT ---

func TestClient_Send_WithBDAT(t *testing.T) {
	h := &basicSMTPHandler{extensions: []string{"CHUNKING"}}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	c := NewClient(&ClientConfig{LocalName: "localhost", ValidateBeforeSend: false})
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	// Build a mail, then use SendWithOptions with BDAT
	mail := ravenmail.NewMailBuilder().
		From("sender@example.com").
		To("recipient@example.com").
		Subject("Test BDAT").
		TextBody("Hello BDAT").
		MustBuild()

	result, err := c.SendWithOptions(mail, SendOptions{PreferBDAT: true, ChunkSize: 32})
	if err != nil {
		t.Fatalf("SendWithOptions with BDAT: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
}

// --- Send with BDAT using default chunk size ---

func TestClient_SendWithOptions_BDAT_DefaultChunkSize(t *testing.T) {
	h := &basicSMTPHandler{extensions: []string{"CHUNKING"}}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	c := NewClient(&ClientConfig{LocalName: "localhost", ValidateBeforeSend: false})
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	mail := ravenmail.NewMailBuilder().
		From("sender@example.com").
		To("recipient@example.com").
		Subject("Test").
		TextBody("Body").
		MustBuild()

	result, err := c.SendWithOptions(mail, SendOptions{PreferBDAT: true})
	if err != nil {
		t.Fatalf("SendWithOptions BDAT default chunk: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
}

// --- Dialer with STARTTLS requested but not available ---

func TestDialer_StartTLS_NotAvailable_NotRequired(t *testing.T) {
	h := &basicSMTPHandler{extensions: []string{"SIZE 10485760"}} // no STARTTLS
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	host, portStr, _ := net.SplitHostPort(srv.addr())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	d := NewDialer(host, port)
	d.StartTLS = true
	d.RequireTLS = false // not required, so should succeed

	client, err := d.Dial()
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()
}

func TestDialer_StartTLS_NotAvailable_Required(t *testing.T) {
	h := &basicSMTPHandler{extensions: []string{"SIZE 10485760"}} // no STARTTLS
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	host, portStr, _ := net.SplitHostPort(srv.addr())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	d := NewDialer(host, port)
	d.StartTLS = true
	d.RequireTLS = true

	_, err := d.Dial()
	if err == nil {
		t.Fatal("expected error when STARTTLS required but not available")
	}
}

// --- Send with DialTLS context explicit test for DialTLSContext closed client ---

func TestClient_DialTLSContext_ClosedClient(t *testing.T) {
	c := NewClient(nil)
	c.closed = true
	err := c.DialTLSContext(context.TODO(), "127.0.0.1:465")
	if err != ErrClientClosed {
		t.Errorf("expected ErrClientClosed, got %v", err)
	}
}

// --- Send mail with RequireTLS when not supported ---

func TestClient_Send_RequireTLS_NotSupported(t *testing.T) {
	h := &basicSMTPHandler{} // no REQUIRETLS extension
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	c := NewClient(&ClientConfig{LocalName: "localhost", ValidateBeforeSend: false})
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	mail := ravenmail.NewMailBuilder().
		From("sender@example.com").
		To("recipient@example.com").
		Subject("Test").
		TextBody("body").
		RequireTLS().
		MustBuild()

	_, err := c.Send(mail)
	if err == nil {
		t.Fatal("expected error when REQUIRETLS not supported")
	}
}

// --- Dialer with SSL flag and connection error ---

func TestDialer_SSL_ConnectionRefused(t *testing.T) {
	d := NewDialer("127.0.0.1", 1) // Port that won't accept
	d.SSL = true
	d.ConnectTimeout = 1 * time.Second
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	_, err := d.Dial()
	if err == nil {
		t.Fatal("expected error for SSL connection to non-TLS port")
	}
}

// --- Response boundary codes ---

func TestClientResponse_BoundaryCodes(t *testing.T) {
	tests := []struct {
		code           int
		isSuccess      bool
		isIntermediate bool
		isTransient    bool
		isPermanent    bool
	}{
		{199, false, false, false, false},
		{200, true, false, false, false},
		{299, true, false, false, false},
		{300, false, true, false, false},
		{399, false, true, false, false},
		{400, false, false, true, false},
		{499, false, false, true, false},
		{500, false, false, false, true},
		{599, false, false, false, true},
		{600, false, false, false, false},
		{100, false, false, false, false},
		{0, false, false, false, false},
	}

	for _, tt := range tests {
		resp := &ClientResponse{Code: tt.code}
		if resp.IsSuccess() != tt.isSuccess {
			t.Errorf("Code %d: IsSuccess() = %v, want %v", tt.code, resp.IsSuccess(), tt.isSuccess)
		}
		if resp.IsIntermediate() != tt.isIntermediate {
			t.Errorf("Code %d: IsIntermediate() = %v, want %v", tt.code, resp.IsIntermediate(), tt.isIntermediate)
		}
		if resp.IsTransientError() != tt.isTransient {
			t.Errorf("Code %d: IsTransientError() = %v, want %v", tt.code, resp.IsTransientError(), tt.isTransient)
		}
		if resp.IsPermanentError() != tt.isPermanent {
			t.Errorf("Code %d: IsPermanentError() = %v, want %v", tt.code, resp.IsPermanentError(), tt.isPermanent)
		}
	}
}

// --- Fuzz tests ---

func FuzzDotStuff(f *testing.F) {
	f.Add([]byte("Hello\r\n"))
	f.Add([]byte(".hidden\r\n"))
	f.Add([]byte("Hello\r\n.World\r\n"))
	f.Add([]byte("..already\r\n"))
	f.Add([]byte(""))
	f.Add([]byte(".\r\n"))
	f.Add([]byte("No dots\r\n"))
	f.Add([]byte(".a\r\n.b\r\n.c\r\n"))
	f.Add([]byte("data without newline"))
	f.Add([]byte(".\n..\n...\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		result := dotStuff(data)

		// Invariant: result length >= input length
		if len(result) < len(data) {
			t.Errorf("dotStuff output shorter than input: %d < %d", len(result), len(data))
		}

		// Invariant: every byte from input should be in result (with possible extra dots)
		// Check that un-dot-stuffing recovers the original
		undone := undotStuff(result)
		if string(undone) != string(data) {
			t.Errorf("roundtrip failed:\n  input:    %q\n  stuffed:  %q\n  unstuffed: %q", data, result, undone)
		}
	})
}

// undotStuff reverses dot-stuffing for verification.
func undotStuff(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	var result []byte
	atLineStart := true
	i := 0
	for i < len(data) {
		if atLineStart && i < len(data) && data[i] == '.' {
			// Skip the extra dot (the stuffed one)
			i++
		}
		if i < len(data) {
			result = append(result, data[i])
			atLineStart = (data[i] == '\n')
			i++
		}
	}
	return result
}

func FuzzExtractMessageID(f *testing.F) {
	f.Add("queued as ABC123")
	f.Add("250 Ok: queued as DEF456")
	f.Add("Message accepted <123@server.com>")
	f.Add("id=XYZ789 accepted")
	f.Add("")
	f.Add("No id here")
	f.Add("<incomplete")
	f.Add("   ")
	f.Add("<id@host> queued as X id=Y")

	f.Fuzz(func(t *testing.T, msg string) {
		result := extractMessageID(msg)
		// Should not panic and result should be a substring of the message (or empty)
		if result != "" && !strings.Contains(msg, result) {
			t.Errorf("extractMessageID returned %q which is not in %q", result, msg)
		}
	})
}

func FuzzParseEnhancedCode(f *testing.F) {
	f.Add("2.0.0 Ok")
	f.Add("5.1.1 User unknown")
	f.Add("Ok")
	f.Add("")
	f.Add("abc")
	f.Add("2.0 short")
	f.Add("notanum.0.0 test")
	f.Add("12.34.56 large")

	f.Fuzz(func(t *testing.T, msg string) {
		result := parseEnhancedCode(msg)
		if result != "" {
			// Verify format X.Y.Z where each is a number
			parts := strings.Split(result, ".")
			if len(parts) != 3 {
				t.Errorf("parseEnhancedCode(%q) = %q: not X.Y.Z format", msg, result)
			}
			for _, p := range parts {
				if _, err := fmt.Sscanf(p, "%d", new(int)); err != nil {
					t.Errorf("parseEnhancedCode(%q) = %q: non-numeric part %q", msg, result, p)
				}
			}
		}
	})
}

func FuzzBase64Encode(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("f"))
	f.Add([]byte("fo"))
	f.Add([]byte("foo"))
	f.Add([]byte("foobar"))
	f.Add([]byte("\x00\x01\x02\x03"))
	f.Add([]byte("Hello, World!"))

	f.Fuzz(func(t *testing.T, data []byte) {
		result := base64Encode(data)

		// Basic invariants
		if len(data) == 0 {
			if result != "" {
				t.Errorf("expected empty for empty input, got %q", result)
			}
			return
		}

		// Output length should be ceil(len(data)/3)*4
		expectedLen := ((len(data) + 2) / 3) * 4
		if len(result) != expectedLen {
			t.Errorf("base64Encode(len=%d): result length %d, expected %d", len(data), len(result), expectedLen)
		}

		// All characters should be valid base64
		const validChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
		for _, c := range result {
			if !strings.ContainsRune(validChars, c) {
				t.Errorf("invalid base64 character: %c", c)
			}
		}
	})
}

// --- Dial with LocalAddr ---

func TestClient_Dial_WithLocalAddr(t *testing.T) {
	h := &basicSMTPHandler{}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	config := DefaultClientConfig()
	config.LocalAddr = "127.0.0.1:0"

	c := NewClient(config)
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial with LocalAddr: %v", err)
	}
	defer c.Close()
}

func TestClient_Dial_InvalidLocalAddr(t *testing.T) {
	config := DefaultClientConfig()
	config.LocalAddr = "invalid"

	c := NewClient(config)
	err := c.Dial("127.0.0.1:25")
	if err == nil {
		t.Fatal("expected error for invalid local address")
	}
}

func TestClient_DialTLS_WithLocalAddr(t *testing.T) {
	config := DefaultClientConfig()
	config.LocalAddr = "invalid"

	c := NewClient(config)
	err := c.DialTLS("127.0.0.1:465")
	if err == nil {
		t.Fatal("expected error for invalid local address in DialTLS")
	}
}

// --- Dial with custom TLS config ---

func TestClient_DialTLS_WithCustomTLSConfig(t *testing.T) {
	c := NewClient(&ClientConfig{
		LocalName: "localhost",
		TLSConfig: &tls.Config{
			ServerName:         "custom.server.name",
			InsecureSkipVerify: true,
		},
		ConnectTimeout: 1 * time.Second,
	})
	c.closed = true
	err := c.DialTLS("127.0.0.1:465")
	if err != ErrClientClosed {
		t.Errorf("expected ErrClientClosed, got %v", err)
	}
}

// --- Send with timeouts ---

func TestClient_Send_WithTimeouts(t *testing.T) {
	h := &basicSMTPHandler{dataResponseMsg: "2.0.0 Ok: queued as TIMEOUT"}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	config := &ClientConfig{
		LocalName:          "localhost",
		ReadTimeout:        30 * time.Second,
		WriteTimeout:       30 * time.Second,
		ValidateBeforeSend: false,
	}

	c := NewClient(config)
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if err := c.Hello(); err != nil {
		t.Fatalf("Hello: %v", err)
	}

	mail := ravenmail.NewMailBuilder().
		From("sender@example.com").
		To("recipient@example.com").
		Subject("Timeout Test").
		TextBody("body").
		MustBuild()

	result, err := c.Send(mail)
	if err != nil {
		t.Fatalf("Send with timeouts: %v", err)
	}
	if !result.Success {
		t.Error("expected success")
	}
}

// --- Pool integration tests ---

func TestPool_SendAndReturn(t *testing.T) {
	h := &basicSMTPHandler{dataResponseMsg: "2.0.0 Ok: queued as POOL"}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	host, portStr, _ := net.SplitHostPort(srv.addr())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	d := NewDialer(host, port)
	p := NewPool(d, 2)
	defer p.Close()

	mail := ravenmail.NewMailBuilder().
		From("sender@example.com").
		To("recipient@example.com").
		Subject("Pool Test").
		TextBody("body").
		MustBuild()

	result, err := p.Send(mail)
	if err != nil {
		t.Fatalf("Pool.Send: %v", err)
	}
	if !result.Success {
		t.Error("expected success from pool send")
	}
}

func TestPool_GetAndPut(t *testing.T) {
	h := &basicSMTPHandler{}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	host, portStr, _ := net.SplitHostPort(srv.addr())
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	d := NewDialer(host, port)
	p := NewPool(d, 2)
	defer p.Close()

	// Get a connection
	client, err := p.Get()
	if err != nil {
		t.Fatalf("Pool.Get: %v", err)
	}

	// Put it back
	p.Put(client)

	// Get it again (should reuse)
	client2, err := p.Get()
	if err != nil {
		t.Fatalf("Pool.Get (reuse): %v", err)
	}
	defer client2.Close()
}

// --- Tests migrated from original client_test.go ---

func TestClientConfig_Defaults(t *testing.T) {
	config := DefaultClientConfig()

	if config.LocalName != "localhost" {
		t.Errorf("Expected LocalName 'localhost', got %q", config.LocalName)
	}

	if config.ConnectTimeout != 30*time.Second {
		t.Errorf("Expected ConnectTimeout 30s, got %v", config.ConnectTimeout)
	}
}

func TestNewDialer(t *testing.T) {
	dialer := NewDialer("smtp.example.com", 587)

	if dialer.Host != "smtp.example.com" {
		t.Errorf("Expected host 'smtp.example.com', got %q", dialer.Host)
	}

	if dialer.Port != 587 {
		t.Errorf("Expected port 587, got %d", dialer.Port)
	}

	if dialer.ConnectTimeout != 30*time.Second {
		t.Errorf("Expected 30s timeout, got %v", dialer.ConnectTimeout)
	}
}

func TestDialerWithLocalAddr(t *testing.T) {
	dialer := NewDialer("smtp.example.com", 587)
	dialer.LocalAddr = "192.168.1.100"

	if dialer.LocalAddr != "192.168.1.100" {
		t.Errorf("Expected LocalAddr '192.168.1.100', got %q", dialer.LocalAddr)
	}
}

func TestClientResponse_Status(t *testing.T) {
	tests := []struct {
		code           int
		isSuccess      bool
		isIntermediate bool
		isTransient    bool
		isPermanent    bool
	}{
		{220, true, false, false, false},
		{250, true, false, false, false},
		{354, false, true, false, false},
		{421, false, false, true, false},
		{450, false, false, true, false},
		{550, false, false, false, true},
		{554, false, false, false, true},
	}

	for _, tt := range tests {
		resp := &ClientResponse{Code: tt.code}

		if resp.IsSuccess() != tt.isSuccess {
			t.Errorf("Code %d: IsSuccess() = %v, want %v", tt.code, resp.IsSuccess(), tt.isSuccess)
		}
		if resp.IsIntermediate() != tt.isIntermediate {
			t.Errorf("Code %d: IsIntermediate() = %v, want %v", tt.code, resp.IsIntermediate(), tt.isIntermediate)
		}
		if resp.IsTransientError() != tt.isTransient {
			t.Errorf("Code %d: IsTransientError() = %v, want %v", tt.code, resp.IsTransientError(), tt.isTransient)
		}
		if resp.IsPermanentError() != tt.isPermanent {
			t.Errorf("Code %d: IsPermanentError() = %v, want %v", tt.code, resp.IsPermanentError(), tt.isPermanent)
		}
	}
}

func TestSMTPError(t *testing.T) {
	err := &SMTPError{
		Code:         550,
		EnhancedCode: "5.1.1",
		Message:      "Mailbox not found",
	}

	if !err.IsPermanent() {
		t.Error("Expected permanent error")
	}

	if err.IsTransient() {
		t.Error("Expected not transient")
	}

	errStr := err.Error()
	if errStr == "" {
		t.Error("Expected non-empty error string")
	}
}

func TestDotStuff(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Hello\r\n", "Hello\r\n"},
		{".hidden\r\n", "..hidden\r\n"},
		{"Hello\r\n.World\r\n", "Hello\r\n..World\r\n"},
		{"..already\r\n", "...already\r\n"},
		{"No dots here\r\n", "No dots here\r\n"},
		{".line1\r\n.line2\r\n", "..line1\r\n..line2\r\n"},
	}

	for _, tt := range tests {
		result := dotStuff([]byte(tt.input))
		if string(result) != tt.expected {
			t.Errorf("dotStuff(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestExtractMessageID(t *testing.T) {
	tests := []struct {
		msg      string
		expected string
	}{
		{"queued as ABC123", "ABC123"},
		{"250 Ok: queued as DEF456", "DEF456"},
		{"Message accepted <123@server.com>", "<123@server.com>"},
		{"id=XYZ789 accepted", "XYZ789"},
		{"", ""},
		{"No id here", ""},
	}

	for _, tt := range tests {
		result := extractMessageID(tt.msg)
		if result != tt.expected {
			t.Errorf("extractMessageID(%q) = %q, want %q", tt.msg, result, tt.expected)
		}
	}
}

func TestResolveLocalAddr(t *testing.T) {
	tests := []struct {
		input   string
		wantIP  string
		wantErr bool
	}{
		{"", "", false},
		{"192.168.1.100", "192.168.1.100", false},
		{"10.0.0.1:0", "10.0.0.1", false},
		{"192.168.1.100:25", "192.168.1.100", false},
		{":25", "", false},
		{"::1", "::1", false},
		{"[::1]:25", "::1", false},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		addr, err := resolveLocalAddr(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("resolveLocalAddr(%q): expected error, got nil", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("resolveLocalAddr(%q): unexpected error: %v", tt.input, err)
			continue
		}
		if tt.input == "" {
			if addr != nil {
				t.Errorf("resolveLocalAddr(%q): expected nil, got %v", tt.input, addr)
			}
			continue
		}
		if tt.wantIP != "" && addr.IP.String() != tt.wantIP {
			t.Errorf("resolveLocalAddr(%q): IP = %s, want %s", tt.input, addr.IP.String(), tt.wantIP)
		}
	}
}

func TestClient_SelectAuthMechanism_PrefersPLAIN(t *testing.T) {
	config := DefaultClientConfig()
	config.Auth = &ClientAuth{
		Username: "user",
		Password: "pass",
	}

	client := &Client{config: config}

	tests := []struct {
		name         string
		serverMechs  []string
		expectedMech string
	}{
		{
			name:         "PLAIN and LOGIN offered, PLAIN first",
			serverMechs:  []string{"PLAIN", "LOGIN"},
			expectedMech: "PLAIN",
		},
		{
			name:         "LOGIN and PLAIN offered, LOGIN first (but PLAIN preferred)",
			serverMechs:  []string{"LOGIN", "PLAIN"},
			expectedMech: "PLAIN",
		},
		{
			name:         "Only LOGIN offered",
			serverMechs:  []string{"LOGIN"},
			expectedMech: "LOGIN",
		},
		{
			name:         "Only PLAIN offered",
			serverMechs:  []string{"PLAIN"},
			expectedMech: "PLAIN",
		},
		{
			name:         "Neither supported",
			serverMechs:  []string{"XOAUTH2", "CRAM-MD5"},
			expectedMech: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			selected := client.selectAuthMechanism(tt.serverMechs)
			if selected != tt.expectedMech {
				t.Errorf("Expected %q, got %q", tt.expectedMech, selected)
			}
		})
	}
}

func TestClient_SelectAuthMechanism_RespectsClientPreference(t *testing.T) {
	config := DefaultClientConfig()
	config.Auth = &ClientAuth{
		Username:   "user",
		Password:   "pass",
		Mechanisms: []string{"LOGIN", "PLAIN"},
	}

	client := &Client{config: config}

	selected := client.selectAuthMechanism([]string{"PLAIN", "LOGIN"})
	if selected != "LOGIN" {
		t.Errorf("Expected LOGIN (client preference), got %q", selected)
	}
}
