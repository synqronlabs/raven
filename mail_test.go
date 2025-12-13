package raven

import (
	"testing"
	"time"
)

func TestMailBuilder_Basic(t *testing.T) {
	mail, err := NewMailBuilder().
		From("sender@example.com").
		To("recipient@example.com").
		Subject("Test Subject").
		TextBody("This is a test body").
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if mail.Envelope.From.Mailbox.LocalPart != "sender" {
		t.Errorf("Expected from local part 'sender', got %q", mail.Envelope.From.Mailbox.LocalPart)
	}

	if mail.Envelope.From.Mailbox.Domain != "example.com" {
		t.Errorf("Expected from domain 'example.com', got %q", mail.Envelope.From.Mailbox.Domain)
	}

	if len(mail.Envelope.To) != 1 {
		t.Errorf("Expected 1 recipient, got %d", len(mail.Envelope.To))
	}

	if mail.Content.Headers.Get("Subject") != "Test Subject" {
		t.Errorf("Expected subject 'Test Subject', got %q", mail.Content.Headers.Get("Subject"))
	}
}

func TestMailBuilder_MultipleRecipients(t *testing.T) {
	mail, err := NewMailBuilder().
		From("sender@example.com").
		To("rcpt1@example.com", "rcpt2@example.com").
		Cc("cc@example.com").
		Bcc("bcc@example.com").
		Subject("Multi-recipient").
		TextBody("Test").
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Should have 4 envelope recipients (To + Cc + Bcc)
	if len(mail.Envelope.To) != 4 {
		t.Errorf("Expected 4 envelope recipients, got %d", len(mail.Envelope.To))
	}

	// Cc should appear in headers, Bcc should not
	cc := mail.Content.Headers.Get("Cc")
	if cc == "" {
		t.Error("Expected Cc header to be set")
	}
}

func TestMailBuilder_DisplayName(t *testing.T) {
	mail, err := NewMailBuilder().
		From("Sender Name <sender@example.com>").
		To("Recipient Name <recipient@example.com>").
		Subject("Test").
		TextBody("Test").
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if mail.Envelope.From.Mailbox.DisplayName != "Sender Name" {
		t.Errorf("Expected display name 'Sender Name', got %q", mail.Envelope.From.Mailbox.DisplayName)
	}
}

func TestMailBuilder_NonASCII(t *testing.T) {
	mail, err := NewMailBuilder().
		From("sender@example.com").
		To("recipient@example.com").
		Subject("日本語の件名").
		TextBody("This has UTF-8: αβγ").
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Subject should be RFC 2047 encoded
	subject := mail.Content.Headers.Get("Subject")
	if subject == "" {
		t.Error("Expected subject header")
	}

	// Should require SMTPUTF8 or have 8BITMIME body type
	if mail.Envelope.BodyType != BodyType8BitMIME {
		t.Errorf("Expected 8BITMIME body type, got %q", mail.Envelope.BodyType)
	}
}

func TestMailBuilder_MissingFrom(t *testing.T) {
	_, err := NewMailBuilder().
		To("recipient@example.com").
		Subject("Test").
		TextBody("Test").
		Build()

	if err == nil {
		t.Error("Expected error for missing from address")
	}
}

func TestMailBuilder_MissingRecipient(t *testing.T) {
	_, err := NewMailBuilder().
		From("sender@example.com").
		Subject("Test").
		TextBody("Test").
		Build()

	if err == nil {
		t.Error("Expected error for missing recipients")
	}
}

func TestMailBuilder_DSN(t *testing.T) {
	mail, err := NewMailBuilder().
		From("sender@example.com").
		To("recipient@example.com").
		Subject("Test").
		TextBody("Test").
		DSN([]string{"SUCCESS", "FAILURE"}, "FULL").
		EnvID("tracking-123").
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if mail.Envelope.EnvID != "tracking-123" {
		t.Errorf("Expected EnvID 'tracking-123', got %q", mail.Envelope.EnvID)
	}

	if mail.Envelope.DSNParams == nil {
		t.Fatal("Expected DSNParams to be set")
	}

	if mail.Envelope.DSNParams.RET != "FULL" {
		t.Errorf("Expected RET 'FULL', got %q", mail.Envelope.DSNParams.RET)
	}
}

func TestMailBuilder_Headers(t *testing.T) {
	mail, err := NewMailBuilder().
		From("sender@example.com").
		To("recipient@example.com").
		Subject("Test").
		TextBody("Test").
		ReplyTo("reply@example.com").
		Header("X-Custom", "value").
		InReplyTo("abc123@example.com").
		References("ref1@example.com", "ref2@example.com").
		Priority(1).
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if mail.Content.Headers.Get("Reply-To") == "" {
		t.Error("Expected Reply-To header")
	}

	if mail.Content.Headers.Get("X-Custom") != "value" {
		t.Errorf("Expected X-Custom header to be 'value'")
	}

	if mail.Content.Headers.Get("In-Reply-To") != "<abc123@example.com>" {
		t.Errorf("Expected In-Reply-To header")
	}

	if mail.Content.Headers.Get("X-Priority") != "1" {
		t.Errorf("Expected X-Priority header to be '1'")
	}
}

func TestMailBuilder_DateAndMessageID(t *testing.T) {
	customDate := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)

	mail, err := NewMailBuilder().
		From("sender@example.com").
		To("recipient@example.com").
		Subject("Test").
		TextBody("Test").
		Date(customDate).
		MessageID("custom-id@example.com").
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Custom date should be set
	date := mail.Content.Headers.Get("Date")
	if date == "" {
		t.Error("Expected Date header")
	}

	// Custom message ID should be set
	msgID := mail.Content.Headers.Get("Message-ID")
	if msgID != "<custom-id@example.com>" {
		t.Errorf("Expected custom message ID, got %q", msgID)
	}
}

func TestClientConfig_Defaults(t *testing.T) {
	config := DefaultClientConfig()

	if config.LocalName != "localhost" {
		t.Errorf("Expected LocalName 'localhost', got %q", config.LocalName)
	}

	if config.ConnectTimeout != 30*time.Second {
		t.Errorf("Expected ConnectTimeout 30s, got %v", config.ConnectTimeout)
	}
}

func TestServerCapabilities_HasExtension(t *testing.T) {
	caps := &ServerCapabilities{
		Extensions: map[Extension]string{
			ExtSTARTTLS: "",
			ExtAuth:     "PLAIN LOGIN",
			ExtSize:     "10485760",
		},
	}

	if !caps.HasExtension(ExtSTARTTLS) {
		t.Error("Expected STARTTLS to be present")
	}

	if !caps.HasExtension(ExtAuth) {
		t.Error("Expected AUTH to be present")
	}

	if caps.HasExtension(ExtDSN) {
		t.Error("Expected DSN to not be present")
	}
}

func TestServerCapabilities_SupportsAuth(t *testing.T) {
	caps := &ServerCapabilities{
		Auth: []string{"PLAIN", "LOGIN"},
	}

	if !caps.SupportsAuth("PLAIN") {
		t.Error("Expected PLAIN auth to be supported")
	}

	if !caps.SupportsAuth("plain") {
		t.Error("Expected case-insensitive match")
	}

	if caps.SupportsAuth("XOAUTH2") {
		t.Error("Expected XOAUTH2 to not be supported")
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
		EnhancedCode: ESCBadDestMailbox.String(),
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

func TestResolveLocalAddr(t *testing.T) {
	tests := []struct {
		input   string
		wantIP  string
		wantErr bool
	}{
		{"", "", false}, // Empty returns nil
		{"192.168.1.100", "192.168.1.100", false},
		{"10.0.0.1:0", "10.0.0.1", false},
		{"192.168.1.100:25", "192.168.1.100", false},
		{":25", "", false},         // Any IP, specific port
		{"::1", "::1", false},      // IPv6 localhost
		{"[::1]:25", "::1", false}, // IPv6 with port
		{"invalid", "", true},      // Invalid IP
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

func TestDialerWithLocalAddr(t *testing.T) {
	dialer := NewDialer("smtp.example.com", 587)
	dialer.LocalAddr = "192.168.1.100"

	if dialer.LocalAddr != "192.168.1.100" {
		t.Errorf("Expected LocalAddr '192.168.1.100', got %q", dialer.LocalAddr)
	}
}

func TestMailBuilder_RequireTLS(t *testing.T) {
	mail, err := NewMailBuilder().
		From("sender@example.com").
		To("recipient@example.com").
		Subject("Test REQUIRETLS").
		TextBody("This message requires TLS").
		RequireTLS().
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if !mail.Envelope.RequireTLS {
		t.Error("Expected RequireTLS to be true")
	}
}

func TestMailBuilder_TLSOptional(t *testing.T) {
	mail, err := NewMailBuilder().
		From("sender@example.com").
		To("admin@example.com").
		Subject("Certificate problem").
		TextBody("Your TLS certificate is expired").
		TLSOptional().
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	tlsRequired := mail.Content.Headers.Get("TLS-Required")
	if tlsRequired != "No" {
		t.Errorf("Expected TLS-Required header to be 'No', got %q", tlsRequired)
	}
}

func TestExtRequireTLS_Constant(t *testing.T) {
	// Verify the extension constant value
	if ExtRequireTLS != "REQUIRETLS" {
		t.Errorf("Expected ExtRequireTLS to be 'REQUIRETLS', got %q", ExtRequireTLS)
	}
}

func TestClient_SelectAuthMechanism_PrefersPLAIN(t *testing.T) {
	// Test that the client prefers PLAIN over LOGIN by default
	config := DefaultClientConfig()
	config.Auth = &ClientAuth{
		Username: "user",
		Password: "pass",
	}

	client := &Client{config: config}

	// When server offers both PLAIN and LOGIN, PLAIN should be selected
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
	// Test that client-specified mechanism order is respected
	config := DefaultClientConfig()
	config.Auth = &ClientAuth{
		Username:   "user",
		Password:   "pass",
		Mechanisms: []string{"LOGIN", "PLAIN"}, // Client prefers LOGIN
	}

	client := &Client{config: config}

	// When client specifies LOGIN first, it should be selected even though
	// PLAIN is generally preferred
	selected := client.selectAuthMechanism([]string{"PLAIN", "LOGIN"})
	if selected != "LOGIN" {
		t.Errorf("Expected LOGIN (client preference), got %q", selected)
	}
}

// ===== RFC 5322 Compliance Tests =====

func TestRFC5322_HeaderFolding(t *testing.T) {
	// Test that long headers are properly folded per
	mail, err := NewMailBuilder().
		From("sender@example.com").
		To("recipient@example.com").
		Subject("This is a very long subject line that should be folded because it exceeds the recommended 78 character limit per RFC 5322").
		TextBody("Test body").
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	raw := mail.Content.ToRaw()

	// Check that no line exceeds 998 characters (RFC 5322 MUST)
	lines := splitLines(raw)
	for i, line := range lines {
		// Line length should not exceed MaxLineLength (998)
		if len(line) > MaxLineLength {
			t.Errorf("Line %d exceeds MaxLineLength (998): got %d characters", i, len(line))
		}
	}
}

func TestRFC5322_HeaderValidation_RequiredFields(t *testing.T) {
	// Test that required Date and From headers are validated
	headers := Headers{
		{Name: "Subject", Value: "Test"},
	}

	err := headers.Validate()
	if err != ErrMissingDateHeader {
		t.Errorf("Expected ErrMissingDateHeader, got %v", err)
	}

	headers = Headers{
		{Name: "Date", Value: "Thu, 12 Dec 2024 10:00:00 +0000"},
	}

	err = headers.Validate()
	if err != ErrMissingFromHeader {
		t.Errorf("Expected ErrMissingFromHeader, got %v", err)
	}

	headers = Headers{
		{Name: "Date", Value: "Thu, 12 Dec 2024 10:00:00 +0000"},
		{Name: "From", Value: "sender@example.com"},
	}

	err = headers.Validate()
	if err != nil {
		t.Errorf("Expected no error for valid headers, got %v", err)
	}
}

func TestRFC5322_HeaderValidation_DuplicateHeaders(t *testing.T) {
	// Test that duplicate single-occurrence headers are rejected
	headers := Headers{
		{Name: "Date", Value: "Thu, 12 Dec 2024 10:00:00 +0000"},
		{Name: "Date", Value: "Fri, 13 Dec 2024 10:00:00 +0000"}, // Duplicate!
		{Name: "From", Value: "sender@example.com"},
	}

	err := headers.Validate()
	if err != ErrDuplicateSingleHeader {
		t.Errorf("Expected ErrDuplicateSingleHeader, got %v", err)
	}
}

func TestRFC5322_HeaderValidation_MultipleFromNoSender(t *testing.T) {
	// Test that multiple From addresses require a Sender header
	headers := Headers{
		{Name: "Date", Value: "Thu, 12 Dec 2024 10:00:00 +0000"},
		{Name: "From", Value: "alice@example.com, bob@example.com"},
	}

	err := headers.Validate()
	if err != ErrMultipleFromNoSender {
		t.Errorf("Expected ErrMultipleFromNoSender, got %v", err)
	}

	// With Sender header, should be valid
	headers = Headers{
		{Name: "Date", Value: "Thu, 12 Dec 2024 10:00:00 +0000"},
		{Name: "From", Value: "alice@example.com, bob@example.com"},
		{Name: "Sender", Value: "alice@example.com"},
	}

	err = headers.Validate()
	if err != nil {
		t.Errorf("Expected no error with Sender header, got %v", err)
	}
}

func TestRFC5322_LineEndingNormalization(t *testing.T) {
	// Test that body line endings are normalized to CRLF
	mail, err := NewMailBuilder().
		From("sender@example.com").
		To("recipient@example.com").
		Subject("Test").
		TextBody("Line 1\nLine 2\r\nLine 3\rLine 4").
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	expected := "Line 1\r\nLine 2\r\nLine 3\r\nLine 4"
	if string(mail.Content.Body) != expected {
		t.Errorf("Body line endings not normalized.\nGot: %q\nWant: %q", string(mail.Content.Body), expected)
	}
}

func TestRFC5322_ContentValidation_LineTooLong(t *testing.T) {
	// Test that body lines exceeding 998 characters are rejected
	longLine := make([]byte, 1000)
	for i := range longLine {
		longLine[i] = 'a'
	}

	content := Content{
		Headers: Headers{
			{Name: "Date", Value: "Thu, 12 Dec 2024 10:00:00 +0000"},
			{Name: "From", Value: "sender@example.com"},
		},
		Body: append(longLine, '\r', '\n'),
	}

	err := content.Validate()
	if err != ErrLineTooLong {
		t.Errorf("Expected ErrLineTooLong, got %v", err)
	}
}

func TestRFC5322_Constants(t *testing.T) {
	// Test that RFC 5322 constants are correctly defined
	if MaxLineLength != 998 {
		t.Errorf("MaxLineLength should be 998, got %d", MaxLineLength)
	}

	if RecommendedLineLength != 78 {
		t.Errorf("RecommendedLineLength should be 78, got %d", RecommendedLineLength)
	}
}

func TestRFC5322_HeaderValidation_LineTooLong(t *testing.T) {
	// Test that header lines exceeding 998 characters are rejected
	longValue := make([]byte, 1000)
	for i := range longValue {
		longValue[i] = 'a'
	}

	headers := Headers{
		{Name: "Date", Value: "Thu, 12 Dec 2024 10:00:00 +0000"},
		{Name: "From", Value: "sender@example.com"},
		{Name: "Subject", Value: string(longValue)},
	}

	err := headers.Validate()
	if err != ErrLineTooLong {
		t.Errorf("Expected ErrLineTooLong for long header, got %v", err)
	}
}

func TestRFC5322_HeaderValidation_AtLimit(t *testing.T) {
	// Test that header lines exactly at 998 characters pass validation
	// Header line: "Subject: " (9 chars) + value = 998, so value = 989
	value := make([]byte, 989)
	for i := range value {
		value[i] = 'a'
	}

	headers := Headers{
		{Name: "Date", Value: "Thu, 12 Dec 2024 10:00:00 +0000"},
		{Name: "From", Value: "sender@example.com"},
		{Name: "Subject", Value: string(value)},
	}

	err := headers.Validate()
	if err != nil {
		t.Errorf("Expected no error for header at limit (998 chars), got %v", err)
	}
}

func TestRFC5322_HeaderValidation_FoldedLines(t *testing.T) {
	// Test that folded header lines are validated per-line
	// A header with a folded value where each line is under the limit should pass
	headers := Headers{
		{Name: "Date", Value: "Thu, 12 Dec 2024 10:00:00 +0000"},
		{Name: "From", Value: "sender@example.com"},
		{Name: "Subject", Value: "Short line\r\n continues here"},
	}

	err := headers.Validate()
	if err != nil {
		t.Errorf("Expected no error for folded header with short lines, got %v", err)
	}
}

func TestRFC5322_HeaderValidation_BareLF(t *testing.T) {
	// Test that bare LF (without CR) in header values is rejected
	headers := Headers{
		{Name: "Date", Value: "Thu, 12 Dec 2024 10:00:00 +0000"},
		{Name: "From", Value: "sender@example.com"},
		{Name: "Subject", Value: "Line one\n continues"}, // bare LF
	}

	err := headers.Validate()
	if err != ErrInvalidLineEnding {
		t.Errorf("Expected ErrInvalidLineEnding for bare LF in header, got %v", err)
	}
}

func TestRFC5322_ContentValidation_BareLF(t *testing.T) {
	// Test that bare LF in body is rejected
	content := Content{
		Headers: Headers{
			{Name: "Date", Value: "Thu, 12 Dec 2024 10:00:00 +0000"},
			{Name: "From", Value: "sender@example.com"},
		},
		Body: []byte("Line one\nLine two\r\n"), // bare LF after "Line one"
	}

	err := content.Validate()
	if err != ErrInvalidLineEnding {
		t.Errorf("Expected ErrInvalidLineEnding for bare LF in body, got %v", err)
	}
}

func TestRFC5322_ContentValidation_ValidCRLF(t *testing.T) {
	// Test that proper CRLF line endings pass validation
	content := Content{
		Headers: Headers{
			{Name: "Date", Value: "Thu, 12 Dec 2024 10:00:00 +0000"},
			{Name: "From", Value: "sender@example.com"},
		},
		Body: []byte("Line one\r\nLine two\r\n"),
	}

	err := content.Validate()
	if err != nil {
		t.Errorf("Expected no error for valid CRLF line endings, got %v", err)
	}
}

func TestMailBuilder_SenderHeader(t *testing.T) {
	// Test that Sender header can be explicitly set
	mail, err := NewMailBuilder().
		From("author@example.com").
		Sender("secretary@example.com").
		To("recipient@example.com").
		Subject("Test").
		TextBody("Test").
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	sender := mail.Content.Headers.Get("Sender")
	if sender != "secretary@example.com" {
		t.Errorf("Expected Sender header to be 'secretary@example.com', got %q", sender)
	}
}

// Helper function to split raw message into lines
func splitLines(data []byte) []string {
	var lines []string
	start := 0
	for i := range data {
		if data[i] == '\n' {
			// Include line without LF, but check for CR before LF
			end := i
			if end > start && data[end-1] == '\r' {
				end--
			}
			lines = append(lines, string(data[start:end]))
			start = i + 1
		}
	}
	// Don't forget the last line if there's no trailing newline
	if start < len(data) {
		lines = append(lines, string(data[start:]))
	}
	return lines
}

func TestFoldHeader_NoFoldingNeeded(t *testing.T) {
	// Short header that doesn't need folding
	result := foldHeader("Subject", "Hello")
	expected := "Subject: Hello\r\n"
	if string(result) != expected {
		t.Errorf("Expected %q, got %q", expected, string(result))
	}
}

func TestFoldHeader_ExactlyAtLimit(t *testing.T) {
	// Header that's exactly at the recommended length (78 chars)
	// "Subject: " = 9 chars, so value should be 69 chars to total 78
	value := "This is exactly at the seventy-eight character limit, yes it is!!!!!!"
	totalLen := len("Subject: ") + len(value)
	if totalLen != 78 {
		t.Fatalf("Test setup error: total length is %d, expected 78", totalLen)
	}
	result := foldHeader("Subject", value)
	// Should not be folded
	if string(result) != "Subject: "+value+"\r\n" {
		t.Errorf("Header at exact limit should not be folded")
	}
}

func TestFoldHeader_SingleFold(t *testing.T) {
	// Header that needs one fold
	value := "This is a longer subject line that will definitely need to be folded at whitespace"
	result := foldHeader("Subject", value)

	lines := splitLines(result)
	if len(lines) < 2 {
		t.Errorf("Expected at least 2 lines after folding, got %d", len(lines))
	}

	// Each line should be under the recommended length
	for i, line := range lines {
		if len(line) > RecommendedLineLength {
			t.Errorf("Line %d exceeds recommended length: %d chars", i, len(line))
		}
	}

	// Continuation lines should start with whitespace
	for i := 1; i < len(lines); i++ {
		if len(lines[i]) > 0 && lines[i][0] != ' ' && lines[i][0] != '\t' {
			t.Errorf("Continuation line %d should start with whitespace", i)
		}
	}
}

func TestFoldHeader_ConsecutiveWhitespace(t *testing.T) {
	// Header with consecutive spaces - these should be collapsed at fold point
	value := "word1 word2  word3   word4    word5 word6 word7 word8 word9 word10 word11 word12 word13"
	result := foldHeader("Subject", value)

	lines := splitLines(result)

	// Check that no line starts with multiple spaces (after the fold)
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if len(line) >= 2 && line[0] == ' ' && line[1] == ' ' {
			t.Errorf("Line %d starts with multiple spaces: %q", i, line[:min(20, len(line))])
		}
	}

	// Verify no line exceeds recommended length
	for i, line := range lines {
		if len(line) > RecommendedLineLength {
			t.Errorf("Line %d exceeds recommended length (%d): %d chars", i, RecommendedLineLength, len(line))
		}
	}
}

func TestFoldHeader_TabCharacters(t *testing.T) {
	// Header with tab characters
	value := "word1\tword2\tword3 word4 word5 word6 word7 word8 word9 word10 word11 word12"
	result := foldHeader("Subject", value)

	lines := splitLines(result)

	// Should fold properly
	if len(lines) < 2 {
		t.Errorf("Expected folding, got %d lines", len(lines))
	}

	// No line should exceed limit
	for i, line := range lines {
		if len(line) > RecommendedLineLength {
			t.Errorf("Line %d exceeds recommended length: %d chars", i, len(line))
		}
	}
}

func TestFoldHeader_NoWhitespace(t *testing.T) {
	// Very long header with no whitespace - must force break at max length
	value := "ThisIsAVeryLongWordWithNoWhitespaceAtAllAndItJustKeepsGoingAndGoingAndGoingUntilItExceedsTheMaximumLineLengthOf998CharactersWhichIsTheAbsoluteLimitPerRFC5322"
	result := foldHeader("X-Long", value)

	lines := splitLines(result)

	// No line should exceed MaxLineLength
	for i, line := range lines {
		if len(line) > MaxLineLength {
			t.Errorf("Line %d exceeds max length (998): %d chars", i, len(line))
		}
	}
}

func TestFoldHeader_MultipleFolds(t *testing.T) {
	// Very long header that needs multiple folds
	value := "This is a very long header value that will need multiple folds because it contains many words separated by spaces and it just keeps going and going until we have tested multiple fold points thoroughly"
	result := foldHeader("X-Description", value)

	lines := splitLines(result)

	// Should have multiple lines
	if len(lines) < 3 {
		t.Errorf("Expected at least 3 lines for this long header, got %d", len(lines))
	}

	// Verify structure
	for i, line := range lines {
		if len(line) > RecommendedLineLength {
			t.Errorf("Line %d exceeds recommended length: %d chars", i, len(line))
		}
		if i > 0 && len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			t.Errorf("Continuation line %d must start with whitespace", i)
		}
	}
}

func TestFoldHeader_PreservesContent(t *testing.T) {
	// Verify that unfolding the result gives back the original content
	value := "This is a test value with multiple words that should be folded and then unfolded correctly"
	result := foldHeader("Subject", value)

	// Unfold: remove CRLF followed by whitespace, then trim final CRLF
	unfolded := string(result)
	// Remove the header name prefix
	unfolded = unfolded[len("Subject: "):]
	// Remove trailing CRLF
	unfolded = unfolded[:len(unfolded)-2]
	// Unfold by replacing CRLF+space with single space
	for {
		newUnfolded := ""
		i := 0
		for i < len(unfolded) {
			if i+2 < len(unfolded) && unfolded[i] == '\r' && unfolded[i+1] == '\n' && (unfolded[i+2] == ' ' || unfolded[i+2] == '\t') {
				newUnfolded += " "
				i += 3
			} else {
				newUnfolded += string(unfolded[i])
				i++
			}
		}
		if newUnfolded == unfolded {
			break
		}
		unfolded = newUnfolded
	}

	// The unfolded value should match original (possibly with whitespace normalization)
	// Since we collapse consecutive spaces at fold points, compare normalized versions
	normalizeSpaces := func(s string) string {
		result := ""
		prevSpace := false
		for _, c := range s {
			if c == ' ' || c == '\t' {
				if !prevSpace {
					result += " "
					prevSpace = true
				}
			} else {
				result += string(c)
				prevSpace = false
			}
		}
		return result
	}

	if normalizeSpaces(unfolded) != normalizeSpaces(value) {
		t.Errorf("Content not preserved after fold/unfold.\nOriginal: %q\nUnfolded: %q", value, unfolded)
	}
}

func TestFoldHeader_EmptyValue(t *testing.T) {
	result := foldHeader("X-Empty", "")
	expected := "X-Empty: \r\n"
	if string(result) != expected {
		t.Errorf("Expected %q, got %q", expected, string(result))
	}
}

func TestFoldHeader_WhitespaceOnlyValue(t *testing.T) {
	result := foldHeader("X-Spaces", "   ")
	// Should produce valid output
	if len(result) == 0 {
		t.Error("Expected non-empty result")
	}
	// Should end with CRLF
	if len(result) < 2 || result[len(result)-2] != '\r' || result[len(result)-1] != '\n' {
		t.Error("Result should end with CRLF")
	}
}

func TestMailMessagePack(t *testing.T) {
	// Create a test mail with various fields populated
	mail, err := NewMailBuilder().
		From("sender@example.com").
		To("recipient@example.com").
		Subject("MessagePack Test").
		TextBody("Testing MessagePack serialization").
		Build()

	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Add some trace information
	mail.Trace = append(mail.Trace, TraceField{
		Type:       "Received",
		FromDomain: "sender.example.com",
		FromIP:     "192.168.1.1",
		ByDomain:   "receiver.example.com",
		With:       "ESMTP",
		Timestamp:  time.Now(),
	})

	// Serialize to MessagePack
	data, err := mail.ToMessagePack()
	if err != nil {
		t.Fatalf("ToMessagePack failed: %v", err)
	}

	// Verify we got some data
	if len(data) == 0 {
		t.Fatal("ToMessagePack returned empty data")
	}

	// Deserialize from MessagePack
	decoded, err := FromMessagePack(data)
	if err != nil {
		t.Fatalf("FromMessagePack failed: %v", err)
	}

	// Verify the decoded mail matches the original
	if decoded.Envelope.From.Mailbox.String() != mail.Envelope.From.Mailbox.String() {
		t.Errorf("Expected from %q, got %q",
			mail.Envelope.From.Mailbox.String(),
			decoded.Envelope.From.Mailbox.String())
	}

	if len(decoded.Envelope.To) != len(mail.Envelope.To) {
		t.Errorf("Expected %d recipients, got %d",
			len(mail.Envelope.To), len(decoded.Envelope.To))
	}

	if decoded.Content.Headers.Get("Subject") != mail.Content.Headers.Get("Subject") {
		t.Errorf("Expected subject %q, got %q",
			mail.Content.Headers.Get("Subject"),
			decoded.Content.Headers.Get("Subject"))
	}

	if string(decoded.Content.Body) != string(mail.Content.Body) {
		t.Errorf("Expected body %q, got %q",
			string(mail.Content.Body),
			string(decoded.Content.Body))
	}

	if len(decoded.Trace) != len(mail.Trace) {
		t.Errorf("Expected %d trace fields, got %d",
			len(mail.Trace), len(decoded.Trace))
	}

	// Test that MessagePack is more compact than JSON for this case
	jsonData, err := mail.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	t.Logf("MessagePack size: %d bytes, JSON size: %d bytes, ratio: %.2f%%",
		len(data), len(jsonData), float64(len(data))/float64(len(jsonData))*100)
}
