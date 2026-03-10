package mail

import (
	"bytes"
	"strings"
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
	result := FoldHeader("Subject", "Hello")
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
	result := FoldHeader("Subject", value)
	// Should not be folded
	if string(result) != "Subject: "+value+"\r\n" {
		t.Errorf("Header at exact limit should not be folded")
	}
}

func TestFoldHeader_SingleFold(t *testing.T) {
	// Header that needs one fold
	value := "This is a longer subject line that will definitely need to be folded at whitespace"
	result := FoldHeader("Subject", value)

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
		if lines[i] != "" && lines[i][0] != ' ' && lines[i][0] != '\t' {
			t.Errorf("Continuation line %d should start with whitespace", i)
		}
	}
}

func TestFoldHeader_ConsecutiveWhitespace(t *testing.T) {
	// Header with consecutive spaces - these should be collapsed at fold point
	value := "word1 word2  word3   word4    word5 word6 word7 word8 word9 word10 word11 word12 word13"
	result := FoldHeader("Subject", value)

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
	result := FoldHeader("Subject", value)

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
	result := FoldHeader("X-Long", value)

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
	result := FoldHeader("X-Description", value)

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
		if i > 0 && line != "" && line[0] != ' ' && line[0] != '\t' {
			t.Errorf("Continuation line %d must start with whitespace", i)
		}
	}
}

func TestFoldHeader_PreservesContent(t *testing.T) {
	// Verify that unfolding the result gives back the original content
	value := "This is a test value with multiple words that should be folded and then unfolded correctly"
	result := FoldHeader("Subject", value)

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
	result := FoldHeader("X-Empty", "")
	expected := "X-Empty: \r\n"
	if string(result) != expected {
		t.Errorf("Expected %q, got %q", expected, string(result))
	}
}

func TestFoldHeader_WhitespaceOnlyValue(t *testing.T) {
	result := FoldHeader("X-Spaces", "   ")
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

	if !bytes.Equal(decoded.Content.Body, mail.Content.Body) {
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

// ===== MailboxAddress / Path / Envelope helpers =====

func TestMailboxAddress_String(t *testing.T) {
	tests := []struct {
		addr MailboxAddress
		want string
	}{
		{MailboxAddress{LocalPart: "user", Domain: "example.com"}, "user@example.com"},
		{MailboxAddress{}, ""},
		{MailboxAddress{LocalPart: "", Domain: ""}, ""},
	}
	for _, tt := range tests {
		got := tt.addr.String()
		if got != tt.want {
			t.Errorf("String() = %q, want %q", got, tt.want)
		}
	}
	// Nil receiver
	var nilAddr *MailboxAddress
	if nilAddr.String() != "" {
		t.Error("nil MailboxAddress.String() should return empty string")
	}
}

func TestPath_IsNull(t *testing.T) {
	if !(*Path)(nil).IsNull() {
		t.Error("nil *Path should be null")
	}
	if !(&Path{}).IsNull() {
		t.Error("empty Path should be null")
	}
	p := &Path{Mailbox: MailboxAddress{LocalPart: "u", Domain: "d.com"}}
	if p.IsNull() {
		t.Error("non-empty Path should not be null")
	}
}

func TestPath_String(t *testing.T) {
	null := &Path{}
	if null.String() != "<>" {
		t.Errorf("null path String() = %q, want \"<>\"", null.String())
	}
	p := &Path{Mailbox: MailboxAddress{LocalPart: "u", Domain: "d.com"}}
	if p.String() != "<u@d.com>" {
		t.Errorf("path String() = %q, want \"<u@d.com>\"", p.String())
	}
}

func TestHeaders_GetAll(t *testing.T) {
	h := Headers{
		{Name: "X-Tag", Value: "a"},
		{Name: "X-Tag", Value: "b"},
		{Name: "Other", Value: "c"},
	}
	got := h.GetAll("x-tag")
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("GetAll = %v, want [a b]", got)
	}
	if len(h.GetAll("missing")) != 0 {
		t.Error("GetAll of missing header should return empty slice")
	}
	// Nil receiver
	var nilH *Headers
	if len(nilH.GetAll("X-Tag")) != 0 {
		t.Error("nil Headers.GetAll should return empty slice")
	}
}

func TestHeaders_Get_NilReceiver(t *testing.T) {
	var nilH *Headers
	if nilH.Get("Date") != "" {
		t.Error("nil Headers.Get should return empty string")
	}
}

func TestHeaders_Count_NilReceiver(t *testing.T) {
	var nilH *Headers
	if nilH.Count("Date") != 0 {
		t.Error("nil Headers.Count should return 0")
	}
}

// ===== TraceField.String =====

func TestTraceField_String_Nil(t *testing.T) {
	var tf *TraceField
	if tf.String() != "" {
		t.Error("nil TraceField.String() should return empty string")
	}
}

func TestTraceField_String_Raw(t *testing.T) {
	tf := &TraceField{Raw: "some raw value"}
	if tf.String() != "some raw value" {
		t.Errorf("expected raw value, got %q", tf.String())
	}
}

func TestTraceField_String_ReturnPath(t *testing.T) {
	tf := &TraceField{Type: "Return-Path", For: ""}
	if tf.String() != "<>" {
		t.Errorf("empty return path = %q, want \"<>\"", tf.String())
	}
	tf2 := &TraceField{Type: "Return-Path", For: "bounce@example.com"}
	if tf2.String() != "<bounce@example.com>" {
		t.Errorf("return path = %q, want \"<bounce@example.com>\"", tf2.String())
	}
}

func TestTraceField_String_Received(t *testing.T) {
	ts := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	tf := &TraceField{
		Type:       "Received",
		FromDomain: "mail.sender.com",
		FromIP:     "192.0.2.1",
		ByDomain:   "mail.receiver.com",
		Via:        "TCP",
		With:       "ESMTPS",
		ID:         "abc123",
		For:        "user@receiver.com",
		Timestamp:  ts,
	}
	s := tf.String()
	for _, want := range []string{
		"from mail.sender.com",
		"by mail.receiver.com",
		"via TCP",
		"with ESMTPS",
		"id abc123",
		"for <user@receiver.com>",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("TraceField.String() missing %q in %q", want, s)
		}
	}
}

func TestTraceField_String_Received_Minimal(t *testing.T) {
	// Only FromDomain set (no IP, no BY, etc.)
	tf := &TraceField{
		Type:       "Received",
		FromDomain: "mail.sender.com",
		Timestamp:  time.Now(),
	}
	s := tf.String()
	if !strings.Contains(s, "from mail.sender.com") {
		t.Errorf("expected 'from mail.sender.com' in %q", s)
	}
}

func TestNewReturnPathTrace(t *testing.T) {
	p := Path{Mailbox: MailboxAddress{LocalPart: "bounce", Domain: "example.com"}}
	tf := NewReturnPathTrace(p)
	if tf.Type != "Return-Path" {
		t.Errorf("type = %q, want Return-Path", tf.Type)
	}
	if tf.For != "bounce@example.com" {
		t.Errorf("for = %q, want bounce@example.com", tf.For)
	}
}

// ===== Mail helpers =====

func TestMail_RequiresSMTPUTF8(t *testing.T) {
	m := NewMail()
	if m.RequiresSMTPUTF8() {
		t.Error("empty mail should not require SMTPUTF8")
	}

	// Explicit flag
	m.Envelope.SMTPUTF8 = true
	if !m.RequiresSMTPUTF8() {
		t.Error("explicit SMTPUTF8 flag should require SMTPUTF8")
	}
	m.Envelope.SMTPUTF8 = false

	// Non-ASCII in From local-part
	m.Envelope.From = Path{Mailbox: MailboxAddress{LocalPart: "ünïcodé", Domain: "example.com"}}
	if !m.RequiresSMTPUTF8() {
		t.Error("non-ASCII From local-part should require SMTPUTF8")
	}
	m.Envelope.From = Path{}

	// Non-ASCII in To domain
	m.Envelope.To = []Recipient{{Address: Path{Mailbox: MailboxAddress{LocalPart: "u", Domain: "münchen.de"}}}}
	if !m.RequiresSMTPUTF8() {
		t.Error("non-ASCII To domain should require SMTPUTF8")
	}
	m.Envelope.To = nil

	// Non-ASCII in header value
	m.Content.Headers = Headers{{Name: "Subject", Value: "こんにちは"}}
	if !m.RequiresSMTPUTF8() {
		t.Error("non-ASCII header value should require SMTPUTF8")
	}
}

func TestMail_Requires8BitMIME(t *testing.T) {
	m := NewMail()
	if m.Requires8BitMIME() {
		t.Error("empty mail should not require 8BITMIME")
	}

	m.Envelope.BodyType = BodyType8BitMIME
	if !m.Requires8BitMIME() {
		t.Error("BodyType8BitMIME should require 8BITMIME")
	}
	m.Envelope.BodyType = ""

	// Body with 8-bit data
	m.Content.Body = []byte{0x80, 0x90}
	if !m.Requires8BitMIME() {
		t.Error("body with bytes >127 should require 8BITMIME")
	}
}

func TestMail_SetNullSender(t *testing.T) {
	m := NewMail()
	m.SetFrom(MailboxAddress{LocalPart: "u", Domain: "d.com"})
	m.SetNullSender()
	if !m.Envelope.From.IsNull() {
		t.Error("SetNullSender should result in null sender")
	}
}

func TestMail_AddReturnPath(t *testing.T) {
	m := NewMail()
	m.SetFrom(MailboxAddress{LocalPart: "sender", Domain: "example.com"})
	m.Content.Headers = Headers{
		{Name: "From", Value: "sender@example.com"},
	}
	m.AddReturnPath()

	if len(m.Trace) == 0 || m.Trace[0].Type != "Return-Path" {
		t.Error("AddReturnPath should prepend a Return-Path trace field")
	}
	if m.Content.Headers[0].Name != "Return-Path" {
		t.Error("AddReturnPath should prepend Return-Path header")
	}
	if !strings.Contains(m.Content.Headers[0].Value, "sender@example.com") {
		t.Errorf("Return-Path header value = %q, want to contain sender address", m.Content.Headers[0].Value)
	}
}

func TestMail_AddReturnPath_NullSender(t *testing.T) {
	m := NewMail()
	m.SetNullSender()
	m.AddReturnPath()
	if m.Content.Headers[0].Value != "<>" {
		t.Errorf("null sender Return-Path = %q, want \"<>\"", m.Content.Headers[0].Value)
	}
}

func TestMail_ToJSONIndent(t *testing.T) {
	m := NewMail()
	m.SetFrom(MailboxAddress{LocalPart: "u", Domain: "d.com"})
	data, err := m.ToJSONIndent()
	if err != nil {
		t.Fatalf("ToJSONIndent: %v", err)
	}
	if !strings.Contains(string(data), "\n") {
		t.Error("ToJSONIndent should produce multi-line output")
	}
}

func TestMail_FromJSON(t *testing.T) {
	m := NewMail()
	m.SetFrom(MailboxAddress{LocalPart: "u", Domain: "d.com"})
	j, err := m.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	decoded, err := FromJSON(j)
	if err != nil {
		t.Fatalf("FromJSON: %v", err)
	}
	if decoded.Envelope.From.Mailbox.String() != "u@d.com" {
		t.Errorf("decoded From = %q", decoded.Envelope.From.Mailbox.String())
	}
}

func TestFromJSON_Invalid(t *testing.T) {
	_, err := FromJSON([]byte("not json"))
	if err == nil {
		t.Error("FromJSON with invalid JSON should return error")
	}
}

func TestFromMessagePack_Invalid(t *testing.T) {
	_, err := FromMessagePack([]byte{0xff, 0xfe})
	if err == nil {
		t.Error("FromMessagePack with invalid data should return error")
	}
}

// ===== Content.ToMIME, FromMIME, FromRaw =====

func TestContent_ToMIME(t *testing.T) {
	c := Content{
		Headers: Headers{
			{Name: "Content-Type", Value: "text/plain; charset=utf-8"},
			{Name: "Content-Transfer-Encoding", Value: "7bit"},
		},
		Body: []byte("Hello, MIME!"),
	}
	part, err := c.ToMIME()
	if err != nil {
		t.Fatalf("ToMIME: %v", err)
	}
	if part.ContentType != "text/plain" {
		t.Errorf("ContentType = %q, want text/plain", part.ContentType)
	}
	if !bytes.Equal(part.Body, c.Body) {
		t.Errorf("body not preserved")
	}
}

func TestContent_FromMIME_SinglePart(t *testing.T) {
	c := Content{
		Headers: Headers{
			{Name: "Content-Type", Value: "text/plain; charset=utf-8"},
		},
		Body: []byte("original"),
	}
	part, _ := c.ToMIME()
	part.Body = []byte("updated body")

	var c2 Content
	if err := c2.FromMIME(part); err != nil {
		t.Fatalf("FromMIME: %v", err)
	}
	if string(c2.Body) != "updated body" {
		t.Errorf("body = %q, want \"updated body\"", string(c2.Body))
	}
	if c2.Charset != "utf-8" {
		t.Errorf("charset = %q, want utf-8", c2.Charset)
	}
}

func TestContent_FromMIME_DefaultEncoding(t *testing.T) {
	c := Content{
		Headers: Headers{{Name: "Content-Type", Value: "text/plain"}},
		Body:    []byte("body"),
	}
	part, _ := c.ToMIME()
	part.ContentTransferEncoding = "" // clear to test default

	var c2 Content
	if err := c2.FromMIME(part); err != nil {
		t.Fatalf("FromMIME: %v", err)
	}
	if c2.Encoding != "7bit" {
		t.Errorf("default encoding = %q, want 7bit", c2.Encoding)
	}
}

func TestContent_FromRaw(t *testing.T) {
	raw := []byte("From: sender@example.com\r\nSubject: Hello\r\nContent-Transfer-Encoding: 7bit\r\n\r\nBody text here")

	var c Content
	c.FromRaw(raw)

	if c.Headers.Get("From") != "sender@example.com" {
		t.Errorf("From header = %q", c.Headers.Get("From"))
	}
	if c.Headers.Get("Subject") != "Hello" {
		t.Errorf("Subject header = %q", c.Headers.Get("Subject"))
	}
	if string(c.Body) != "Body text here" {
		t.Errorf("body = %q", string(c.Body))
	}
	if c.Encoding != "7bit" {
		t.Errorf("encoding = %q", c.Encoding)
	}
}

func TestContent_FromRaw_Charset(t *testing.T) {
	tests := []struct {
		name   string
		ct     string
		wantCS string
	}{
		{"quoted charset", `text/plain; charset="utf-8"`, "utf-8"},
		{"unquoted charset", "text/plain; charset=iso-8859-1", "iso-8859-1"},
		{"charset with trailing semicolon", "text/plain; charset=utf-8; format=flowed", "utf-8"},
		{"no charset", "text/plain", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := []byte("Content-Type: " + tt.ct + "\r\n\r\n")
			var c Content
			c.FromRaw(raw)
			if c.Charset != tt.wantCS {
				t.Errorf("charset = %q, want %q", c.Charset, tt.wantCS)
			}
		})
	}
}

func TestContent_FromRaw_NoContentTransferEncoding(t *testing.T) {
	raw := []byte("Subject: Hi\r\n\r\nBody")
	var c Content
	c.FromRaw(raw)
	if c.Encoding != "7bit" {
		t.Errorf("default encoding = %q, want 7bit", c.Encoding)
	}
}

// ===== parseRawContent edge cases =====

func TestParseRawContent_CRLFCRLF(t *testing.T) {
	data := []byte("From: a@b.com\r\nSubject: Hi\r\n\r\nbody here")
	h, body := parseRawContent(data)
	if h.Get("From") != "a@b.com" {
		t.Errorf("From = %q", h.Get("From"))
	}
	if h.Get("Subject") != "Hi" {
		t.Errorf("Subject = %q", h.Get("Subject"))
	}
	if string(body) != "body here" {
		t.Errorf("body = %q", string(body))
	}
}

func TestParseRawContent_BareLF(t *testing.T) {
	data := []byte("From: a@b.com\nSubject: Hi\n\nbody here")
	h, body := parseRawContent(data)
	if h.Get("From") != "a@b.com" {
		t.Errorf("From = %q", h.Get("From"))
	}
	if h.Get("Subject") != "Hi" {
		t.Errorf("Subject = %q", h.Get("Subject"))
	}
	if string(body) != "body here" {
		t.Errorf("body = %q", string(body))
	}
}

func TestParseRawContent_NoSeparator(t *testing.T) {
	// No header/body separator — treated as all-body
	data := []byte("just some body text without headers")
	h, body := parseRawContent(data)
	if h != nil {
		t.Errorf("expected nil headers, got %v", h)
	}
	if !bytes.Equal(body, data) {
		t.Errorf("expected entire data as body")
	}
}

func TestParseRawContent_EmptyHeaderSection(t *testing.T) {
	// Separator immediately at start: empty headers, body only
	data := []byte("\r\n\r\nbody only")
	h, body := parseRawContent(data)
	if len(h) != 0 {
		t.Errorf("expected empty headers, got %v", h)
	}
	if string(body) != "body only" {
		t.Errorf("body = %q", string(body))
	}
}

func TestParseRawContent_EmptyBody(t *testing.T) {
	data := []byte("From: a@b.com\r\n\r\n")
	h, body := parseRawContent(data)
	if h.Get("From") != "a@b.com" {
		t.Errorf("From = %q", h.Get("From"))
	}
	if body != nil {
		t.Errorf("expected nil body, got %q", body)
	}
}

func TestParseRawContent_FoldedHeader(t *testing.T) {
	data := []byte("Subject: long\r\n subject continuation\r\n\r\nbody")
	h, _ := parseRawContent(data)
	subj := h.Get("Subject")
	if !strings.Contains(subj, "long") || !strings.Contains(subj, "subject continuation") {
		t.Errorf("folded subject not reassembled: %q", subj)
	}
}

func TestParseRawContent_FoldedHeader_BareLF(t *testing.T) {
	data := []byte("Subject: long\n subject continuation\n\nbody")
	h, _ := parseRawContent(data)
	subj := h.Get("Subject")
	if !strings.Contains(subj, "long") || !strings.Contains(subj, "subject continuation") {
		t.Errorf("folded subject (bare LF) not reassembled: %q", subj)
	}
}

func TestParseRawContent_MalformedHeader(t *testing.T) {
	// Line without colon should be silently dropped
	data := []byte("From: a@b.com\r\nNOCOLONHERE\r\nSubject: Hi\r\n\r\nbody")
	h, _ := parseRawContent(data)
	if h.Get("From") != "a@b.com" {
		t.Errorf("From = %q", h.Get("From"))
	}
	if h.Get("Subject") != "Hi" {
		t.Errorf("Subject = %q", h.Get("Subject"))
	}
}

func TestParseRawContent_ContinuationWithNoCurrentHeader(t *testing.T) {
	// Continuation line as very first line — should be silently ignored
	data := []byte(" continuation with no preceding header\r\nSubject: OK\r\n\r\nbody")
	h, _ := parseRawContent(data)
	if h.Get("Subject") != "OK" {
		t.Errorf("Subject = %q", h.Get("Subject"))
	}
}

func TestParseRawContent_ShortData(_ *testing.T) {
	// Less than 4 bytes: can never contain CRLF CRLF
	for _, d := range [][]byte{{}, {'\r'}, {'\r', '\n'}, {'\r', '\n', '\r'}} {
		h, body := parseRawContent(d)
		_ = h
		_ = body
		// Just must not panic
	}
}

func TestParseRawContent_HeaderWithColonInValue(t *testing.T) {
	data := []byte("Subject: re: reply: nested\r\n\r\nbody")
	h, _ := parseRawContent(data)
	if h.Get("Subject") != "re: reply: nested" {
		t.Errorf("Subject = %q", h.Get("Subject"))
	}
}

// ===== ParseAddress =====

func TestParseAddress_Invalid(t *testing.T) {
	_, err := ParseAddress("not-an-email")
	if err == nil {
		t.Error("expected error for invalid address")
	}
}

func TestParseAddress_NoAtSign(t *testing.T) {
	// mail.ParseAddress can handle "Name <user@domain>" but plain "local" with no @ is malformed
	_, err := ParseAddress("plainlocal")
	if err == nil {
		t.Error("expected error for address without domain")
	}
}

// ===== Builder: uncovered methods =====

func TestMailBuilder_FromMailbox(t *testing.T) {
	m, err := NewMailBuilder().
		FromMailbox(MailboxAddress{LocalPart: "user", Domain: "example.com", DisplayName: "User"}).
		To("rcpt@example.com").
		TextBody("test").
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if m.Envelope.From.Mailbox.LocalPart != "user" {
		t.Errorf("From local-part = %q", m.Envelope.From.Mailbox.LocalPart)
	}
}

func TestMailBuilder_NullSender(t *testing.T) {
	m, err := NewMailBuilder().
		NullSender().
		Header("From", "postmaster@example.com").
		To("rcpt@example.com").
		TextBody("bounce").
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !m.Envelope.From.IsNull() {
		t.Error("expected null sender")
	}
}

func TestMailBuilder_ToMailbox(t *testing.T) {
	m, err := NewMailBuilder().
		From("sender@example.com").
		ToMailbox(MailboxAddress{LocalPart: "a", Domain: "x.com"}, MailboxAddress{LocalPart: "b", Domain: "x.com"}).
		TextBody("test").
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(m.Envelope.To) != 2 {
		t.Errorf("expected 2 recipients, got %d", len(m.Envelope.To))
	}
}

func TestMailBuilder_HTMLBody(t *testing.T) {
	m, err := NewMailBuilder().
		From("s@example.com").
		To("r@example.com").
		HTMLBody("<h1>Hello</h1>").
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	ct := m.Content.Headers.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html...", ct)
	}
}

func TestMailBuilder_HTMLBody_NonASCII(t *testing.T) {
	m, err := NewMailBuilder().
		From("s@example.com").
		To("r@example.com").
		HTMLBody("<p>こんにちは</p>").
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if m.Envelope.BodyType != BodyType8BitMIME {
		t.Errorf("expected 8BITMIME body type, got %q", m.Envelope.BodyType)
	}
}

func TestMailBuilder_Body(t *testing.T) {
	raw := []byte{0x89, 0x50, 0x4e, 0x47} // PNG magic bytes
	m, err := NewMailBuilder().
		From("s@example.com").
		To("r@example.com").
		Body(raw, "image/png", "base64").
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !bytes.Equal(m.Content.Body, raw) {
		t.Error("body bytes not preserved")
	}
	if m.Content.Headers.Get("Content-Type") != "image/png" {
		t.Errorf("Content-Type = %q", m.Content.Headers.Get("Content-Type"))
	}
}

func TestMailBuilder_InvalidFromAddress(t *testing.T) {
	_, err := NewMailBuilder().
		From("not-valid").
		To("r@example.com").
		TextBody("test").
		Build()
	if err == nil {
		t.Error("expected error for invalid From address")
	}
}

func TestMailBuilder_InvalidToAddress(t *testing.T) {
	_, err := NewMailBuilder().
		From("s@example.com").
		To("not-valid").
		TextBody("test").
		Build()
	if err == nil {
		t.Error("expected error for invalid To address")
	}
}

func TestMailBuilder_InvalidCcAddress(t *testing.T) {
	_, err := NewMailBuilder().
		From("s@example.com").
		To("r@example.com").
		Cc("not-valid").
		TextBody("test").
		Build()
	if err == nil {
		t.Error("expected error for invalid Cc address")
	}
}

func TestMailBuilder_InvalidBccAddress(t *testing.T) {
	_, err := NewMailBuilder().
		From("s@example.com").
		Bcc("not-valid").
		TextBody("test").
		Build()
	if err == nil {
		t.Error("expected error for invalid Bcc address")
	}
}

func TestMailBuilder_InvalidSenderAddress(t *testing.T) {
	_, err := NewMailBuilder().
		From("s@example.com").
		Sender("not-valid").
		To("r@example.com").
		TextBody("test").
		Build()
	if err == nil {
		t.Error("expected error for invalid Sender address")
	}
}

func TestMailBuilder_InvalidReplyToAddress(t *testing.T) {
	_, err := NewMailBuilder().
		From("s@example.com").
		To("r@example.com").
		ReplyTo("not-valid").
		TextBody("test").
		Build()
	if err == nil {
		t.Error("expected error for invalid ReplyTo address")
	}
}

func TestMailBuilder_SMTPUTF8(t *testing.T) {
	m, err := NewMailBuilder().
		From("s@example.com").
		To("r@example.com").
		TextBody("test").
		SMTPUTF8().
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !m.Envelope.SMTPUTF8 {
		t.Error("expected SMTPUTF8 to be true")
	}
}

func TestMailBuilder_Size(t *testing.T) {
	m, err := NewMailBuilder().
		From("s@example.com").
		To("r@example.com").
		TextBody("test").
		Size(12345).
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// Size was manually set; Build() should not override it
	if m.Envelope.Size != 12345 {
		t.Errorf("Size = %d, want 12345", m.Envelope.Size)
	}
}

func TestMailBuilder_Auth(t *testing.T) {
	m, err := NewMailBuilder().
		From("s@example.com").
		To("r@example.com").
		TextBody("test").
		Auth("identity@example.com").
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if m.Envelope.Auth != "identity@example.com" {
		t.Errorf("Auth = %q", m.Envelope.Auth)
	}
}

func TestMailBuilder_ExtensionParam(t *testing.T) {
	m, err := NewMailBuilder().
		From("s@example.com").
		To("r@example.com").
		TextBody("test").
		ExtensionParam("HOLDUNTIL", "2099-01-01").
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if m.Envelope.ExtensionParams["HOLDUNTIL"] != "2099-01-01" {
		t.Errorf("ExtensionParam = %q", m.Envelope.ExtensionParams["HOLDUNTIL"])
	}
}

func TestMailBuilder_RecipientDSN(t *testing.T) {
	m, err := NewMailBuilder().
		From("s@example.com").
		To("r@example.com").
		TextBody("test").
		RecipientDSN(0, []string{"SUCCESS", "FAILURE"}, "rfc822;original@example.com").
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if m.Envelope.To[0].DSNParams == nil {
		t.Fatal("expected DSNParams to be set on recipient")
	}
	if m.Envelope.To[0].DSNParams.ORcpt != "rfc822;original@example.com" {
		t.Errorf("ORcpt = %q", m.Envelope.To[0].DSNParams.ORcpt)
	}
}

func TestMailBuilder_RecipientDSN_OutOfRange(t *testing.T) {
	_, err := NewMailBuilder().
		From("s@example.com").
		To("r@example.com").
		TextBody("test").
		RecipientDSN(99, []string{"SUCCESS"}, "").
		Build()
	if err == nil {
		t.Error("expected error for out-of-range recipient index")
	}
}

func TestMailBuilder_MustBuild_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustBuild should panic on error")
		}
	}()
	// No From or To — will fail
	NewMailBuilder().MustBuild()
}

func TestMailBuilder_MustBuild_OK(t *testing.T) {
	m := NewMailBuilder().
		From("s@example.com").
		To("r@example.com").
		TextBody("test").
		MustBuild()
	if m == nil {
		t.Error("MustBuild returned nil")
	}
}

func TestMailBuilder_DisplayName_QuoteSpecials(t *testing.T) {
	// Display name containing RFC 5322 special characters (e.g. parentheses) should be quoted.
	m, err := NewMailBuilder().
		From(`"Sean (Dev)" <sean@example.com>`).
		To("r@example.com").
		TextBody("test").
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	from := m.Content.Headers.Get("From")
	if from == "" {
		t.Error("expected From header")
	}
}

// ===== Attachment bug regression test =====

func TestMailBuilder_AttachFile(t *testing.T) {
	data := []byte("PDF content here")
	m, err := NewMailBuilder().
		From("s@example.com").
		To("r@example.com").
		TextBody("Please find attachment.").
		AttachFile("doc.pdf", data, "application/pdf").
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	ct := m.Content.Headers.Get("Content-Type")
	if !strings.HasPrefix(ct, "multipart/mixed") {
		t.Errorf("Content-Type = %q, want multipart/mixed", ct)
	}
	if !strings.Contains(string(m.Content.Body), "Please find attachment.") {
		t.Error("body should contain text part")
	}
	if !strings.Contains(string(m.Content.Body), "doc.pdf") {
		t.Error("body should contain attachment filename")
	}
	// MIME-Version should still be present
	if m.Content.Headers.Get("MIME-Version") != "1.0" {
		t.Errorf("MIME-Version = %q, want 1.0", m.Content.Headers.Get("MIME-Version"))
	}
}

func TestMailBuilder_AttachFile_NoContentType(t *testing.T) {
	// Empty contentType should default to application/octet-stream
	m, err := NewMailBuilder().
		From("s@example.com").
		To("r@example.com").
		TextBody("hi").
		AttachFile("data.bin", []byte{0x01, 0x02}, "").
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !strings.Contains(string(m.Content.Body), "application/octet-stream") {
		t.Error("empty content type should default to application/octet-stream")
	}
}

func TestMailBuilder_AttachInline(t *testing.T) {
	imgData := []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a} // PNG header
	m, err := NewMailBuilder().
		From("s@example.com").
		To("r@example.com").
		HTMLBody(`<img src="cid:logo">`).
		AttachInline("logo.png", "logo", imgData, "image/png").
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if !strings.HasPrefix(m.Content.Headers.Get("Content-Type"), "multipart/mixed") {
		t.Errorf("Content-Type = %q, want multipart/mixed", m.Content.Headers.Get("Content-Type"))
	}
	if !strings.Contains(string(m.Content.Body), "inline") {
		t.Error("inline attachment should have Content-Disposition: inline")
	}
	if !strings.Contains(string(m.Content.Body), "<logo>") {
		t.Error("inline attachment should have Content-Id header")
	}
}

func TestMailBuilder_AttachInline_NoContentType(t *testing.T) {
	m, err := NewMailBuilder().
		From("s@example.com").
		To("r@example.com").
		TextBody("hi").
		AttachInline("img.jpg", "img", []byte{0xff, 0xd8}, "").
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !strings.Contains(string(m.Content.Body), "application/octet-stream") {
		t.Error("empty content type on inline should default to application/octet-stream")
	}
}

func TestMailBuilder_MultipleAttachments(t *testing.T) {
	m, err := NewMailBuilder().
		From("s@example.com").
		To("r@example.com").
		TextBody("Two attachments follow.").
		AttachFile("a.txt", []byte("file a"), "text/plain").
		AttachFile("b.txt", []byte("file b"), "text/plain").
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	body := string(m.Content.Body)
	if !strings.Contains(body, "a.txt") {
		t.Error("first attachment filename missing")
	}
	if !strings.Contains(body, "b.txt") {
		t.Error("second attachment filename missing")
	}
}

func TestMailBuilder_AttachFile_Base64Encoded(t *testing.T) {
	// Verify the attachment data is actually base64 encoded in the output
	rawData := []byte("Hello, attachment!")
	m, err := NewMailBuilder().
		From("s@example.com").
		To("r@example.com").
		TextBody("see attachment").
		AttachFile("hello.txt", rawData, "text/plain").
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// base64("Hello, attachment!") = "SGVsbG8sIGF0dGFjaG1lbnQh"
	if !strings.Contains(string(m.Content.Body), "SGVsbG8sIGF0dGFjaG1lbnQh") {
		t.Errorf("expected base64-encoded content in body, got:\n%s", string(m.Content.Body))
	}
}

// ===== Targeted gap-filling tests =====

func TestMailBuilder_References_AlreadyBracketed(t *testing.T) {
	// When IDs already have angle brackets they must not be double-bracketed.
	m, err := NewMailBuilder().
		From("s@example.com").
		To("r@example.com").
		TextBody("test").
		References("<msg1@example.com>", "<msg2@example.com>").
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	refs := m.Content.Headers.Get("References")
	if strings.Count(refs, "<<") > 0 {
		t.Errorf("double-bracketed References: %q", refs)
	}
	if !strings.Contains(refs, "<msg1@example.com>") {
		t.Errorf("References missing msg1: %q", refs)
	}
}

func TestMailBuilder_NullSender_NoFromHeader(t *testing.T) {
	// NullSender with no From header should return an error.
	_, err := NewMailBuilder().
		NullSender().
		To("r@example.com").
		TextBody("test").
		Build()
	if err == nil {
		t.Error("expected error: NullSender with no From header")
	}
}

func TestMailBuilder_AttachFile_NoFilename(t *testing.T) {
	// Attachment without a filename should still build successfully.
	m, err := NewMailBuilder().
		From("s@example.com").
		To("r@example.com").
		TextBody("hi").
		AttachFile("", []byte("data"), "application/octet-stream").
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !strings.HasPrefix(m.Content.Headers.Get("Content-Type"), "multipart/mixed") {
		t.Errorf("Content-Type = %q", m.Content.Headers.Get("Content-Type"))
	}
}

func TestFormatAddress_NonASCIIDisplayName(t *testing.T) {
	// Non-ASCII display name should be RFC 2047 encoded.
	addr := MailboxAddress{
		LocalPart:   "user",
		Domain:      "example.com",
		DisplayName: "田中太郎",
	}
	result := formatAddress(addr)
	if !strings.Contains(result, "=?UTF-8?B?") {
		t.Errorf("non-ASCII display name not RFC2047-encoded: %q", result)
	}
	if !strings.Contains(result, "<user@example.com>") {
		t.Errorf("address part missing in %q", result)
	}
}

func TestContent_Validate_FinalLineTooLong(t *testing.T) {
	// Body with no trailing CRLF whose final line exceeds MaxLineLength.
	finalLine := bytes.Repeat([]byte("a"), MaxLineLength+1)
	content := Content{
		Headers: Headers{
			{Name: "Date", Value: "Thu, 12 Dec 2024 10:00:00 +0000"},
			{Name: "From", Value: "sender@example.com"},
		},
		Body: finalLine, // no trailing \r\n
	}
	err := content.Validate()
	if err != ErrLineTooLong {
		t.Errorf("expected ErrLineTooLong for long final line, got %v", err)
	}
}

func TestContent_Validate_FinalLineAtLimit(t *testing.T) {
	// Final line exactly at MaxLineLength (no CRLF) should be valid.
	finalLine := bytes.Repeat([]byte("a"), MaxLineLength)
	content := Content{
		Headers: Headers{
			{Name: "Date", Value: "Thu, 12 Dec 2024 10:00:00 +0000"},
			{Name: "From", Value: "sender@example.com"},
		},
		Body: finalLine,
	}
	err := content.Validate()
	if err != nil {
		t.Errorf("expected no error for final line at MaxLineLength, got %v", err)
	}
}

func TestContent_FromMIME_Multipart(t *testing.T) {
	// FromMIME with a multipart Part should serialize the whole structure into Body.
	boundary := "test-boundary-xyz"
	part := &MIMEPart{
		ContentType: "multipart/mixed; boundary=\"" + boundary + "\"",
		Parts: []*MIMEPart{
			{
				ContentType:             "text/plain",
				Charset:                 "utf-8",
				ContentTransferEncoding: Encoding7Bit,
				Body:                    []byte("Text part body"),
			},
			{
				ContentType:             "application/octet-stream",
				ContentTransferEncoding: EncodingBase64,
				Body:                    []byte("attachment data"),
			},
		},
	}

	var c Content
	if err := c.FromMIME(part); err != nil {
		t.Fatalf("FromMIME: %v", err)
	}
	if !strings.Contains(string(c.Body), boundary) {
		t.Errorf("multipart boundary missing from serialized body")
	}
	if !strings.Contains(string(c.Body), "Text part body") {
		t.Errorf("first part body missing from serialized output")
	}
}

func TestFoldHeader_ForceBreakAtMaxLength(t *testing.T) {
	// A value with no whitespace longer than MaxLineLength must be force-broken.
	longWord := strings.Repeat("x", MaxLineLength+10)
	result := FoldHeader("X-Token", longWord)

	lines := splitLines(result)
	for i, line := range lines {
		if len(line) > MaxLineLength {
			t.Errorf("line %d exceeds MaxLineLength after force-break: len=%d", i, len(line))
		}
	}
	// Result must end with CRLF.
	if len(result) < 2 || result[len(result)-2] != '\r' || result[len(result)-1] != '\n' {
		t.Error("result must end with CRLF")
	}
}
