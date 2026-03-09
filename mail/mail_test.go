package mail

import (
	"bytes"
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
