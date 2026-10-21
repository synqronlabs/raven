package mail

import (
	"errors"
	"mime"
	"strings"
	"testing"
)

func TestParseAddress_EncodedDisplayNameRejectsControlCharacters(t *testing.T) {
	inputs := []string{
		"=?utf-8?q?Acme=0D=0ABcc=3A_attacker=40evil.example?= <noreply@acme.example>",
		"=?utf-8?q?Acme=0ABcc=3A_attacker=40evil.example?= <noreply@acme.example>",
		"=?utf-8?q?Acme=00Bcc?= <noreply@acme.example>",
	}
	for _, input := range inputs {
		if _, err := ParseAddress(input); err == nil {
			t.Errorf("ParseAddress(%q) = nil error, want error", input)
		}
	}
}

func TestMailBuilder_FromEncodedDisplayNameInjectionRejected(t *testing.T) {
	_, err := NewMailBuilder().
		From("=?utf-8?q?Acme=0D=0ABcc=3A_attacker=40evil.example?= <noreply@acme.example>").
		To("recipient@example.com").
		TextBody("test").
		Build()
	if err == nil {
		t.Fatal("Build() = nil error, want rejected encoded display name")
	}
}

func TestFormatAddress_ProgrammaticDisplayNameCannotInjectHeader(t *testing.T) {
	got := formatAddress(MailboxAddress{
		LocalPart:   "noreply",
		Domain:      "acme.example",
		DisplayName: "Acme\r\nBcc: attacker@evil.example",
	})
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("formatAddress() emitted a line break: %q", got)
	}
}

func TestMailBuilder_FromMailboxRejectsInjectedDisplayName(t *testing.T) {
	_, err := NewMailBuilder().
		FromMailbox(MailboxAddress{
			LocalPart:   "noreply",
			Domain:      "acme.example",
			DisplayName: "Acme\r\nBcc: attacker@evil.example",
		}).
		To("recipient@example.com").
		TextBody("test").
		Build()
	if !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("Build() error = %v, want %v", err, ErrInvalidAddress)
	}
}

func TestMailBuilder_ToMailboxRejectsInjectedAddress(t *testing.T) {
	_, err := NewMailBuilder().
		From("sender@example.com").
		ToMailbox(MailboxAddress{
			LocalPart: "victim@example.com>\r\nRCPT TO:<attacker@evil.example",
			Domain:    "example.com",
		}).
		TextBody("test").
		Build()
	if !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("Build() error = %v, want %v", err, ErrInvalidAddress)
	}
}

func TestFormatAddress_QuotedDisplayNameBackslashRoundTrip(t *testing.T) {
	const input = `"A\\B, C" <a@b.com>`
	parsed, err := ParseAddress(input)
	if err != nil {
		t.Fatalf("ParseAddress(%q) error: %v", input, err)
	}
	if parsed.DisplayName != `A\B, C` {
		t.Fatalf("DisplayName = %q, want %q", parsed.DisplayName, `A\B, C`)
	}

	formatted := formatAddress(parsed)
	if formatted != input {
		t.Fatalf("formatAddress() = %q, want %q", formatted, input)
	}

	reparsed, err := ParseAddress(formatted)
	if err != nil {
		t.Fatalf("re-parsing %q error: %v", formatted, err)
	}
	if reparsed.DisplayName != parsed.DisplayName {
		t.Fatalf("round-trip DisplayName = %q, want %q", reparsed.DisplayName, parsed.DisplayName)
	}
}

func TestParseAddress_FoldingWhiteSpace(t *testing.T) {
	for _, input := range []string{
		"John\r\n Doe <john@example.com>",
		"John\r\n\tDoe <john@example.com>",
		"(lead)\r\n John Doe <john@example.com>",
		"\"John\r\n Doe\" <john@example.com>",
	} {
		parsed, err := ParseAddress(input)
		if err != nil {
			t.Errorf("ParseAddress(%q) error: %v", input, err)
			continue
		}
		if parsed.DisplayName != "John Doe" {
			t.Errorf("ParseAddress(%q).DisplayName = %q, want %q", input, parsed.DisplayName, "John Doe")
		}
	}

	for _, input := range []string{
		"John\n Doe <john@example.com>",
		"John\rDoe <john@example.com>",
		"John\r\nDoe <john@example.com>",
	} {
		if _, err := ParseAddress(input); !errors.Is(err, ErrInvalidLineEnding) {
			t.Errorf("ParseAddress(%q) error = %v, want %v", input, err, ErrInvalidLineEnding)
		}
	}
}

func TestParseAddress_CanonicalizesObsCFWS(t *testing.T) {
	tests := []struct {
		input   string
		local   string
		domain  string
		display string
	}{
		{"user (comment) . name@example.com", "user.name", "example.com", ""},
		{"user@exam (comment) . com", "user", "exam.com", ""},
		{"(a) user (b) . name (c) @ (d) Exam (e) . Com (f)", "user.name", "exam.com", ""},
		{"Jane (comment) Doe <user (x) . name@exam (y) . com>", "user.name", "exam.com", "Jane Doe"},
	}
	for _, tt := range tests {
		parsed, err := ParseAddress(tt.input)
		if err != nil {
			t.Errorf("ParseAddress(%q) error: %v", tt.input, err)
			continue
		}
		if parsed.LocalPart != tt.local || parsed.Domain != tt.domain || parsed.DisplayName != tt.display {
			t.Errorf("ParseAddress(%q) = %+v, want local=%q domain=%q display=%q",
				tt.input, parsed, tt.local, tt.domain, tt.display)
		}
	}
}

func TestParseAddress_InvalidIDNAndAddressLiterals(t *testing.T) {
	invalid := []string{
		"user@例え.\u200b.jp",
		"user@[notip]",
		"user@[IPv6:zz]",
		"user@[192.168.1]",
	}
	for _, input := range invalid {
		if _, err := ParseAddress(input); err == nil {
			t.Errorf("ParseAddress(%q) = nil error, want error", input)
		}
	}

	parsed, err := ParseAddress("user@[ IPv6:2001:db8::1 ]")
	if err != nil {
		t.Fatalf("folded address literal error: %v", err)
	}
	if parsed.Domain != "[IPv6:2001:db8::1]" {
		t.Errorf("Domain = %q, want [IPv6:2001:db8::1]", parsed.Domain)
	}
}

func TestParseAddress_HeaderLengthLimits(t *testing.T) {
	if _, err := ParseAddress(strings.Repeat("a", 65) + "@example.com"); !errors.Is(err, ErrLocalPartTooLong) {
		t.Errorf("long local-part error = %v, want %v", err, ErrLocalPartTooLong)
	}

	domain := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 62)
	if _, err := ParseAddress(strings.Repeat("a", 64) + "@" + domain); !errors.Is(err, ErrAddressTooLong) {
		t.Errorf("long address error = %v, want %v", err, ErrAddressTooLong)
	}

	domain = strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63) + ".e"
	if _, err := ParseAddress("user@" + domain); !errors.Is(err, ErrDomainTooLong) {
		t.Errorf("long domain error = %v, want %v", err, ErrDomainTooLong)
	}
}

func TestEncodeRFC2047_SplitsLongValues(t *testing.T) {
	value := strings.Repeat("日本語の件名", 50)
	encoded := encodeRFC2047(value)
	words := strings.Fields(encoded)
	if len(words) < 2 {
		t.Fatalf("encodeRFC2047() did not split a long value: %q", encoded)
	}
	for _, word := range words {
		if len(word) > 75 {
			t.Errorf("encoded-word is %d characters, want <= 75: %q", len(word), word)
		}
		if !strings.HasPrefix(word, "=?UTF-8?B?") || !strings.HasSuffix(word, "?=") {
			t.Errorf("unexpected encoded-word: %q", word)
		}
	}

	decoded, err := new(mime.WordDecoder).DecodeHeader(encoded)
	if err != nil {
		t.Fatalf("decoding encoded value: %v", err)
	}
	if decoded != value {
		t.Errorf("decoded value = %q, want %q", decoded, value)
	}
}

func TestMailBuilder_BuildRejectsHeaderInjection(t *testing.T) {
	_, err := NewMailBuilder().
		From("sender@example.com").
		To("recipient@example.com").
		Header("Subject", "hello\r\nBcc: attacker@evil.example").
		TextBody("test").
		Build()
	if !errors.Is(err, ErrInvalidLineEnding) {
		t.Fatalf("Build() error = %v, want %v", err, ErrInvalidLineEnding)
	}
}
