package mail

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestMailBuilder_ExtensionParam_InitializesMapWhenNil(t *testing.T) {
	b := NewMailBuilder()
	b.mail.Envelope.ExtensionParams = nil
	b.ExtensionParam("x-test", "1")
	if b.mail.Envelope.ExtensionParams["X-TEST"] != "1" {
		t.Fatalf("ExtensionParams = %#v", b.mail.Envelope.ExtensionParams)
	}
}

func TestMailBuilder_Build_AutoAddsSenderForMultipleFrom(t *testing.T) {
	b := NewMailBuilder()
	b.mail.SetFrom(MailboxAddress{LocalPart: "sender", Domain: "example.com"})
	b.mail.Content.Headers = Headers{{Name: "From", Value: "one@example.com, two@example.com"}}
	b.mail.AddRecipient(MailboxAddress{LocalPart: "rcpt", Domain: "example.com"})
	b.mail.Content.Body = []byte("body")

	m, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if m.Content.Headers.Get("Sender") != "sender@example.com" {
		t.Errorf("Sender = %q, want sender@example.com", m.Content.Headers.Get("Sender"))
	}
}

func TestMailBuilder_Build_MessageIDFallsBackToLocalhost(t *testing.T) {
	b := NewMailBuilder()
	b.mail.Content.Headers = Headers{{Name: "From", Value: "sender"}}
	b.mail.Envelope.From = Path{}
	b.mail.AddRecipient(MailboxAddress{LocalPart: "rcpt"})
	b.mail.Content.Body = []byte("body")

	m, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !strings.Contains(m.Content.Headers.Get("Message-ID"), "@localhost>") {
		t.Errorf("Message-ID = %q, want localhost domain fallback", m.Content.Headers.Get("Message-ID"))
	}
}

func TestMailBuilder_Build_ReturnsCollectedErrors(t *testing.T) {
	_, err := NewMailBuilder().
		From("not-an-address").
		To("r@example.com").
		Build()
	if err == nil || !strings.Contains(err.Error(), "mail builder errors") {
		t.Fatalf("expected collected builder error, got %v", err)
	}
}

func TestMailBuilder_Build_ApplyAttachmentsError(t *testing.T) {
	_, err := NewMailBuilder().
		From("s@example.com").
		To("r@example.com").
		AttachFile("bad\r\nname.txt", []byte("data"), "text/plain").
		Build()
	if err == nil {
		t.Fatal("expected attachment header error")
	}
}

func TestMailBuilder_ApplyAttachments_DefaultBodyHeadersAndBase64Wrapping(t *testing.T) {
	data := []byte(strings.Repeat("abcdef", 20))
	m, err := NewMailBuilder().
		From("s@example.com").
		To("r@example.com").
		AttachFile("long.txt", data, "text/plain").
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	body := string(m.Content.Body)
	if !strings.Contains(body, "Content-Type: text/plain; charset=utf-8") {
		t.Errorf("default body Content-Type missing: %q", body)
	}
	if !strings.Contains(body, "Content-Transfer-Encoding: 7bit") {
		t.Errorf("default body Content-Transfer-Encoding missing: %q", body)
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	if !strings.Contains(body, encoded[:76]+"\r\n") {
		t.Errorf("base64 body not wrapped at 76 chars: %q", body)
	}
}
