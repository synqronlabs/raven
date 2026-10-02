package server

import (
	stdmail "net/mail"
	"strings"
	"testing"

	ravenmail "github.com/synqronlabs/raven/mail"
)

func newFixupServer(opts HeaderFixupOptions) *Server {
	return NewServer(nil, ServerConfig{Domain: "mx.example.com", HeaderFixups: opts})
}

func fixupAndParse(t *testing.T, s *Server, raw string) ravenmail.Headers {
	t.Helper()
	out := s.fixupHeaders(MessageHeaders(raw))
	return ravenmail.ParseHeaders([]byte(out))
}

func TestFixupHeaders_DisabledIsNoOp(t *testing.T) {
	s := newFixupServer(HeaderFixupOptions{})
	in := MessageHeaders("Received: from client\r\nFrom: a@example.com\r\nSubject: x\r\n")

	out := s.fixupHeaders(in)
	if string(out) != string(in) {
		t.Fatalf("disabled fixup changed headers:\n got %q\nwant %q", out, in)
	}
}

func TestFixupHeaders_AddMessageID(t *testing.T) {
	s := newFixupServer(HeaderFixupOptions{AddMessageID: true})
	parsed := fixupAndParse(t, s, "Received: from client\r\nFrom: a@example.com\r\nDate: Thu, 12 Dec 2024 10:00:00 +0000\r\nSubject: x\r\n")

	id := parsed.Get("Message-ID")
	if id == "" {
		t.Fatal("expected Message-ID to be generated")
	}
	if !strings.HasPrefix(id, "<") || !strings.HasSuffix(id, "@mx.example.com>") {
		t.Fatalf("Message-ID = %q, want generated for mx.example.com", id)
	}
}

func TestFixupHeaders_AddMessageIDDomainOverride(t *testing.T) {
	s := newFixupServer(HeaderFixupOptions{AddMessageID: true, MessageIDDomain: "submit.example.net"})
	parsed := fixupAndParse(t, s, "From: a@example.com\r\n")

	id := parsed.Get("Message-ID")
	if !strings.HasSuffix(id, "@submit.example.net>") {
		t.Fatalf("Message-ID = %q, want domain override", id)
	}
}

func TestFixupHeaders_AddDate(t *testing.T) {
	s := newFixupServer(HeaderFixupOptions{AddDate: true})
	parsed := fixupAndParse(t, s, "From: a@example.com\r\nSubject: x\r\n")

	value := parsed.Get("Date")
	if value == "" {
		t.Fatal("expected Date to be generated")
	}
	if _, err := stdmail.ParseDate(value); err != nil {
		t.Fatalf("generated Date %q is not parseable: %v", value, err)
	}
}

func TestFixupHeaders_AddSender(t *testing.T) {
	s := newFixupServer(HeaderFixupOptions{AddSender: true})
	parsed := fixupAndParse(t, s, "From: alice@example.com, bob@example.com\r\nSubject: x\r\n")

	if got := parsed.Get("Sender"); got != "alice@example.com" {
		t.Fatalf("Sender = %q, want first From mailbox", got)
	}
}

func TestFixupHeaders_AddSenderRespectsExisting(t *testing.T) {
	s := newFixupServer(HeaderFixupOptions{AddSender: true})
	parsed := fixupAndParse(t, s, "From: alice@example.com, bob@example.com\r\nSender: carol@example.com\r\n")

	if got := parsed.Count("Sender"); got != 1 {
		t.Fatalf("Sender count = %d, want 1", got)
	}
	if got := parsed.Get("Sender"); got != "carol@example.com" {
		t.Fatalf("Sender = %q, want existing value", got)
	}
}

func TestFixupHeaders_AddSenderSingleFromUntouched(t *testing.T) {
	s := newFixupServer(HeaderFixupOptions{AddSender: true})
	parsed := fixupAndParse(t, s, "From: alice@example.com\r\n")

	if got := parsed.Count("Sender"); got != 0 {
		t.Fatalf("Sender count = %d, want 0 for single From", got)
	}
}

func TestFixupHeaders_DedupeSingleOccurrenceHeaders(t *testing.T) {
	s := newFixupServer(HeaderFixupOptions{RemoveDuplicateSingleHeaders: true})
	parsed := fixupAndParse(t, s,
		"From: first@example.com\r\n"+
			"Subject: keep\r\n"+
			"From: second@example.com\r\n"+
			"Subject: drop\r\n",
	)

	if got := parsed.Count("From"); got != 1 {
		t.Fatalf("From count = %d, want 1", got)
	}
	if got := parsed.Get("From"); got != "first@example.com" {
		t.Fatalf("From = %q, want first occurrence", got)
	}
	if got := parsed.Get("Subject"); got != "keep" {
		t.Fatalf("Subject = %q, want first occurrence", got)
	}
}

func TestFixupHeaders_DedupeKeepsRepeatableHeaders(t *testing.T) {
	s := newFixupServer(HeaderFixupOptions{RemoveDuplicateSingleHeaders: true})
	parsed := fixupAndParse(t, s,
		"Received: from one\r\n"+
			"Received: from two\r\n"+
			"X-Custom: a\r\n"+
			"X-Custom: b\r\n",
	)

	if got := parsed.Count("Received"); got != 2 {
		t.Fatalf("Received count = %d, want 2", got)
	}
	if got := parsed.Count("X-Custom"); got != 2 {
		t.Fatalf("X-Custom count = %d, want 2", got)
	}
}

func TestFixupHeaders_ReorderTraceHeaders(t *testing.T) {
	s := newFixupServer(HeaderFixupOptions{ReorderTraceHeaders: true})
	parsed := fixupAndParse(t, s,
		"Received: from raven\r\n"+
			"Subject: x\r\n"+
			"Return-Path: <bounce@example.com>\r\n",
	)

	if len(parsed) != 3 {
		t.Fatalf("header count = %d, want 3", len(parsed))
	}
	if parsed[0].Name != "Return-Path" || parsed[1].Name != "Received" || parsed[2].Name != "Subject" {
		t.Fatalf("unexpected order: %s, %s, %s", parsed[0].Name, parsed[1].Name, parsed[2].Name)
	}
}

func TestFixupHeaders_ReorderMovesResentBeforeRegular(t *testing.T) {
	s := newFixupServer(HeaderFixupOptions{ReorderTraceHeaders: true})
	parsed := fixupAndParse(t, s,
		"Received: from raven\r\n"+
			"Resent-From: alice@example.com\r\n"+
			"Subject: x\r\n"+
			"Resent-Date: Thu, 12 Dec 2024 10:00:00 +0000\r\n",
	)

	want := []string{"Received", "Resent-From", "Resent-Date", "Subject"}
	for i, name := range want {
		if parsed[i].Name != name {
			t.Fatalf("header[%d] = %s, want %s (order: %v)", i, parsed[i].Name, name, names(parsed))
		}
	}
}

func TestFixupHeaders_Combined(t *testing.T) {
	s := newFixupServer(AllHeaderFixups())
	parsed := fixupAndParse(t, s,
		"Received: from client.test (127.0.0.1) by mx.example.com with ESMTP id abc; Thu, 12 Dec 2024 10:00:00 +0000\r\n"+
			"From: alice@example.com, bob@example.com\r\n"+
			"Subject: one\r\n"+
			"Subject: two\r\n",
	)

	if parsed.Get("Message-ID") == "" {
		t.Fatal("expected Message-ID")
	}
	if parsed.Get("Date") == "" {
		t.Fatal("expected Date")
	}
	if parsed.Get("Sender") != "alice@example.com" {
		t.Fatalf("Sender = %q", parsed.Get("Sender"))
	}
	if parsed.Count("Subject") != 1 {
		t.Fatalf("Subject count = %d, want 1", parsed.Count("Subject"))
	}
	if parsed[0].Name != "Received" {
		t.Fatalf("expected Received first, got %s", parsed[0].Name)
	}
	// Generated headers must still produce a block that validates.
	if err := parsed.Validate(); err != nil {
		t.Fatalf("fixed headers failed validation: %v", err)
	}
}

func TestFixupHeaders_NormalizeReturnPath(t *testing.T) {
	s := newFixupServer(HeaderFixupOptions{NormalizeReturnPath: true})

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"bare address", "noreply@example.com", "<noreply@example.com>"},
		{"already bracketed", "<noreply@example.com>", "<noreply@example.com>"},
		{"null path", "<>", "<>"},
		{"display name", "Zitadel <noreply@example.com>", "<noreply@example.com>"},
		{"empty", "", ""},
		{"whitespace only", "   ", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := fixupAndParse(t, s, "Return-Path: "+tt.in+"\r\n")
			if got := parsed.Get("Return-Path"); got != tt.want {
				t.Fatalf("Return-Path = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFixupHeaders_DropEmptyAddressHeaders(t *testing.T) {
	s := newFixupServer(HeaderFixupOptions{DropEmptyAddressHeaders: true})
	parsed := fixupAndParse(t, s,
		"From: a@example.com\r\n"+
			"To: \r\n"+
			"Cc:    \r\n"+
			"Bcc:\r\n"+
			"Reply-To: \r\n"+
			"X-Custom: \r\n",
	)

	for _, name := range []string{"To", "Cc", "Bcc", "Reply-To"} {
		if got := parsed.Count(name); got != 0 {
			t.Fatalf("%s count = %d, want 0", name, got)
		}
	}
	if got := parsed.Count("From"); got != 1 {
		t.Fatalf("From count = %d, want 1", got)
	}
	if got := parsed.Count("X-Custom"); got != 1 {
		t.Fatalf("X-Custom count = %d, want 1", got)
	}
}

func TestFixupHeaders_DropEmptyAddressHeadersKeepsValues(t *testing.T) {
	s := newFixupServer(HeaderFixupOptions{DropEmptyAddressHeaders: true})
	parsed := fixupAndParse(t, s,
		"To: user@example.com\r\n"+
			"Cc: cc@example.com\r\n",
	)

	if got := parsed.Get("To"); got != "user@example.com" {
		t.Fatalf("To = %q, want preserved", got)
	}
	if got := parsed.Get("Cc"); got != "cc@example.com" {
		t.Fatalf("Cc = %q, want preserved", got)
	}
}

func TestFixupHeaders_ZitadelSubmission(t *testing.T) {
	s := newFixupServer(AllHeaderFixups())
	parsed := fixupAndParse(t, s,
		"Received: from client.test (127.0.0.1) by mx.example.com with ESMTP id abc; Thu, 12 Dec 2024 10:00:00 +0000\r\n"+
			"From: =?UTF-8?B?Wml0YWRlbA==?= <noreply@example.com>\r\n"+
			"Return-Path: noreply@example.com\r\n"+
			"To: user@example.net\r\n"+
			"Cc: \r\n"+
			"Date: Thu, 12 Dec 2024 10:00:00 +0000\r\n"+
			"Subject: =?UTF-8?B?VmVyaWZ5?=\r\n"+
			"MIME-Version: 1.0\r\n"+
			"Content-Type: text/html; charset=\"UTF-8\"\r\n",
	)

	if parsed[0].Name != "Return-Path" {
		t.Fatalf("expected Return-Path first, got %s", parsed[0].Name)
	}
	if got := parsed.Get("Return-Path"); got != "<noreply@example.com>" {
		t.Fatalf("Return-Path = %q, want bracketed", got)
	}
	if got := parsed.Count("Cc"); got != 0 {
		t.Fatalf("Cc count = %d, want 0", got)
	}
	if got := parsed.Get("Message-ID"); got == "" {
		t.Fatal("expected Message-ID to be generated")
	}
	if err := parsed.Validate(); err != nil {
		t.Fatalf("Zitadel-like message failed validation after fixups: %v", err)
	}
}

func TestAllHeaderFixups_EnablesEveryRepair(t *testing.T) {
	opts := AllHeaderFixups()
	if !opts.AddMessageID || !opts.AddDate || !opts.AddSender || !opts.NormalizeReturnPath ||
		!opts.DropEmptyAddressHeaders || !opts.RemoveDuplicateSingleHeaders || !opts.ReorderTraceHeaders {
		t.Fatalf("AllHeaderFixups did not enable every repair: %+v", opts)
	}
}

func names(headers ravenmail.Headers) []string {
	out := make([]string, len(headers))
	for i, h := range headers {
		out[i] = h.Name
	}
	return out
}
