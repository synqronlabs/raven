package server_test

import (
	"strings"
	"testing"

	"github.com/synqronlabs/raven/mail"
	"github.com/synqronlabs/raven/server"
)

func TestServer_HeaderFixups_DATA(t *testing.T) {
	sess := &testSession{}
	backend := &testBackend{
		sessionFactory: func(_ *server.Conn) (server.Session, error) {
			return sess, nil
		},
	}
	ts := newTestServer(t, backend, server.ServerConfig{
		Domain:       "mx.example.com",
		HeaderFixups: server.AllHeaderFixups(),
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

	tc.send("Subject: first\r\n" +
		"Subject: second\r\n" +
		"From: alice@example.com, bob@example.com\r\n" +
		"Return-Path: <bounce@example.com>\r\n" +
		"\r\nBody.\r\n.")
	tc.expectCode(250)

	if len(sess.completed) != 1 {
		t.Fatalf("expected one completed transaction, got %d", len(sess.completed))
	}

	parsed := mail.ParseHeaders(sess.completed[0].headers)
	if got := parsed.Get("Message-ID"); got == "" {
		t.Fatal("expected Message-ID to be generated")
	}
	if got := parsed.Get("Date"); got == "" {
		t.Fatal("expected Date to be generated")
	}
	if got := parsed.Get("Sender"); got != "alice@example.com" {
		t.Fatalf("Sender = %q, want first From mailbox", got)
	}
	if got := parsed.Count("Subject"); got != 1 {
		t.Fatalf("Subject count = %d, want 1", got)
	}
	if parsed[0].Name != "Return-Path" {
		t.Fatalf("expected Return-Path first, got %s", parsed[0].Name)
	}
	if parsed[1].Name != "Received" {
		t.Fatalf("expected Received second, got %s", parsed[1].Name)
	}
	if err := parsed.Validate(); err != nil {
		t.Fatalf("fixed headers failed validation: %v\nheaders:\n%s", err, sess.completed[0].headers)
	}
	if got := string(sess.completed[0].body); got != "Body.\r\n" {
		t.Fatalf("body = %q, want unchanged", got)
	}
}

func TestServer_HeaderFixups_BDAT(t *testing.T) {
	sess := &testSession{}
	backend := &testBackend{
		sessionFactory: func(_ *server.Conn) (server.Session, error) {
			return sess, nil
		},
	}
	ts := newTestServer(t, backend, server.ServerConfig{
		Domain:         "mx.example.com",
		EnableCHUNKING: true,
		HeaderFixups:   server.AllHeaderFixups(),
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

	msg := "Subject: first\r\nSubject: second\r\nFrom: alice@example.com\r\n\r\nBody here."
	tc.send("BDAT %d LAST", len(msg))
	tc.writeRaw(msg)
	tc.expectCode(250)

	if len(sess.completed) != 1 {
		t.Fatalf("expected one completed transaction, got %d", len(sess.completed))
	}

	parsed := mail.ParseHeaders(sess.completed[0].headers)
	if got := parsed.Get("Message-ID"); got == "" {
		t.Fatal("expected Message-ID to be generated")
	}
	if got := parsed.Get("Date"); got == "" {
		t.Fatal("expected Date to be generated")
	}
	if got := parsed.Count("Subject"); got != 1 {
		t.Fatalf("Subject count = %d, want 1", got)
	}
	if parsed[0].Name != "Received" {
		t.Fatalf("expected Received first, got %s", parsed[0].Name)
	}
	if err := parsed.Validate(); err != nil {
		t.Fatalf("fixed headers failed validation: %v\nheaders:\n%s", err, sess.completed[0].headers)
	}
	if got := string(sess.completed[0].body); got != "Body here." {
		t.Fatalf("body = %q, want unchanged", got)
	}
}

func TestServer_HeaderFixups_ZitadelSubmission(t *testing.T) {
	sess := &testSession{}
	backend := &testBackend{
		sessionFactory: func(_ *server.Conn) (server.Session, error) {
			return sess, nil
		},
	}
	ts := newTestServer(t, backend, server.ServerConfig{
		Domain:       "mx.example.com",
		HeaderFixups: server.AllHeaderFixups(),
	})
	defer ts.close()

	tc := ts.dial()
	defer tc.close()

	tc.send("EHLO client.test")
	tc.expectMultilineCode(250)
	tc.send("MAIL FROM:<noreply@example.com>")
	tc.expectCode(250)
	tc.send("RCPT TO:<user@example.net>")
	tc.expectCode(250)
	tc.send("DATA")
	tc.expectCode(354)

	tc.send("From: =?UTF-8?B?Wml0YWRlbA==?= <noreply@example.com>\r\n" +
		"Return-Path: noreply@example.com\r\n" +
		"To: user@example.net\r\n" +
		"Cc: \r\n" +
		"Date: Thu, 12 Dec 2024 10:00:00 +0000\r\n" +
		"Subject: =?UTF-8?B?VmVyaWZ5?=\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=\"UTF-8\"\r\n" +
		"\r\nBody.\r\n.")
	tc.expectCode(250)

	parsed := mail.ParseHeaders(sess.completed[0].headers)
	if err := parsed.Validate(); err != nil {
		t.Fatalf("Zitadel-like message failed validation after fixups: %v\nheaders:\n%s", err, sess.completed[0].headers)
	}
	if got := parsed.Get("Return-Path"); got != "<noreply@example.com>" {
		t.Fatalf("Return-Path = %q, want bracketed", got)
	}
	if got := parsed.Count("Cc"); got != 0 {
		t.Fatalf("Cc count = %d, want 0", got)
	}
}

func TestServer_HeaderFixups_DisabledPreservesRawHeaders(t *testing.T) {
	sess := &testSession{}
	backend := &testBackend{
		sessionFactory: func(_ *server.Conn) (server.Session, error) {
			return sess, nil
		},
	}
	ts := newTestServer(t, backend, server.ServerConfig{Domain: "mx.example.com"})
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
	tc.send("Subject: first\r\nSubject: second\r\n\r\nBody.\r\n.")
	tc.expectCode(250)

	if got := sess.completed[0].headers; !strings.Contains(string(got), "Subject: first\r\nSubject: second\r\n") {
		t.Fatalf("disabled fixups altered headers:\n%s", got)
	}
}
