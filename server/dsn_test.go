package server_test

import (
	"strings"
	"testing"

	"github.com/synqronlabs/raven/server"
)

func newDSNTestServer(t *testing.T, session *testSession, smtpUTF8 bool) (*testServer, *testClient) {
	t.Helper()
	backend := &testBackend{sessionFactory: func(*server.Conn) (server.Session, error) {
		return session, nil
	}}
	ts := newTestServer(t, backend, server.ServerConfig{
		EnableDSN:      true,
		EnableSMTPUTF8: smtpUTF8,
	})
	tc := ts.dial()
	tc.send("EHLO client.example.com")
	tc.expectMultilineCode(250)
	return ts, tc
}

func TestServerDSNRejectsDuplicateParameters(t *testing.T) {
	tests := []struct {
		name    string
		command string
		rcpt    bool
	}{
		{name: "RET", command: "MAIL FROM:<sender@example.com> RET=FULL RET=HDRS"},
		{name: "ENVID", command: "MAIL FROM:<sender@example.com> ENVID=one ENVID=two"},
		{name: "NOTIFY", command: "RCPT TO:<recipient@example.com> NOTIFY=FAILURE NOTIFY=DELAY", rcpt: true},
		{name: "ORCPT", command: "RCPT TO:<recipient@example.com> ORCPT=rfc822;one@example.com ORCPT=rfc822;two@example.com", rcpt: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &testSession{}
			ts, tc := newDSNTestServer(t, session, false)
			defer ts.close()
			defer tc.close()
			if tt.rcpt {
				tc.send("MAIL FROM:<sender@example.com>")
				tc.expectCode(250)
			}

			tc.send("%s", tt.command)
			tc.expectCode(501)
			if tt.rcpt && len(session.recipients) != 0 {
				t.Fatal("application session was invoked for invalid RCPT")
			}
			if !tt.rcpt && session.mailOpts != nil {
				t.Fatal("application session was invoked for invalid MAIL")
			}
		})
	}
}

func TestServerDSNRejectsMalformedParameters(t *testing.T) {
	mailCommands := []string{
		"MAIL FROM:<sender@example.com> RET",
		"MAIL FROM:<sender@example.com> RET=",
		"MAIL FROM:<sender@example.com> ENVID",
		"MAIL FROM:<sender@example.com> ENVID=",
		"MAIL FROM:<sender@example.com> ENVID=bad+2f",
		"MAIL FROM:<sender@example.com> ENVID=bad+",
		"MAIL FROM:<sender@example.com> ENVID=bad=equals",
	}
	for _, command := range mailCommands {
		t.Run(command, func(t *testing.T) {
			session := &testSession{}
			ts, tc := newDSNTestServer(t, session, false)
			defer ts.close()
			defer tc.close()
			tc.send("%s", command)
			tc.expectCode(501)
		})
	}

	rcptCommands := []string{
		"RCPT TO:<recipient@example.com> NOTIFY",
		"RCPT TO:<recipient@example.com> NOTIFY=",
		"RCPT TO:<recipient@example.com> NOTIFY=FAILURE,",
		"RCPT TO:<recipient@example.com> ORCPT",
		"RCPT TO:<recipient@example.com> ORCPT=",
		"RCPT TO:<recipient@example.com> ORCPT=missing-semicolon",
		"RCPT TO:<recipient@example.com> ORCPT=rfc822;bad+2f",
	}
	for _, command := range rcptCommands {
		t.Run(command, func(t *testing.T) {
			session := &testSession{}
			ts, tc := newDSNTestServer(t, session, false)
			defer ts.close()
			defer tc.close()
			tc.send("MAIL FROM:<sender@example.com>")
			tc.expectCode(250)
			tc.send("%s", command)
			tc.expectCode(501)
			if len(session.recipients) != 0 {
				t.Fatal("application session was invoked for invalid RCPT")
			}
		})
	}
}

func TestServerDSNNotifyNeverMustAppearAlone(t *testing.T) {
	session := &testSession{}
	ts, tc := newDSNTestServer(t, session, false)
	defer ts.close()
	defer tc.close()
	tc.send("MAIL FROM:<sender@example.com>")
	tc.expectCode(250)
	tc.send("RCPT TO:<recipient@example.com> NOTIFY=NEVER,FAILURE")
	tc.expectCode(501)
	if len(session.recipients) != 0 {
		t.Fatal("application session was invoked before NOTIFY validation")
	}
}

func TestServerDSNXTextDecodedAndWireValues(t *testing.T) {
	session := &testSession{}
	ts, tc := newDSNTestServer(t, session, false)
	defer ts.close()
	defer tc.close()

	tc.send("MAIL FROM:<sender@example.com> ENVID=queue+20one+2Btag")
	tc.expectCode(250)
	if session.mailOpts.EnvelopeID != "queue one+tag" {
		t.Fatalf("decoded ENVID = %q", session.mailOpts.EnvelopeID)
	}
	if got := session.mailOpts.EnvelopeIDValue.Wire; got != "queue+20one+2Btag" {
		t.Fatalf("wire ENVID = %q", got)
	}

	tc.send("RCPT TO:<recipient@example.com> ORCPT=RFC822;old+20name+2Btag@example.com")
	tc.expectCode(250)
	options := session.rcptOpts[0]
	if options.OriginalRecipient != "RFC822;old name+tag@example.com" {
		t.Fatalf("decoded ORCPT = %q", options.OriginalRecipient)
	}
	if got := options.OriginalRecipientValue.Wire; got != "RFC822;old+20name+2Btag@example.com" {
		t.Fatalf("wire ORCPT = %q", got)
	}
}

func TestServerDSNParameterLengthLimits(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    int
		rcpt    bool
	}{
		{name: "ENVID 100", command: "MAIL FROM:<sender@example.com> ENVID=" + strings.Repeat("a", 94), want: 250},
		{name: "ENVID 101", command: "MAIL FROM:<sender@example.com> ENVID=" + strings.Repeat("a", 95), want: 501},
		{name: "ORCPT 500", command: "RCPT TO:<recipient@example.com> ORCPT=rfc822;" + strings.Repeat("a", 487), want: 250, rcpt: true},
		{name: "ORCPT 501", command: "RCPT TO:<recipient@example.com> ORCPT=rfc822;" + strings.Repeat("a", 488), want: 501, rcpt: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &testSession{}
			ts, tc := newDSNTestServer(t, session, false)
			defer ts.close()
			defer tc.close()
			if tt.rcpt {
				tc.send("MAIL FROM:<sender@example.com>")
				tc.expectCode(250)
			}
			tc.send("%s", tt.command)
			tc.expectCode(tt.want)
		})
	}
}

func TestServerDSNUTF8OriginalRecipient(t *testing.T) {
	for _, tt := range []struct {
		name       string
		mailParams string
		want       int
	}{
		{name: "requires SMTPUTF8 transaction", want: 501},
		{name: "accepted with SMTPUTF8", mailParams: " SMTPUTF8", want: 250},
	} {
		t.Run(tt.name, func(t *testing.T) {
			session := &testSession{}
			ts, tc := newDSNTestServer(t, session, true)
			defer ts.close()
			defer tc.close()
			tc.send("MAIL FROM:<sender@example.com>%s", tt.mailParams)
			tc.expectCode(250)
			tc.send("RCPT TO:<recipient@example.com> ORCPT=utf-8;用户@example.com")
			tc.expectCode(tt.want)
			if tt.want == 250 && session.rcptOpts[0].OriginalRecipient != "utf-8;用户@example.com" {
				t.Fatalf("decoded UTF-8 ORCPT = %q", session.rcptOpts[0].OriginalRecipient)
			}
		})
	}
}

func TestServerDSNAccepts1036ByteCommandLine(t *testing.T) {
	session := &testSession{}
	ts, tc := newDSNTestServer(t, session, false)
	defer ts.close()
	defer tc.close()

	const prefix = "MAIL FROM:<sender@example.com> ENVID=id X="
	command := prefix + strings.Repeat("a", 1036-len(prefix)-2)
	if len(command)+2 != 1036 {
		t.Fatalf("test command length = %d", len(command)+2)
	}
	tc.send("%s", command)
	tc.expectCode(250)
}
