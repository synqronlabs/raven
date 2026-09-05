package client

import (
	"strings"
	"testing"

	ravenmail "github.com/synqronlabs/raven/mail"
)

func dsnTestClient() *Client {
	return &Client{extensions: map[ravenmail.Extension]string{ravenmail.ExtDSN: ""}}
}

func TestClientDSNMailSerialization(t *testing.T) {
	c := dsnTestClient()
	envelope := ravenmail.Envelope{
		From:  ravenmail.Path{Mailbox: ravenmail.MailboxAddress{LocalPart: "sender", Domain: "example.com"}},
		EnvID: "queue one+=",
		DSNParams: &ravenmail.DSNEnvelopeParams{
			RET: "hdrs",
		},
	}
	command, err := c.mailFromCommand(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(command, "RET=HDRS") || !strings.Contains(command, "ENVID=queue+20one+2B+3D") {
		t.Fatalf("MAIL command = %q", command)
	}
}

func TestClientDSNPreservesEnvelopeIDWireValue(t *testing.T) {
	c := dsnTestClient()
	envelope := ravenmail.Envelope{
		From: ravenmail.Path{Mailbox: ravenmail.MailboxAddress{LocalPart: "sender", Domain: "example.com"}},
		DSNParams: &ravenmail.DSNEnvelopeParams{
			EnvelopeID: &ravenmail.DSNXText{Wire: "queue+20ID", Decoded: "queue ID"},
		},
	}
	command, err := c.mailFromCommand(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(command, "ENVID=queue+20ID") {
		t.Fatalf("MAIL command = %q", command)
	}
}

func TestClientRejectsInvalidDSNMailValues(t *testing.T) {
	tests := []struct {
		name     string
		envelope ravenmail.Envelope
	}{
		{name: "RET injection", envelope: ravenmail.Envelope{DSNParams: &ravenmail.DSNEnvelopeParams{RET: "FULL\r\nRCPT TO:<bad@example.com>"}}},
		{name: "invalid RET", envelope: ravenmail.Envelope{DSNParams: &ravenmail.DSNEnvelopeParams{RET: "BODY"}}},
		{name: "ENVID injection", envelope: ravenmail.Envelope{EnvID: "id\r\nRCPT TO:<bad@example.com>"}},
		{name: "ENVID encoded too long", envelope: ravenmail.Envelope{EnvID: strings.Repeat(" ", 34)}},
		{name: "malformed ENVID wire", envelope: ravenmail.Envelope{DSNParams: &ravenmail.DSNEnvelopeParams{EnvelopeID: &ravenmail.DSNXText{Wire: "bad+2f"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.envelope.From = ravenmail.Path{Mailbox: ravenmail.MailboxAddress{LocalPart: "sender", Domain: "example.com"}}
			if _, err := dsnTestClient().mailFromCommand(tt.envelope); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestClientDSNRecipientSerialization(t *testing.T) {
	c := dsnTestClient()
	rcpt := ravenmail.Recipient{
		Address: ravenmail.Path{Mailbox: ravenmail.MailboxAddress{LocalPart: "recipient", Domain: "example.com"}},
		DSNParams: &ravenmail.DSNRecipientParams{
			Notify: []string{"success", "failure"},
			ORcpt:  "rfc822;old name+tag@example.com",
		},
	}
	command, err := c.rcptToCommand(rcpt, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(command, "NOTIFY=SUCCESS,FAILURE") || !strings.Contains(command, "ORCPT=rfc822;old+20name+2Btag@example.com") {
		t.Fatalf("RCPT command = %q", command)
	}
}

func TestClientDSNPreservesOriginalRecipientWireValue(t *testing.T) {
	c := dsnTestClient()
	rcpt := ravenmail.Recipient{
		Address: ravenmail.Path{Mailbox: ravenmail.MailboxAddress{LocalPart: "recipient", Domain: "example.com"}},
		DSNParams: &ravenmail.DSNRecipientParams{OriginalRecipient: &ravenmail.DSNOriginalRecipient{
			Wire:        "RFC822;old+20name@example.com",
			AddressType: "RFC822",
			Address:     ravenmail.DSNXText{Decoded: "old name@example.com"},
		}},
	}
	command, err := c.rcptToCommand(rcpt, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(command, "ORCPT=RFC822;old+20name@example.com") {
		t.Fatalf("RCPT command = %q", command)
	}
}

func TestClientRejectsInvalidDSNRecipientValues(t *testing.T) {
	tests := []struct {
		name     string
		params   *ravenmail.DSNRecipientParams
		smtpUTF8 bool
	}{
		{name: "NEVER combination", params: &ravenmail.DSNRecipientParams{Notify: []string{"NEVER", "FAILURE"}}},
		{name: "NOTIFY injection", params: &ravenmail.DSNRecipientParams{Notify: []string{"FAILURE\r\nDATA"}}},
		{name: "ORCPT structure", params: &ravenmail.DSNRecipientParams{ORcpt: "recipient@example.com"}},
		{name: "ORCPT injection", params: &ravenmail.DSNRecipientParams{ORcpt: "rfc822;recipient@example.com\r\nDATA"}},
		{name: "ORCPT too long", params: &ravenmail.DSNRecipientParams{ORcpt: "rfc822;" + strings.Repeat("a", 488)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rcpt := ravenmail.Recipient{
				Address:   ravenmail.Path{Mailbox: ravenmail.MailboxAddress{LocalPart: "recipient", Domain: "example.com"}},
				DSNParams: tt.params,
			}
			if _, err := dsnTestClient().rcptToCommand(rcpt, tt.smtpUTF8); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestClientSerializesUTF8OriginalRecipient(t *testing.T) {
	rcpt := ravenmail.Recipient{
		Address: ravenmail.Path{Mailbox: ravenmail.MailboxAddress{LocalPart: "recipient", Domain: "example.com"}},
		DSNParams: &ravenmail.DSNRecipientParams{
			ORcpt: "utf-8;用户@example.com",
		},
	}
	command, err := dsnTestClient().rcptToCommand(rcpt, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(command, "ORCPT=utf-8;用户@example.com") {
		t.Fatalf("RCPT command = %q", command)
	}
}

func TestClientEncodesUTF8OriginalRecipientWithoutSMTPUTF8(t *testing.T) {
	rcpt := ravenmail.Recipient{
		Address: ravenmail.Path{Mailbox: ravenmail.MailboxAddress{LocalPart: "recipient", Domain: "example.com"}},
		DSNParams: &ravenmail.DSNRecipientParams{
			ORcpt: "utf-8;用户@example.com",
		},
	}
	command, err := dsnTestClient().rcptToCommand(rcpt, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(command, `ORCPT=utf-8;\x{7528}\x{6237}@example.com`) {
		t.Fatalf("RCPT command = %q", command)
	}
}

func TestClientDSNProtocolSerialization(t *testing.T) {
	h := &basicSMTPHandler{extensions: []string{"DSN"}}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	c := NewClient(&ClientConfig{LocalName: "localhost", ValidateBeforeSend: false})
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Hello(); err != nil {
		t.Fatal(err)
	}

	message := ravenmail.NewMailBuilder().
		From("sender@example.com").
		To("recipient@example.com").
		Subject("DSN serialization").
		TextBody("body").
		MustBuild()
	message.Envelope.EnvID = "queue one+"
	message.Envelope.DSNParams = &ravenmail.DSNEnvelopeParams{RET: "full"}
	message.Envelope.To[0].DSNParams = &ravenmail.DSNRecipientParams{
		Notify: []string{"success", "failure"},
		ORcpt:  "rfc822;old name+tag@example.com",
	}
	if _, err := c.Send(message); err != nil {
		t.Fatal(err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if !strings.Contains(h.mailFromLine, "RET=FULL ENVID=queue+20one+2B") {
		t.Fatalf("MAIL wire command = %q", h.mailFromLine)
	}
	if len(h.rcptToLines) != 1 || !strings.Contains(h.rcptToLines[0], "NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;old+20name+2Btag@example.com") {
		t.Fatalf("RCPT wire commands = %q", h.rcptToLines)
	}
}

func TestClientDSNProtocolRejectsCRLFBeforeWrite(t *testing.T) {
	h := &basicSMTPHandler{extensions: []string{"DSN"}}
	srv := newMockSMTPServer(t, h.handle)
	defer srv.close()

	c := NewClient(&ClientConfig{LocalName: "localhost", ValidateBeforeSend: false})
	if err := c.Dial(srv.addr()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Hello(); err != nil {
		t.Fatal(err)
	}

	message := ravenmail.NewMailBuilder().
		From("sender@example.com").
		To("recipient@example.com").
		Subject("DSN injection").
		TextBody("body").
		MustBuild()
	message.Envelope.To[0].DSNParams = &ravenmail.DSNRecipientParams{
		ORcpt: "rfc822;recipient@example.com\r\nDATA",
	}
	if _, err := c.Send(message); err == nil {
		t.Fatal("expected CR/LF validation error")
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.mailFromLine != "" || len(h.rcptToLines) != 0 {
		t.Fatalf("invalid envelope wrote commands: MAIL=%q RCPT=%q", h.mailFromLine, h.rcptToLines)
	}
}
