# Raven

Raven is an idiomatic Go toolkit for ESMTP transport and email authentication protocols.

It includes:
- SMTP server and client primitives.
- Structured message handling, including MIME parsing and multipart serialization.
- SPF, DKIM, DMARC, and ARC verification/signing.
- DNS resolvers with optional DNSSEC authenticity signals.

## Install

```bash
go get github.com/synqronlabs/raven
```

## Package Map

- `arc`: Authenticated Received Chain (RFC 8617)
- `client`: SMTP client and probing utilities
- `dkim`: DKIM signing and verification
- `dmarc`: DMARC lookup and policy evaluation
- `dns`: DNS resolvers with optional DNSSEC awareness and domain validation helpers
- `io`: SMTP-oriented line-reading helpers and ASCII string helpers
- `mail`: Core message model, builder, and MIME parsing/serialization
- `sasl`: SASL LOGIN and PLAIN primitives
- `server`: SMTP server implementation (Backend/Session pattern)
- `spf`: SPF parsing and evaluation

## Quick Start

### Build a message and send via SMTP

```go
msg, err := mail.NewMailBuilder().
    From("sender@example.com").
    To("recipient@example.com").
    Subject("Hello").
    TextBody("Sent with Raven").
    Build()
if err != nil {
    panic(err)
}

dialer := client.NewDialer("smtp.example.com", 587)
dialer.StartTLS = true

c, err := dialer.Dial()
if err != nil {
    panic(err)
}
defer c.Quit()

result, err := c.Send(msg)
if err != nil {
    panic(err)
}
_ = result
```

For prebuilt RFC 5322 messages, stream a raw `.eml` with a caller-supplied
SMTP envelope:

```go
f, err := os.Open("message.eml")
if err != nil {
    panic(err)
}
defer f.Close()

env := mail.Envelope{
    From: mail.Path{Mailbox: mail.MailboxAddress{LocalPart: "sender", Domain: "example.com"}},
    To: []mail.Recipient{
        {Address: mail.Path{Mailbox: mail.MailboxAddress{LocalPart: "recipient", Domain: "example.net"}}},
    },
}

result, err = c.SendRaw(env, f)
if err != nil {
    panic(err)
}
```

### Run an SMTP server

```go
type Backend struct{}

func (b *Backend) NewSession(c *server.Conn) (server.Session, error) {
    return &Session{}, nil
}

type Session struct{}

func (s *Session) Mail(from string, opts *server.MailOptions) error           { return nil }
func (s *Session) Rcpt(to string, opts *server.RcptOptions) error             { return nil }
func (s *Session) Data(headers server.MessageHeaders, body io.Reader) error { return nil }
func (s *Session) Reset()                                                   {}
func (s *Session) Logout() error                                            { return nil }

srv := server.NewServer(&Backend{}, server.ServerConfig{
    Domain:         "mx.example.com",
    Addr:           ":2525",
    EnableSMTPUTF8: true, // Opt in to RFC 6531 support.
})

if err := srv.ListenAndServe(ctx); err != nil {
    panic(err)
}
```

### Verify SPF, DKIM, and DMARC

```go
resolver := dns.NewResolver(dns.ResolverConfig{DNSSEC: true})

spfReceived, spfDomain, _, _, err := spf.Verify(ctx, spf.NewResolver(spf.ResolverConfig{DNSSEC: true}), spf.Args{
    RemoteIP:       remoteIP,
    MailFromDomain: mailFromDomain,
    HelloDomain:    heloDomain,
    LocalHostname:  "mx.example.net",
})
if err != nil {
    panic(err)
}

dkimResults, err := dkim.Verify(ctx, resolver, rawMessage)
if err != nil {
    panic(err)
}

useDMARC, dmarcResult := dmarc.Verify(ctx, resolver, dmarc.VerifyArgs{
    FromDomain:  fromDomain,
    SPFResult:   spfReceived.Result,
    SPFDomain:   spfDomain,
    DKIMResults: dkimResults,
}, true)

_ = useDMARC
_ = dmarcResult
```

## License

MIT License. See `LICENSE`.
