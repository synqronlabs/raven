# Raven

Raven is an idiomatic Go toolkit for ESMTP transport and email authentication protocols.

Raven is server-oriented. Its primary message path keeps RFC 5322 content as a
stream: `server.Session.Data` receives an `io.Reader`, `client.SendRaw` forwards
an `io.Reader`, and DKIM/ARC expose `io.ReaderAt` APIs for seekable message
spools. Structured `mail.Mail` composition remains available for generated
messages, but eager secondary representations are deprecated.

It includes:
- SMTP server and client primitives.
- Streaming MIME traversal plus compatibility helpers for structured messages.
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

See [DEPRECATIONS.md](DEPRECATIONS.md) for eager convenience APIs retained for
compatibility and their streaming replacements.

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

## Performance

Raven's curated benchmarks exercise server-oriented streaming paths entirely in
memory, excluding network, disk, and external DNS latency. These are median
single-stream results from the documented reference host:

| Workload | Time/op | Throughput | B/op | Allocs/op |
| --- | ---: | ---: | ---: | ---: |
| SMTP DATA receive, 1 MiB | 205 µs | 5.12 GB/s | 4,352 | 4 |
| SMTP DATA send, 1 MiB | 987 µs | 1.06 GB/s | 0 | 0 |
| SMTP BDAT receive, 1 MiB / 64 KiB chunks | 90.6 µs | 11.6 GB/s | 48,449 | 148 |
| SMTP BDAT send, 1 MiB / 64 KiB chunks | 22.9 µs | 45.9 GB/s | 4,176 | 167 |
| Streaming MIME walk, 1 MiB | 159 µs | 6.58 GB/s | 8,008 | 48 |
| DKIM RSA-2048 `SignReader`, 1 MiB | 2.15 ms | 487 MB/s | 18,033 | 168 |
| DKIM RSA-2048 `VerifyReader`, 1 MiB | 1.86 ms | 563 MB/s | 3,169,775 | 214 |
| ARC RSA-2048 `SealReader`, 1 MiB | 3.14 ms | 334 MB/s | 28,472 | 227 |
| ARC RSA-2048 `VerifyReader`, 1 MiB | 1.66 ms | 634 MB/s | 42,944 | 277 |
| SPF pass with include | 3.73 µs | — | 2,928 | 67 |
| DMARC aligned pass | 1.61 µs | — | 864 | 15 |

Hardware, methodology, larger-message scaling, and reproduction commands are
documented in [BENCHMARKS.md](BENCHMARKS.md). Absolute timings are specific to
the reference environment.

Parallel 1 MiB workloads on the 22-thread reference workstation scaled to
approximately 9.22 GB/s for DATA send, 49.5 GB/s for DATA receive, 50.3 GB/s
for MIME traversal, 4.31 GB/s for DKIM verification, and 5.42 GB/s for ARC
verification. Transport and MIME peaked around 16 workers; authentication
continued scaling through 22. These are in-memory aggregate rates, not network
throughput measurements.

The primary objective for the benchmarks is to prove that Raven’s protocol layer
will not be the primary performance blocker across parallel SMTP connections in
a production environment.

## License

MIT License. See `LICENSE`.
