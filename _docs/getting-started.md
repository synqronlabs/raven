# Getting Started

## Installation

```bash
go get github.com/synqronlabs/raven
```

Raven is a multi-package module. Import only the sub-packages you need:

```go
import (
    "github.com/synqronlabs/raven/mail"
    "github.com/synqronlabs/raven/client"
    "github.com/synqronlabs/raven/server"
    // ... etc.
)
```

MIME parsing and multipart serialization now live in `github.com/synqronlabs/raven/mail`; there is no separate Raven `mime` package to import.

## Sending a Message

### 1. Build the message

```go
msg, err := mail.NewMailBuilder().
    From("alice@example.com").
    To("bob@example.net").
    Subject("Hello from Raven").
    TextBody("This is a plain-text message sent with Raven.").
    Build()
if err != nil {
    log.Fatal(err)
}
```

The builder sets required RFC 5322 headers (`Date`, `From`), normalises line
endings to CRLF, and validates everything at `Build()` time.

### 2. Send with the Dialer (high-level)

```go
dialer := client.NewDialer("smtp.example.com", 587)
dialer.StartTLS = true
dialer.Auth = &client.ClientAuth{
    Username: "alice@example.com",
    Password: "app-password",
}

result, err := dialer.DialAndSend(msg)
if err != nil {
    log.Fatal(err)
}
fmt.Println("Sent:", result.Success)
```

`DialAndSend` opens a connection, performs EHLO, STARTTLS, AUTH, sends the
message, and issues QUIT — all in one call.

## Inspecting MIME Content

Use the `mail` package when you need to inspect or rewrite structured content:

```go
part, err := msg.Content.ToMIME()
if err != nil {
    log.Fatal(err)
}

if part.IsMultipart() {
    fmt.Printf("root media type: %s (%d child parts)\n", part.ContentType, len(part.Parts))
}

if err := msg.Content.FromMIME(part); err != nil {
    log.Fatal(err)
}
```

### 3. Send with the Client (low-level)

```go
c, err := dialer.Dial()
if err != nil {
    log.Fatal(err)
}
defer c.Quit()

res, err := c.Send(msg)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Message ID: %s\n", res.MessageID)
```

## Running an SMTP Server

### 1. Implement Backend and Session

```go
type MyBackend struct{}

func (b *MyBackend) NewSession(c *server.Conn) (server.Session, error) {
    fmt.Printf("Connection from %s\n", c.RemoteAddr())
    return &MySession{}, nil
}

type MySession struct {
    from string
    to   []string
}

func (s *MySession) Mail(from string, opts *server.MailOptions) error {
    s.from = from
    return nil
}

func (s *MySession) Rcpt(to string, opts *server.RcptOptions) error {
    s.to = append(s.to, to)
    return nil
}

func (s *MySession) Data(r io.Reader) error {
    body, _ := io.ReadAll(r)
    fmt.Printf("Message from %s to %v: %d bytes\n", s.from, s.to, len(body))
    return nil
}

func (s *MySession) Reset()        {}
func (s *MySession) Logout() error { return nil }
```

### 2. Start the server

```go
srv := server.NewServer(&MyBackend{}, server.ServerConfig{
    Domain: "mx.example.com",
    Addr:   ":2525",
})

ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
defer cancel()

if err := srv.ListenAndServe(ctx); err != nil && err != server.ErrServerClosed {
    log.Fatal(err)
}
```

The context controls graceful shutdown — cancel it or send `SIGINT` and the
server drains connections.

## DKIM Signing

```go
import "github.com/synqronlabs/raven/dkim"

// Load your RSA or Ed25519 private key
privKey, _ := loadPrivateKey("selector._domainkey.example.com.pem")

err := dkim.QuickSign(msg, "example.com", "selector", privKey)
if err != nil {
    log.Fatal(err)
}

// msg now has a DKIM-Signature header; send it with client.Send()
```

## SPF Verification

```go
import "github.com/synqronlabs/raven/spf"

resolver := spf.NewResolverWithDefaults()

status, domain, explanation, authentic, err := spf.Verify(ctx, resolver, spf.Args{
    RemoteIP:       net.ParseIP("198.51.100.42"),
    MailFromDomain: "example.com",
    HelloDomain:    "mail.example.com",
    LocalHostname:  "mx.receiver.net",
})

fmt.Printf("SPF %s for %s (DNSSEC: %v)\n", status, domain, authentic)
if status == spf.StatusFail {
    fmt.Println("Explanation:", explanation)
}
```

## DKIM Verification

```go
import (
    "github.com/synqronlabs/raven/dkim"
    "github.com/synqronlabs/raven/dns"
)

resolver := dns.NewResolver(dns.ResolverConfig{DNSSEC: true})

results, err := dkim.VerifyMailContext(ctx, msg, resolver)
if err != nil {
    log.Fatal(err)
}

for _, r := range results {
    fmt.Printf("DKIM %s (d=%s s=%s)\n", r.Status, r.Signature.Domain, r.Signature.Selector)
}
```

## DMARC Evaluation

```go
import "github.com/synqronlabs/raven/dmarc"

result, useResult, err := dmarc.VerifyMailObject(ctx, resolver, msg, dmarc.MailVerifyArgs{
    SPFResult:   spfStatus,
    SPFDomain:   spfDomain,
    DKIMResults: dkimResults,
})

if useResult && result.Reject {
    fmt.Println("DMARC policy says reject")
}
```

## ARC Chain Verification and Sealing

```go
import "github.com/synqronlabs/raven/arc"

// Verify existing ARC chain
arcResult, err := arc.VerifyMailContext(ctx, msg, resolver)
chainStatus := arc.GetARCChainStatus(arcResult)

// Seal with your own ARC set
err = arc.QuickSeal(msg,
    "relay.example.com",  // domain
    "arc1",               // selector
    privKey,              // signing key
    "relay.example.com",  // authserv-id
    "spf=pass; dkim=pass; dmarc=pass",  // auth results
    chainStatus,
)
```

## What's Next?

- See [architecture.md](architecture.md) for the full package map and dependency
  graph.
- See [motivation.md](motivation.md) for design rationale.
- Explore the `_examples/` directory for complete, runnable programs that mock
  production setups (MUA, MSA, MX server, authentication pipeline).
