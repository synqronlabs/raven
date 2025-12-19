# Raven

[![Go Reference](https://pkg.go.dev/badge/github.com/synqronlabs/raven.svg)](https://pkg.go.dev/github.com/synqronlabs/raven)

Raven is a high-performance, RFC-compliant ESMTP server and client library for Go. It provides a flexible and extensible framework for building mail transfer agents (MTAs), mail submission agents (MSAs), and custom email processing applications.

## Installation

```bash
go get github.com/synqronlabs/raven
```

## Quick Start

```go
package main

import (
    "log"
    "log/slog"
    "os"

    "github.com/synqronlabs/raven"
)

func main() {
    logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

    server, err := raven.New("mail.example.com").
        Addr(":2525").
        Logger(logger).
        MaxMessageSize(10 * 1024 * 1024). // 10MB
        Use(raven.SecureDefaults(logger)...).
        OnConnect(func(ctx *raven.Context) error {
            logger.Info("connection", "remote", ctx.RemoteAddr())
            return nil
        }).
        OnMessage(func(ctx *raven.Context) error {
            logger.Info("message received",
                "from", ctx.Mail.Envelope.From.String(),
                "recipients", len(ctx.Mail.Envelope.To))
            return nil
        }).
        Build()

    if err != nil {
        log.Fatal(err)
    }

    if err := server.ListenAndServe(); err != raven.ErrServerClosed {
        log.Fatal(err)
    }
}
```

## SMTP Extensions

Raven categorizes extensions into **intrinsic** (always enabled) and **opt-in** (must be enabled manually):

### Intrinsic Extensions (Always Enabled)

| Extension | RFC | Description |
|-----------|-----|-------------|
| ENHANCEDSTATUSCODES | RFC 2034 | Detailed error codes |
| 8BITMIME | RFC 6152 | 8-bit content support |
| SMTPUTF8 | RFC 6531 | Internationalized email |
| PIPELINING | RFC 2920 | Command pipelining |
| REQUIRETLS | RFC 8689 | Require TLS for message transmission (advertised after STARTTLS) |

### Opt-in Extensions

| Extension | RFC | How to Enable |
|-----------|-----|---------------|
| STARTTLS | RFC 3207 | `.TLS(tlsConfig)` |
| AUTH | RFC 4954 | `.Auth(mechanisms, handler)` |
| SIZE | RFC 1870 | `.MaxMessageSize(size)` |
| DSN | RFC 3461 | `.Extension(raven.DSN())` |
| CHUNKING | RFC 3030 | `.Extension(raven.Chunking())` |

## Documentation

- **[API Reference](https://pkg.go.dev/github.com/synqronlabs/raven)** - Complete API documentation

## Middleware

Built-in middleware for common functionality:

```go
server := raven.New("mail.example.com").
    Use(
        raven.Recovery(logger),           // Panic recovery
        raven.Logger(logger),             // Request logging
        raven.RateLimit(rateLimiter),     // Rate limiting
        raven.IPFilterMiddleware(filter), // IP filtering
    ).
    Build()

// Or use preset groups
server := raven.New("mail.example.com").
    Use(raven.SecureDefaults(logger)...).
    Build()
```

## Handler Chaining

Chain multiple handlers for complex validation:

```go
server := raven.New("mail.example.com").
    OnRcptTo(
        validateDomain,     // Check domain
        checkRateLimit,     // Check limits  
        lookupMailbox,      // Verify mailbox
    ).
    Build()

func validateDomain(ctx *raven.Context) error {
    to := ctx.Keys["to"].(raven.Path)
    if to.Mailbox.Domain != "example.com" {
        return errors.New("relay not permitted")
    }
    return ctx.Next() // Continue to next handler
}
```

## SMTP Client

Raven includes a full-featured SMTP client with extension support, connection pooling, and a fluent mail builder API.

### Quick Send

```go
// Simplest way to send an email
err := raven.QuickSend(
    "smtp.example.com:587",
    &raven.ClientAuth{Username: "user", Password: "pass"},
    "sender@example.com",
    []string{"recipient@example.com"},
    "Hello",
    "This is the message body.",
)
```

### Mail Builder

Build emails fluently with full RFC compliance:

```go
mail, err := raven.NewMailBuilder().
    From("Sender Name <sender@example.com>").
    To("recipient1@example.com", "recipient2@example.com").
    Cc("cc@example.com").
    ReplyTo("reply@example.com").
    Subject("Meeting Tomorrow").
    TextBody("Don't forget the meeting!").
    Priority(1). // High priority
    Build()
```

### Client with Extension Probing

```go
// Create client
client := raven.NewClient(&raven.ClientConfig{
    LocalName: "client.example.com",
    Auth: &raven.ClientAuth{
        Username: "user",
        Password: "password",
    },
})

// Connect and probe server
client.Dial("smtp.example.com:587")
client.Hello()

// Check available extensions
caps := client.Capabilities()
if caps.TLS {
    client.StartTLS()
    client.Hello() // Re-EHLO after STARTTLS
}

if client.HasExtension(raven.ExtAuth) {
    client.Auth()
}

// Send mail
result, err := client.Send(mail)
client.Quit()
```

### Probe Server Capabilities

```go
// Discover what a server supports without sending mail
caps, err := raven.Probe("smtp.example.com:25")
fmt.Println(caps.String())

// Probe with STARTTLS upgrade
caps, err := raven.ProbeWithSTARTTLS("smtp.example.com:587")
```

### Connection Pooling

```go
// Create a dialer for connection reuse
dialer := raven.NewDialer("smtp.example.com", 587)
dialer.Auth = &raven.ClientAuth{Username: "user", Password: "pass"}
dialer.StartTLS = true

// Create pool
pool := raven.NewPool(dialer, 5)
defer pool.Close()

// Send messages efficiently
for _, mail := range mails {
    result, err := pool.Send(mail)
}
```

### Advanced Features

```go
// DSN (Delivery Status Notifications)
mail, _ := raven.NewMailBuilder().
    From("sender@example.com").
    To("recipient@example.com").
    Subject("Important").
    TextBody("Please confirm receipt").
    DSN([]string{"SUCCESS", "FAILURE"}, "FULL"). // Request full DSN
    EnvID("tracking-123").
    Build()

// Streaming large messages
reader := bytes.NewReader(largeMessage)
resp, err := client.StreamData(reader)

// Command pipelining
responses, err := client.PipelineCommands([]string{
    "MAIL FROM:<sender@example.com>",
    "RCPT TO:<rcpt1@example.com>",
    "RCPT TO:<rcpt2@example.com>",
})
```

## Serialization

Raven supports both JSON and MessagePack serialization for Mail objects.

### JSON Serialization

```go
// Serialize to JSON
jsonData, err := mail.ToJSON()
if err != nil {
    log.Fatal(err)
}

// Deserialize from JSON
mail, err := raven.FromJSON(jsonData)
if err != nil {
    log.Fatal(err)
}
```

### MessagePack Serialization

MessagePack provides more compact binary serialization compared to JSON, which is useful for storage and transmission of mail objects:

```go
// Serialize to MessagePack
msgpackData, err := mail.ToMessagePack()
if err != nil {
    log.Fatal(err)
}

// Deserialize from MessagePack
mail, err := raven.FromMessagePack(msgpackData)
if err != nil {
    log.Fatal(err)
}
```

## Email Authentication

Raven includes subpackages for email authentication: DKIM, DMARC, SPF, and a flexible DNS resolver.

### DNS Package

The `dns` package provides DNS resolution with optional DNSSEC validation support, used by SPF, DKIM, and DMARC authentication.

```go
import "github.com/synqronlabs/raven/dns"

// Create a DNSSEC-enabled resolver
resolver := dns.NewResolver(dns.ResolverConfig{
    Nameservers: []string{"8.8.8.8:53", "1.1.1.1:53"},
    DNSSEC:      true,
    Timeout:     5 * time.Second,
})

// Lookup TXT records
result, err := resolver.LookupTXT(ctx, "example.com")
if err != nil {
    if dns.IsNotFound(err) {
        // No records found
    } else if dns.IsTemporary(err) {
        // Temporary error, retry later
    }
}
for _, txt := range result.Records {
    fmt.Println(txt)
}
if result.Authentic {
    fmt.Println("Response was DNSSEC-validated")
}

// Simple resolver without DNSSEC (uses standard library)
stdResolver := dns.NewStdResolver()
```

### DKIM Package

The `dkim` package implements DomainKeys Identified Mail (RFC 6376) for signing and verifying email messages.

**Supported Algorithms:**
- RSA-SHA256 (required by RFC 6376)
- RSA-SHA1 (deprecated, for compatibility)
- Ed25519-SHA256 (RFC 8463)
- ECDSA-SHA256 (P-256, P-384, P-521 curves)

#### Signing Messages

```go
import "github.com/synqronlabs/raven/dkim"

// Load your private key
privateKey, _ := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)

// Create a signer
signer := &dkim.Signer{
    Domain:                 "example.com",
    Selector:               "selector1",
    PrivateKey:             privateKey,
    Headers:                dkim.DefaultSignedHeaders, // Optional
    HeaderCanonicalization: dkim.CanonRelaxed,
    BodyCanonicalization:   dkim.CanonRelaxed,
    Expiration:             7 * 24 * time.Hour, // Optional: signature expires in 7 days
}

// Sign the message
signature, err := signer.Sign(rawMessage)
if err != nil {
    log.Fatal(err)
}

// Prepend signature to message
signedMessage := signature + "\r\n" + string(rawMessage)
```

#### Verifying Messages

```go
import (
    "github.com/synqronlabs/raven/dkim"
    "github.com/synqronlabs/raven/dns"
)

resolver := dns.NewResolver(dns.ResolverConfig{DNSSEC: true})

verifier := &dkim.Verifier{
    Resolver:      resolver,
    MinRSAKeyBits: 1024, // Reject weak keys
}

results, err := verifier.Verify(ctx, rawMessage)
for _, r := range results {
    switch r.Status {
    case dkim.StatusPass:
        fmt.Printf("DKIM pass for domain: %s\n", r.Signature.Domain)
    case dkim.StatusFail:
        fmt.Printf("DKIM failed: %v\n", r.Err)
    case dkim.StatusTemperror:
        fmt.Println("Temporary error (e.g., DNS timeout)")
    case dkim.StatusPermerror:
        fmt.Println("Permanent error (e.g., invalid signature)")
    }
}
```

#### DKIM Middleware

```go
import (
    "github.com/synqronlabs/raven"
    "github.com/synqronlabs/raven/dkim"
    "github.com/synqronlabs/raven/dns"
)

resolver := dns.NewResolver(dns.ResolverConfig{DNSSEC: true})

server := raven.New("mx.example.com").
    Use(dkim.Middleware(dkim.MiddlewareConfig{
        Resolver:         resolver,
        Logger:           logger,
        RejectOnFail:     false, // Add Authentication-Results header but don't reject
        RequireSignature: false, // Allow unsigned messages
        MinRSAKeyBits:    1024,
    })).
    Build()

// Access DKIM results in your handler
server.OnMessage(func(ctx *raven.Context) error {
    if results, ok := ctx.Keys[dkim.ContextKeyDKIMResults].([]dkim.Result); ok {
        for _, r := range results {
            if r.Status == dkim.StatusPass {
                log.Printf("Valid DKIM signature from %s", r.Signature.Domain)
            }
        }
    }
    return nil
})
```

### SPF Package

The `spf` package implements Sender Policy Framework (RFC 7208) for verifying that sending servers are authorized to send mail for a domain.

**SPF Result Statuses:**

| Status | Description |
|--------|-------------|
| `StatusPass` | IP is authorized to send for the domain |
| `StatusFail` | IP is explicitly not authorized |
| `StatusSoftfail` | IP is probably not authorized (weak statement) |
| `StatusNeutral` | Domain makes no assertion about the IP |
| `StatusNone` | No SPF record found |
| `StatusTemperror` | Temporary error (e.g., DNS timeout) |
| `StatusPermerror` | Permanent error (e.g., invalid SPF record) |

#### Verifying SPF

```go
import "github.com/synqronlabs/raven/spf"

// Create resolver with DNSSEC support
resolver := spf.NewResolver(spf.ResolverConfig{
    DNSSEC: true,
})

// Or use defaults (system nameservers, DNSSEC enabled)
resolver := spf.NewResolverWithDefaults()

// Verify SPF for an incoming message
args := spf.Args{
    RemoteIP:       net.ParseIP("192.0.2.1"),    // Sender's IP
    MailFromDomain: "example.com",               // Domain from MAIL FROM
    MailFromLocal:  "sender",                    // Local part from MAIL FROM
    HelloDomain:    "mail.example.com",          // EHLO/HELO domain
    LocalHostname:  "mx.myserver.com",           // Receiving server hostname
}

received, err := spf.Verify(ctx, resolver, args)
if err != nil {
    log.Printf("SPF verification error: %v", err)
}

switch received.Result {
case spf.StatusPass:
    fmt.Println("SPF passed - sender is authorized")
case spf.StatusFail:
    fmt.Printf("SPF failed - sender not authorized: %s\n", received.Problem)
case spf.StatusSoftfail:
    fmt.Println("SPF softfail - treat with suspicion")
case spf.StatusNone:
    fmt.Println("No SPF record found")
}

// Generate Received-SPF header
header := received.Header()
// Output: Received-SPF: pass client-ip=192.0.2.1; envelope-from=sender@example.com; ...
```

#### SPF Middleware

```go
import (
    "github.com/synqronlabs/raven"
    "github.com/synqronlabs/raven/spf"
)

resolver := spf.NewResolverWithDefaults()

server := raven.New("mx.example.com").
    Use(spf.Middleware(spf.MiddlewareConfig{
        Resolver: resolver,
        Logger:   logger,
        Policy:   spf.PolicyRejectFail, // Reject on hard fail
        Timeout:  20 * time.Second,
    })).
    Build()

// Access SPF results in your handler
server.OnMessage(func(ctx *raven.Context) error {
    if status, ok := ctx.Keys[spf.ContextKeySPFStatus].(spf.Status); ok {
        if status == spf.StatusPass {
            log.Println("SPF verification passed")
        }
    }
    if domain, ok := ctx.Keys[spf.ContextKeySPFDomain].(string); ok {
        log.Printf("Checked SPF for domain: %s", domain)
    }
    return nil
})
```

**SPF Middleware Policies:**

| Policy | Behavior |
|--------|----------|
| `PolicyMark` | Add Received-SPF header, never reject |
| `PolicyRejectFail` | Reject on SPF `fail` result |
| `PolicyRejectFailAndSoftfail` | Reject on `fail` and `softfail` |
| `PolicyRejectAll` | Reject anything that isn't `pass` or `none` |

### DMARC Package

The `dmarc` package implements Domain-based Message Authentication, Reporting, and Conformance (RFC 7489).

#### Looking Up DMARC Policy

```go
import (
    "github.com/synqronlabs/raven/dmarc"
    "github.com/synqronlabs/raven/dns"
)

resolver := dns.NewResolver(dns.ResolverConfig{DNSSEC: true})

status, domain, record, txt, authentic, err := dmarc.Lookup(ctx, resolver, "sender.example.com")
if record != nil {
    fmt.Printf("DMARC policy for %s:\n", domain)
    fmt.Printf("  Policy: %s\n", record.Policy)           // none, quarantine, reject
    fmt.Printf("  Subdomain Policy: %s\n", record.SubdomainPolicy)
    fmt.Printf("  SPF Alignment: %s\n", record.ASPF)      // r (relaxed) or s (strict)
    fmt.Printf("  DKIM Alignment: %s\n", record.ADKIM)
    fmt.Printf("  Percentage: %d%%\n", record.Percentage) // pct= field
}
```

#### Verifying DMARC

```go
import (
    "github.com/synqronlabs/raven/dkim"
    "github.com/synqronlabs/raven/dmarc"
    "github.com/synqronlabs/raven/spf"
)

// First, run SPF and DKIM checks
spfResult := spf.StatusPass // Result from SPF check
dkimResults := []dkim.Result{...} // Results from DKIM verification

// Then verify DMARC
useResult, result := dmarc.Verify(ctx, resolver, dmarc.VerifyArgs{
    FromDomain:  "sender.example.com",
    SPFResult:   spfResult,
    SPFDomain:   "sender.example.com", // MAIL FROM domain
    DKIMResults: dkimResults,
}, true) // applyRandomPercentage honors the pct= field

if result.Status == dmarc.StatusPass {
    fmt.Println("DMARC passed!")
    if result.AlignedSPFPass {
        fmt.Println("  - SPF aligned and passed")
    }
    if result.AlignedDKIMPass {
        fmt.Println("  - DKIM aligned and passed")
    }
} else if result.Reject {
    fmt.Printf("DMARC failed, policy=%s recommends rejection\n", result.Record.Policy)
}
```

#### DMARC Middleware

The DMARC middleware should be used **after** SPF and DKIM middleware:

```go
import (
    "github.com/synqronlabs/raven"
    "github.com/synqronlabs/raven/dkim"
    "github.com/synqronlabs/raven/dmarc"
    "github.com/synqronlabs/raven/dns"
    "github.com/synqronlabs/raven/spf"
)

resolver := dns.NewResolver(dns.ResolverConfig{DNSSEC: true})

server := raven.New("mx.example.com").
    Use(
        spf.Middleware(spf.MiddlewareConfig{Resolver: resolver}),   // Run first
        dkim.Middleware(dkim.MiddlewareConfig{Resolver: resolver}), // Run second
        dmarc.Middleware(dmarc.MiddlewareConfig{                    // Run last
            Resolver: resolver,
            Logger:   logger,
            Policy:   dmarc.MiddlewarePolicyEnforce, // Enforce published DMARC policy
        }),
    ).
    Build()
```

**DMARC Middleware Policies:**

| Policy | Behavior |
|--------|----------|
| `MiddlewarePolicyMark` | Add Authentication-Results header, never reject |
| `MiddlewarePolicyEnforce` | Reject messages when DMARC policy is `reject` |
| `MiddlewarePolicyStrict` | Reject all messages that fail DMARC |

#### Utility Functions

```go
// Get the organizational domain using the Public Suffix List
orgDomain := dmarc.OrganizationalDomain("mail.sub.example.com") // Returns "example.com"

// Check domain alignment
aligned := dmarc.DomainsAligned("mail.example.com", "example.com", dmarc.AlignRelaxed) // true
aligned = dmarc.DomainsAligned("mail.example.com", "example.com", dmarc.AlignStrict)   // false
```

## Project Structure

The codebase is organized with clear file naming for easy navigation:

```
raven/
├── raven.go           # Package documentation and overview
├── server.go          # Server type and lifecycle methods
├── server_config.go   # Server configuration options
├── server_builder.go  # Fluent builder API for server setup
├── server_handler.go  # SMTP command handlers
├── server_conn.go     # Connection state and management
├── server_auth.go     # Authentication handling
├── server_test.go     # Server integration tests
├── client.go          # SMTP client core
├── client_dialer.go   # Connection dialing and pooling
├── client_probe.go    # Server capability probing
├── client_send.go     # Mail sending logic
├── mail.go            # Mail and envelope types
├── mail_builder.go    # Fluent mail builder API
├── mail_test.go       # Mail builder tests
├── response.go        # SMTP response codes and types
├── extensions.go      # SMTP extension definitions
├── middleware.go      # Built-in middleware
├── parser.go          # SMTP command parser
├── dkim/              # DKIM signing and verification (RFC 6376)
├── dmarc/             # DMARC policy evaluation (RFC 7489)
├── dns/               # DNS resolution with DNSSEC support
├── io/                # I/O utilities
├── mime/              # MIME handling
├── sasl/              # SASL authentication mechanisms
├── spf/               # SPF verification (RFC 7208)
└── utils/             # Utility functions
```

## License

See [LICENSE](LICENSE) for details.