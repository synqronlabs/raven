# Raven

[![Go Reference](https://pkg.go.dev/badge/github.com/synqronlabs/raven.svg)](https://pkg.go.dev/github.com/synqronlabs/raven)

Raven is a high-performance, RFC-compliant SMTP server and client library for Go. It provides a flexible and extensible framework for building mail transfer agents (MTAs), mail submission agents (MSAs), and custom email processing applications.

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

### Using Callbacks

```go
config := raven.DefaultServerConfig()
config.Hostname = "mail.example.com"
config.Addr = ":2525"

config.Callbacks = &raven.Callbacks{
    OnMessage: func(ctx context.Context, conn *raven.Connection, mail *raven.Mail) error {
        log.Printf("Received mail from %s", mail.Envelope.From.String())
        return nil
    },
}

server, _ := raven.NewServer(config)
server.ListenAndServe()
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

```go
// Enable opt-in extensions
server := raven.New("mail.example.com").
    TLS(tlsConfig).                       // Enables STARTTLS
    Auth([]string{"PLAIN"}, authHandler). // Enables AUTH
    MaxMessageSize(25 * 1024 * 1024).     // Enables SIZE
    Extension(raven.DSN()).               // Enables DSN
    Extension(raven.Chunking()).          // Enables CHUNKING/BDAT
    Build()
```

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

## DKIM Signing and Verification

Raven supports DKIM (RFC 6376) for signing outbound messages and verifying inbound messages:

### Signing Outbound Messages

```go
import "crypto/rsa"

// Load your private key
privateKey, _ := loadPrivateKey() // *rsa.PrivateKey

// Build your mail
mail, _ := raven.NewMailBuilder().
    From("sender@example.com").
    To("recipient@example.com").
    Subject("Signed Message").
    TextBody("This message will be DKIM signed.").
    Build()

// Sign with DKIM
err := mail.SignDKIM(&raven.DKIMSignOptions{
    Domain:     "example.com",
    Selector:   "default",
    PrivateKey: privateKey,
})

// Send the signed mail
client.Send(mail)
```

### Verifying Inbound Messages

```go
// Verify DKIM signatures on received mail
results := mail.VerifyDKIM(raven.DefaultDKIMVerifyOptions())

for _, result := range results {
    if result.Status == raven.DKIMStatusPass {
        log.Printf("Valid signature from domain: %s", result.Domain)
    } else {
        log.Printf("DKIM verification failed: %v", result.Error)
    }
}
```

The library uses secure defaults (RSA-SHA256, relaxed canonicalization) and performs DNS lookups to retrieve public keys automatically.

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
├── io/                # I/O utilities
├── mime/              # MIME handling
├── sasl/              # SASL authentication mechanisms
└── utils/             # Utility functions
```

## License

See [LICENSE](LICENSE) for details.
