# Raven

[![Go Reference](https://pkg.go.dev/badge/github.com/synqronlabs/raven.svg)](https://pkg.go.dev/github.com/synqronlabs/raven)

Raven is a high-performance, RFC-compliant SMTP server library for Go. It provides a flexible and extensible framework for building mail transfer agents (MTAs), mail submission agents (MSAs), and custom email processing applications.

## Features

- **Full RFC 5321 Compliance**: Complete SMTP protocol implementation
- **Fluent Builder API**: Gin-style chainable configuration and handler registration
- **Modern Extensions**: STARTTLS, AUTH, 8BITMIME, SMTPUTF8, PIPELINING, SIZE, DSN, CHUNKING
- **Middleware Support**: Composable middleware for logging, rate limiting, IP filtering
- **Handler Chaining**: Multiple handlers per event with `ctx.Next()` pattern
- **Resource Limits**: Built-in protection with configurable limits
- **Concurrent Handling**: Efficiently handles multiple simultaneous connections
- **Structured Logging**: Integration with Go's `slog` package
- **Security**: SMTP smuggling protection, TLS support, SASL authentication

## Installation

```bash
go get github.com/synqronlabs/raven
```

## Quick Start

### Builder API (Recommended)

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

    log.Fatal(server.ListenAndServe())
}
```

### Traditional Callbacks API

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

Raven categorizes extensions into **intrinsic** (always enabled) and **opt-in** (must be enabled):

### Intrinsic Extensions (Always Enabled)

| Extension | RFC | Description |
|-----------|-----|-------------|
| ENHANCEDSTATUSCODES | RFC 2034 | Detailed error codes |
| 8BITMIME | RFC 6152 | 8-bit content support |
| SMTPUTF8 | RFC 6531 | Internationalized email |
| PIPELINING | RFC 2920 | Command pipelining |

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
- **[API Guide](doc/api-guide.md)** - Builder API and middleware guide
- **[Getting Started](doc/getting-started.md)** - Detailed walkthrough
- **[Configuration](doc/configuration.md)** - All configuration options
- **[Callbacks](doc/callbacks.md)** - Event handling reference
- **[TLS & Auth](doc/tls-and-auth.md)** - Security setup
- **[Examples](doc/examples.md)** - Complete working examples

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

## Complete Example: Mail Submission Agent

```go
server, _ := raven.New("smtp.example.com").
    Addr(":587").
    Logger(logger).
    TLS(tlsConfig).
    RequireTLS().
    Auth([]string{"PLAIN", "LOGIN"}, authenticate).
    RequireAuth().
    MaxMessageSize(25 * 1024 * 1024).
    Extension(raven.DSN()).
    Use(raven.SecureDefaults(logger)...).
    OnMailFrom(raven.ValidateSender(domains)).
    OnRcptTo(raven.ValidateRecipient(domains)).
    OnMessage(queueForDelivery).
    Build()
```

## RFC Compliance

Raven implements the following RFCs:

- **RFC 5321** - Simple Mail Transfer Protocol
- **RFC 3207** - SMTP Service Extension for Secure SMTP over TLS
- **RFC 4954** - SMTP Service Extension for Authentication
- **RFC 6152** - SMTP Service Extension for 8-bit MIME Transport
- **RFC 6531** - SMTP Extension for Internationalized Email
- **RFC 2920** - SMTP Service Extension for Command Pipelining
- **RFC 1870** - SMTP Service Extension for Message Size Declaration
- **RFC 3461** - SMTP Service Extension for Delivery Status Notifications
- **RFC 3030** - SMTP Service Extensions for Large and Binary MIME Messages
- **RFC 2034** - SMTP Service Extension for Returning Enhanced Error Codes

## License

See [LICENSE](LICENSE) for details.
