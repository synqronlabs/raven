# Raven

[![Go Reference](https://pkg.go.dev/badge/github.com/synqronlabs/raven.svg)](https://pkg.go.dev/github.com/synqronlabs/raven)

Raven is a high-performance, RFC-compliant SMTP server library for Go. It provides a flexible and extensible framework for building mail transfer agents (MTAs), mail submission agents (MSAs), and custom email processing applications.

## Features

- **Full RFC 5321 Compliance**: Complete SMTP protocol implementation
- **Modern Extensions**: STARTTLS, AUTH, 8BITMIME, SMTPUTF8, PIPELINING, SIZE, DSN, CHUNKING
- **Flexible Callbacks**: Hook into every stage of the SMTP transaction
- **Resource Limits**: Built-in protection with configurable limits
- **Concurrent Handling**: Efficiently handles multiple simultaneous connections
- **Structured Logging**: Integration with Go's `slog` package
- **Security**: SMTP smuggling protection, TLS support, SASL authentication

## Installation

```bash
go get github.com/synqronlabs/raven
```

## Quick Start

```go
package main

import (
    "context"
    "log"

    "github.com/synqronlabs/raven"
)

func main() {
    config := raven.DefaultServerConfig()
    config.Hostname = "mail.example.com"
    config.Addr = ":2525"
    
    config.Callbacks = &raven.Callbacks{
        OnMessage: func(ctx context.Context, conn *raven.Connection, mail *raven.Mail) error {
            log.Printf("Received mail from %s", mail.Envelope.From.String())
            return nil
        },
    }

    server, err := raven.NewServer(config)
    if err != nil {
        log.Fatal(err)
    }

    log.Fatal(server.ListenAndServe())
}
```

## Documentation

- **[API Reference](https://pkg.go.dev/github.com/synqronlabs/raven)** - Complete API documentation on pkg.go.dev
- **[Examples](https://pkg.go.dev/github.com/synqronlabs/raven#pkg-examples)** - Code examples for common use cases
- **[Additional Guides](doc/)** - In-depth guides for specific topics:
  - [Getting Started Guide](doc/getting-started.md) - Detailed walkthrough
  - [Configuration Reference](doc/configuration.md) - All configuration options
  - [Callbacks Guide](doc/callbacks.md) - Event handling
  - [TLS & Authentication](doc/tls-and-auth.md) - Security setup
  - [DANE Support](doc/dane.md) - DANE/TLSA configuration
  - [Examples Collection](doc/examples.md) - Complete working examples


## Key Concepts

### Server Configuration

The `ServerConfig` structure provides all configuration options:

```go
config := raven.DefaultServerConfig()
config.Hostname = "mail.example.com"      // Required: server hostname
config.Addr = ":587"                       // Submission port
config.MaxMessageSize = 10 * 1024 * 1024   // 10 MB limit
config.MaxRecipients = 100                 // Max recipients per message
config.RequireTLS = true                   // Require TLS before auth
config.RequireAuth = true                  // Require authentication
```

### Callbacks

Implement callbacks to control SMTP behavior:

```go
config.Callbacks = &raven.Callbacks{
    OnConnect: func(ctx context.Context, conn *raven.Connection) error {
        // Called when client connects (return error to reject)
    },
    OnMailFrom: func(ctx context.Context, conn *raven.Connection, from raven.Path, params map[string]string) error {
        // Validate sender
    },
    OnRcptTo: func(ctx context.Context, conn *raven.Connection, to raven.Path, params map[string]string) error {
        // Validate recipient
    },
    OnMessage: func(ctx context.Context, conn *raven.Connection, mail *raven.Mail) error {
        // Process received message
    },
}
```

### TLS Support

Enable STARTTLS for secure connections:

```go
cert, _ := tls.LoadX509KeyPair("server.crt", "server.key")
config.TLSConfig = &tls.Config{
    Certificates: []tls.Certificate{cert},
    MinVersion:   tls.VersionTLS12,
}
```

For implicit TLS (SMTPS on port 465):

```go
server.ListenAndServeTLS()
```

### Authentication

Implement the `OnAuth` callback to validate credentials:

```go
config.Callbacks = &raven.Callbacks{
    OnAuth: func(ctx context.Context, conn *raven.Connection, mechanism, identity, password string) error {
        // Validate identity and password
        if !isValid(identity, password) {
            return errors.New("invalid credentials")
        }
        return nil
    },
}
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
