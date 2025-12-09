# Getting Started with Raven

This guide will walk you through setting up your first SMTP server using Raven.

## Installation

```bash
go get github.com/synqronlabs/raven
```

## Basic Server Setup

### Minimal Example

The simplest SMTP server requires only a hostname:

```go
package main

import (
    "log"

    "github.com/synqronlabs/raven"
)

func main() {
    config := raven.DefaultServerConfig()
    config.Hostname = "mail.example.com"

    server, err := raven.NewServer(config)
    if err != nil {
        log.Fatal(err)
    }

    log.Println("Starting SMTP server on :25")
    log.Fatal(server.ListenAndServe())
}
```

This creates a server that:
- Listens on port 25
- Accepts all incoming mail (but doesn't store it anywhere)
- Supports PIPELINING, 8BITMIME, SMTPUTF8, and Enhanced Status Codes

### Handling Incoming Messages

To actually process received emails, add an `OnMessage` callback:

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/synqronlabs/raven"
)

func main() {
    config := raven.DefaultServerConfig()
    config.Hostname = "mail.example.com"
    config.Addr = ":2525" // Use non-privileged port for development

    config.Callbacks = &raven.Callbacks{
        OnMessage: func(ctx context.Context, conn *raven.Connection, mail *raven.Mail) error {
            fmt.Printf("=== New Message ===\n")
            fmt.Printf("From: %s\n", mail.Envelope.From.String())
            fmt.Printf("To: ")
            for i, rcpt := range mail.Envelope.To {
                if i > 0 {
                    fmt.Printf(", ")
                }
                fmt.Printf("%s", rcpt.Address.String())
            }
            fmt.Printf("\n")
            fmt.Printf("Size: %d bytes\n", len(mail.Raw))
            fmt.Printf("Message ID: %s\n", mail.ID)
            fmt.Println("==================")
            return nil
        },
    }

    server, err := raven.NewServer(config)
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Starting SMTP server on %s", config.Addr)
    log.Fatal(server.ListenAndServe())
}
```

### Testing Your Server

You can test your server using `telnet` or `nc`:

```bash
telnet localhost 2525
```

Then type the following SMTP commands:

```
EHLO client.example.com
MAIL FROM:<sender@example.com>
RCPT TO:<recipient@example.com>
DATA
Subject: Test Email

This is a test message.
.
QUIT
```

Or use a command-line email tool like `swaks`:

```bash
swaks --to recipient@example.com \
      --from sender@example.com \
      --server localhost:2525 \
      --body "Hello, World!"
```

## Understanding the Mail Object

When a message is received, the `OnMessage` callback receives a `*raven.Mail` object containing:

### Envelope

The SMTP envelope (separate from message headers):

```go
// Sender (from MAIL FROM command)
from := mail.Envelope.From.Mailbox.String()

// Recipients (from RCPT TO commands)
for _, rcpt := range mail.Envelope.To {
    recipient := rcpt.Address.Mailbox.String()
    // Process recipient...
}

// Body type (7BIT or 8BITMIME)
bodyType := mail.Envelope.BodyType

// Message size (if declared via SIZE extension)
size := mail.Envelope.Size
```

### Content

The message content (headers and body):

```go
// Get specific headers
subject := mail.Content.Headers.Get("Subject")
contentType := mail.Content.Headers.Get("Content-Type")

// Get all headers with a name
receivedHeaders := mail.Content.Headers.GetAll("Received")

// Access raw body
body := mail.Content.Body
```

### Metadata

Server-assigned metadata:

```go
// Unique message ID
messageID := mail.ID

// When the message was received
receivedAt := mail.ReceivedAt

// Raw message data
rawMessage := mail.Raw
```

## Adding Connection Validation

You can validate connections at various stages:

```go
config.Callbacks = &raven.Callbacks{
    // Validate on initial connection
    OnConnect: func(ctx context.Context, conn *raven.Connection) error {
        // Check IP blacklist, rate limiting, etc.
        remoteIP := conn.RemoteAddr().String()
        if isBlacklisted(remoteIP) {
            return fmt.Errorf("connection rejected")
        }
        return nil
    },

    // Validate sender
    OnMailFrom: func(ctx context.Context, conn *raven.Connection, from raven.Path, params map[string]string) error {
        // Reject certain senders
        if from.IsNull() {
            // Null sender (bounce message) - might want to limit these
        }
        return nil
    },

    // Validate recipients
    OnRcptTo: func(ctx context.Context, conn *raven.Connection, to raven.Path, params map[string]string) error {
        // Only accept mail for your domains
        domain := to.Mailbox.Domain
        if !isLocalDomain(domain) {
            return fmt.Errorf("relay not permitted")
        }
        return nil
    },

    // Process the message
    OnMessage: func(ctx context.Context, conn *raven.Connection, mail *raven.Mail) error {
        return saveMessage(mail)
    },
}
```

## Graceful Shutdown

To properly shut down the server:

```go
package main

import (
    "context"
    "log"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/synqronlabs/raven"
)

func main() {
    config := raven.DefaultServerConfig()
    config.Hostname = "mail.example.com"

    server, err := raven.NewServer(config)
    if err != nil {
        log.Fatal(err)
    }

    // Start server in a goroutine
    go func() {
        if err := server.ListenAndServe(); err != raven.ErrServerClosed {
            log.Printf("Server error: %v", err)
        }
    }()

    log.Println("Server started")

    // Wait for interrupt signal
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    log.Println("Shutting down server...")

    // Give existing connections 30 seconds to complete
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    if err := server.Shutdown(ctx); err != nil {
        log.Printf("Shutdown error: %v", err)
        // Force close if graceful shutdown times out
        server.Close()
    }

    log.Println("Server stopped")
}
```

## Next Steps

- [Configuration](configuration.md) - Learn about all configuration options
- [TLS & Authentication](tls-and-auth.md) - Secure your server
- [Callbacks](callbacks.md) - Deep dive into the callback system
- [Examples](examples.md) - Complete working examples
