# Configuration Reference

This document provides a complete reference for all `ServerConfig` options.

## ServerConfig Structure

```go
type ServerConfig struct {
    // Network Configuration
    Hostname   string
    Addr       string
    TLSConfig  *tls.Config

    // Security Requirements
    RequireTLS  bool
    RequireAuth bool

    // Resource Limits
    MaxMessageSize int64
    MaxRecipients  int
    MaxConnections int
    MaxCommands    int64
    MaxErrors      int

    // Timeouts
    ReadTimeout  time.Duration
    WriteTimeout time.Duration
    DataTimeout  time.Duration
    IdleTimeout  time.Duration

    // Protocol Settings
    MaxLineLength    int
    Enable8BitMIME   bool
    EnableSMTPUTF8   bool
    EnableDSN        bool
    AuthMechanisms   []string

    // Logging & Callbacks
    Logger    *slog.Logger
    Callbacks *Callbacks
}
```

## Network Configuration

### Hostname (required)

The server's fully qualified domain name (FQDN). Used in:
- SMTP greeting banner
- EHLO response
- `Received` headers

```go
config.Hostname = "mail.example.com"
```

**Best Practice**: Use the actual DNS hostname that resolves to your server's IP address. This is important for email deliverability and anti-spam measures.

### Addr

The address and port to listen on.

| Value | Description |
|-------|-------------|
| `:25` | Standard SMTP port (default) |
| `:587` | Submission port (MSA) |
| `:465` | SMTPS (implicit TLS) |
| `0.0.0.0:25` | All interfaces, port 25 |
| `127.0.0.1:25` | Localhost only |

```go
config.Addr = ":587"  // Submission port
```

**Default**: `:25`

### TLSConfig

TLS configuration for STARTTLS and implicit TLS connections.

```go
cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
if err != nil {
    log.Fatal(err)
}

config.TLSConfig = &tls.Config{
    Certificates: []tls.Certificate{cert},
    MinVersion:   tls.VersionTLS12,
    CipherSuites: []uint16{
        tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    },
}
```

**Default**: `nil` (STARTTLS not offered)

## Security Requirements

### RequireTLS

When `true`, clients must upgrade to TLS before authentication or sending mail.

```go
config.RequireTLS = true
```

**Default**: `false`

**Note**: When enabled, the server returns error `554 5.7.0 TLS required` for MAIL FROM commands on non-TLS connections.

### RequireAuth

When `true`, clients must authenticate before sending mail.

```go
config.RequireAuth = true
```

**Default**: `false`

**Note**: When enabled, the server returns error `554 5.7.0 Authentication required` for MAIL FROM commands from unauthenticated clients.

## Resource Limits

### MaxMessageSize

Maximum message size in bytes. Advertised via the SIZE extension.

```go
config.MaxMessageSize = 25 * 1024 * 1024  // 25 MB
```

**Default**: `0` (unlimited)

**Behavior**:
- Advertised in EHLO response: `SIZE 26214400`
- Checked when SIZE parameter provided in MAIL FROM
- Enforced during DATA reading

### MaxRecipients

Maximum recipients per message transaction.

```go
config.MaxRecipients = 100
```

**Default**: `0` (unlimited)

**Behavior**: Returns `452 5.5.3 Too many recipients` when limit exceeded.

### MaxConnections

Maximum concurrent connections the server will accept.

```go
config.MaxConnections = 1000
```

**Default**: `0` (unlimited)

**Behavior**: New connections are immediately closed when limit reached.

### MaxCommands

Maximum commands per connection before forced disconnect.

```go
config.MaxCommands = 1000
```

**Default**: `0` (unlimited)

**Purpose**: Prevents resource exhaustion from clients that never complete transactions.

### MaxErrors

Maximum errors before forced disconnect.

```go
config.MaxErrors = 10
```

**Default**: `0` (unlimited)

**Purpose**: Disconnects misbehaving clients quickly.

## Timeouts

### ReadTimeout

Maximum time to wait for a complete command line.

```go
config.ReadTimeout = 2 * time.Minute
```

**Default**: `5 * time.Minute`

### WriteTimeout

Maximum time to write a response.

```go
config.WriteTimeout = 2 * time.Minute
```

**Default**: `5 * time.Minute`

### DataTimeout

Maximum time to read message content during DATA command.

```go
config.DataTimeout = 15 * time.Minute
```

**Default**: `10 * time.Minute`

**Note**: Should be longer than ReadTimeout to accommodate large messages.

### IdleTimeout

Maximum idle time before disconnecting client.

```go
config.IdleTimeout = 3 * time.Minute
```

**Default**: `5 * time.Minute`

## Protocol Settings

### MaxLineLength

Maximum length of a command line in bytes.

```go
config.MaxLineLength = 512  // RFC 5321 minimum
```

**Default**: `512` (RFC 5321 requirement)

**Note**: RFC 5321 specifies 512 as the minimum; some extensions may require more.

### Enable8BitMIME

Enable 8BITMIME extension (RFC 6152).

```go
config.Enable8BitMIME = true
```

**Default**: `true`

**Purpose**: Allows transmission of 8-bit content without encoding to 7-bit.

### EnableSMTPUTF8

Enable SMTPUTF8 extension (RFC 6531).

```go
config.EnableSMTPUTF8 = true
```

**Default**: `true`

**Purpose**: Supports internationalized email addresses with non-ASCII characters.

### EnableDSN

Enable Delivery Status Notifications extension (RFC 3461).

```go
config.EnableDSN = true
```

**Default**: `false`

**Purpose**: Allows senders to request delivery confirmations.

### EnableChunking

Enable CHUNKING/BDAT extension (RFC 3030).

```go
config.EnableChunking = true
```

**Default**: `false`

**Purpose**: Allows clients to send message data in binary chunks using the BDAT command instead of the traditional DATA command.

**Benefits**:
- More efficient for binary content (no dot-stuffing required)
- Allows streaming large messages in chunks
- Better error recovery (can abort mid-transfer)
- Required for BINARYMIME extension

**BDAT Command Syntax**:
```
BDAT <size> [LAST]
```

Where `<size>` is the number of octets in the chunk, and `LAST` indicates the final chunk.

### AuthMechanisms

List of supported SASL authentication mechanisms.

```go
config.AuthMechanisms = []string{"PLAIN", "LOGIN"}
```

**Default**: `["PLAIN", "LOGIN"]`

**Supported mechanisms**:
| Mechanism | Description |
|-----------|-------------|
| `PLAIN` | Simple plaintext authentication (RFC 4616) |
| `LOGIN` | Legacy mechanism (common but non-standard) |

**Note**: Both mechanisms transmit credentials in base64 (not encrypted). Always use with TLS.

## Logging & Callbacks

### Logger

Structured logger for server events.

```go
config.Logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelDebug,
}))
```

**Default**: `slog.Default()`

**Log events include**:
- Server start/stop
- Connection open/close
- Command processing (at Debug level)
- Errors and warnings
- Message receipt

### Callbacks

Event callbacks for customizing server behavior.

```go
config.Callbacks = &raven.Callbacks{
    OnConnect:  myConnectHandler,
    OnMessage:  myMessageHandler,
    // ... other callbacks
}
```

See [Callbacks](callbacks.md) for full documentation.

## Default Configuration

Use `DefaultServerConfig()` to get sensible defaults:

```go
func DefaultServerConfig() ServerConfig {
    return ServerConfig{
        Addr:             ":25",
        ReadTimeout:      5 * time.Minute,
        WriteTimeout:     5 * time.Minute,
        DataTimeout:      10 * time.Minute,
        IdleTimeout:      5 * time.Minute,
        MaxLineLength:    512,
        Enable8BitMIME:   true,
        EnableSMTPUTF8:   true,
        AuthMechanisms:   []string{"PLAIN", "LOGIN"},
        Logger:           slog.Default(),
    }
}
```

## Configuration Examples

### Development Server

```go
config := raven.DefaultServerConfig()
config.Hostname = "localhost"
config.Addr = ":2525"
config.Logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelDebug,
}))
```

### Production Mail Server

```go
cert, _ := tls.LoadX509KeyPair("server.crt", "server.key")

config := raven.ServerConfig{
    Hostname: "mail.example.com",
    Addr:     ":25",
    TLSConfig: &tls.Config{
        Certificates: []tls.Certificate{cert},
        MinVersion:   tls.VersionTLS12,
    },
    MaxMessageSize: 50 * 1024 * 1024,  // 50 MB
    MaxRecipients:  500,
    MaxConnections: 5000,
    MaxCommands:    1000,
    MaxErrors:      10,
    ReadTimeout:    2 * time.Minute,
    WriteTimeout:   2 * time.Minute,
    DataTimeout:    10 * time.Minute,
    IdleTimeout:    5 * time.Minute,
    EnableDSN:      true,
    Logger:         productionLogger,
    Callbacks:      productionCallbacks,
}
```

### Submission Server (MSA)

```go
cert, _ := tls.LoadX509KeyPair("server.crt", "server.key")

config := raven.ServerConfig{
    Hostname:    "mail.example.com",
    Addr:        ":587",
    TLSConfig:   tlsConfig,
    RequireTLS:  true,
    RequireAuth: true,
    MaxMessageSize: 25 * 1024 * 1024,
    AuthMechanisms: []string{"PLAIN"},
    Callbacks: &raven.Callbacks{
        OnAuth: authenticateUser,
        OnMessage: queueForDelivery,
    },
}
```

### Relay Restrictions

```go
config.Callbacks = &raven.Callbacks{
    OnRcptTo: func(ctx context.Context, conn *raven.Connection, to raven.Path, params map[string]string) error {
        // Only relay for authenticated users
        if !conn.IsAuthenticated() {
            // Only accept for local domains
            if !isLocalDomain(to.Mailbox.Domain) {
                return fmt.Errorf("relay access denied")
            }
        }
        return nil
    },
}
```
