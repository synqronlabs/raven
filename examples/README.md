# Raven Examples

This directory contains working examples demonstrating how to use Raven for different mail server scenarios.

## Examples Overview

### 1. MSA Server (`msa_server/`)

A **Mail Submission Agent (MSA)** that accepts mail from authenticated users (mail clients like Thunderbird, Outlook, etc.) and queues it for delivery.

**Features demonstrated:**
- STARTTLS support on port 587
- Implicit TLS on port 465
- SMTP authentication with PLAIN and LOGIN mechanisms
- TLS requirement enforcement before authentication
- Sender address validation (users can only send from allowed addresses)
- Per-user rate limiting
- Message queueing

**Use case:** Your organization's outgoing mail server that users configure in their email clients.

### Testing with swaks

[swaks](http://www.jetmore.org/john/code/swaks/) is a great tool for testing SMTP servers:

```bash
# Test MSA with authentication
swaks --to recipient@example.com \
      --from alice@example.com \
      --server localhost:587 \
      --auth PLAIN \
      --auth-user alice \
      --auth-password password123 \
      --tls
```

## Production Considerations

### TLS Certificates

All examples include placeholder TLS configuration. For production:

```go
cert, err := tls.LoadX509KeyPair(
    "/etc/ssl/certs/mail.example.com.crt",
    "/etc/ssl/private/mail.example.com.key",
)
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    MinVersion:   tls.VersionTLS12,
}
```

Consider using [autocert](https://pkg.go.dev/golang.org/x/crypto/acme/autocert) for automatic Let's Encrypt certificates.

### Database Integration

All examples use in-memory maps for:
- User authentication (`userDB`)
- Mailbox lookup (`mailboxDB`)
- Message storage (`messageStore`)
- Signing keys (`keyStore`)

Replace these with actual database implementations:

```go
// Example: PostgreSQL user lookup
func authenticateUser(ctx context.Context, username, password string) (*User, error) {
    var user User
    err := db.QueryRowContext(ctx,
        "SELECT id, password_hash, enabled FROM users WHERE username = $1",
        username,
    ).Scan(&user.ID, &user.PasswordHash, &user.Enabled)
    
    if err != nil {
        return nil, err
    }
    
    if err := bcrypt.CompareHashAndPassword(
        []byte(user.PasswordHash),
        []byte(password),
    ); err != nil {
        return nil, ErrInvalidCredentials
    }
    
    return &user, nil
}
```

### Message Queue

For relay and MSA servers, replace the in-memory queue with:
- Redis with reliable queues
- RabbitMQ / AMQP
- PostgreSQL with SKIP LOCKED
- Kafka for high-throughput scenarios

### DKIM Key Management

Store DKIM private keys securely:
- HashiCorp Vault
- AWS Secrets Manager / KMS
- Hardware Security Modules (HSMs)
- Encrypted files with proper key management

### DNS Configuration

For a complete mail server setup, configure:

```dns
; MX record
example.com.     IN MX   10 mx.example.com.

; SPF record
example.com.     IN TXT  "v=spf1 mx a:relay.example.com -all"

; DKIM record
relay1._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=MIGfMA0G..."

; DMARC record
_dmarc.example.com. IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
```

### Monitoring

Add metrics collection for:
- Connection counts
- Messages processed
- Authentication success/failure rates
- Delivery success/failure rates
- SPF/DKIM/DMARC pass rates
- Queue depth

```go
// Example: Prometheus metrics
var messagesReceived = prometheus.NewCounterVec(
    prometheus.CounterOpts{
        Name: "smtp_messages_received_total",
        Help: "Total messages received",
    },
    []string{"domain", "auth_result"},
)
```

## Architecture Patterns

### Combined MSA + MTA

For smaller deployments, you should combine MSA and MTA on the same server:

```go
server := raven.New("mail.example.com").
    OnMailFrom(
        func(c *raven.Context) *raven.Response {
            if c.IsAuthenticated() {
                // Authenticated: MSA mode (submission)
                return validateSenderAddress(c)
            }
            // Not authenticated: MTA mode (receiving)
            return spf.Middleware(...)(c)
        },
    )
```

### High Availability

For HA deployments:
- Multiple MX servers with different priorities
- Load balancer in front of submission servers
- Shared queue backend (Redis, PostgreSQL)
- DNS round-robin or anycast for MX records

## License

These examples are part of the Raven library and are provided under the same license.
