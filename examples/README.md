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

### 2. Relay Server (`relay_server/`)

An **SMTP Relay** that accepts mail from trusted/whitelisted hosts and forwards it to destination MX servers.

**Features demonstrated:**
- IP-based whitelisting for trusted senders
- MX record lookup and delivery
- DKIM signing of outgoing messages
- ARC sealing for message chain of custody
- Opportunistic TLS for outbound connections
- Delivery queue with retry logic

**Use case:** Internal relay that your application servers use to send email, or a forwarding service.

### 3. MTA/MX Server (`mta_server/`)

A **Mail Transfer Agent (MTA)** that accepts incoming mail for specific domains.

**Features demonstrated:**
- Domain-based mail acceptance
- Full email authentication stack:
  - SPF verification (Sender Policy Framework)
  - DKIM verification (DomainKeys Identified Mail)
  - DMARC verification (Domain-based Message Authentication)
  - ARC verification (Authenticated Received Chain)
- Mailbox validation
- Spam score calculation based on authentication results
- Message delivery to mailboxes

**Use case:** Your organization's incoming mail server (MX record target).

## Running the Examples

### Prerequisites

1. Go 1.25 or later
2. TLS certificates (for production use)
3. DNS records configured (MX, SPF, DKIM, DMARC)

### Development Mode

For testing, you can run the examples on non-privileged ports:

```bash
# MSA Server (change ports in code or use environment variables)
cd examples/msa_server
go run main.go

# Relay Server
cd examples/relay_server
go run main.go

# MTA Server
cd examples/mta_server
go run main.go
```

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

# Test MTA (no auth, simulating external sender)
swaks --to alice@example.com \
      --from sender@external.com \
      --server localhost:25 \
      --ehlo external.com
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

For smaller deployments, combine MSA and MTA on the same server:

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
