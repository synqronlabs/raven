# TLS & Authentication

This guide covers how to secure your Raven SMTP server with TLS encryption and authentication.

## TLS Configuration

### Why TLS Matters

TLS (Transport Layer Security) provides:
- **Encryption**: Protects email content and credentials in transit
- **Server Authentication**: Clients can verify they're connecting to the right server
- **Client Authentication**: Optional certificate-based client verification

### Generating Certificates

#### For Development

Generate a self-signed certificate:

```bash
# Generate private key
openssl genrsa -out server.key 2048

# Generate self-signed certificate
openssl req -new -x509 -sha256 -key server.key -out server.crt -days 365 \
    -subj "/CN=localhost"
```

#### For Production

Use a certificate from a trusted CA (Let's Encrypt, DigiCert, etc.):

```bash
# Using certbot for Let's Encrypt
certbot certonly --standalone -d mail.example.com

# Certificates will be in:
# /etc/letsencrypt/live/mail.example.com/fullchain.pem
# /etc/letsencrypt/live/mail.example.com/privkey.pem
```

### Basic TLS Setup

```go
package main

import (
    "crypto/tls"
    "log"

    "github.com/synqronlabs/raven"
)

func main() {
    // Load certificate
    cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
    if err != nil {
        log.Fatal("Failed to load certificate:", err)
    }

    config := raven.DefaultServerConfig()
    config.Hostname = "mail.example.com"
    config.TLSConfig = &tls.Config{
        Certificates: []tls.Certificate{cert},
    }

    server, err := raven.NewServer(config)
    if err != nil {
        log.Fatal(err)
    }

    // Set up signal handling for graceful shutdown
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

    // Run server in a goroutine
    go func() {
        // STARTTLS will be advertised
        log.Println("SMTP server listening on :25")
        if err := server.ListenAndServe(); err != raven.ErrServerClosed {
            log.Fatal(err)
        }
    }()

    // Wait for shutdown signal
    <-sigChan
    log.Println("Shutting down...")

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    server.Shutdown(ctx)
}
```

### TLS Modes

#### STARTTLS (Explicit TLS)

Connection starts unencrypted, then upgrades via STARTTLS command.

```go
// Standard SMTP port with STARTTLS
config.Addr = ":25"
config.TLSConfig = tlsConfig

server.ListenAndServe() // Offers STARTTLS
```

**SMTP session**:
```
S: 220 mail.example.com ESMTP ready
C: EHLO client.example.com
S: 250-mail.example.com Hello client.example.com
S: 250-STARTTLS
S: 250 ENHANCEDSTATUSCODES
C: STARTTLS
S: 220 Ready to start TLS
[TLS handshake]
C: EHLO client.example.com
...
```

#### Implicit TLS (SMTPS)

Connection is encrypted from the start. Used on port 465.

```go
// SMTPS port with implicit TLS
config.Addr = ":465"
config.TLSConfig = tlsConfig

server.ListenAndServeTLS() // Implicit TLS
```

### Production TLS Configuration

```go
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    
    // Minimum TLS version (TLS 1.2 recommended)
    MinVersion: tls.VersionTLS12,
    
    // Prefer server cipher suites
    PreferServerCipherSuites: true,
    
    // Recommended cipher suites
    CipherSuites: []uint16{
        // TLS 1.3 cipher suites (automatic in Go 1.13+)
        tls.TLS_AES_256_GCM_SHA384,
        tls.TLS_AES_128_GCM_SHA256,
        tls.TLS_CHACHA20_POLY1305_SHA256,
        
        // TLS 1.2 cipher suites
        tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
        tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
    },
    
    // Curve preferences
    CurvePreferences: []tls.CurveID{
        tls.X25519,
        tls.CurveP256,
    },
}
```

### Requiring TLS

Force clients to use TLS before sending mail:

```go
config.RequireTLS = true
```

When enabled:
- MAIL FROM is rejected without TLS
- AUTH is rejected without TLS
- Response: `554 5.7.0 TLS required`

### Multiple Certificates (SNI)

Support multiple domains with different certificates:

```go
cert1, _ := tls.LoadX509KeyPair("example.com.crt", "example.com.key")
cert2, _ := tls.LoadX509KeyPair("example.org.crt", "example.org.key")

tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert1, cert2},
}
```

Go automatically selects the correct certificate based on SNI (Server Name Indication).

### Certificate Reload

Reload certificates without restart:

```go
type CertReloader struct {
    mu   sync.RWMutex
    cert *tls.Certificate
}

func (r *CertReloader) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
    r.mu.RLock()
    defer r.mu.RUnlock()
    return r.cert, nil
}

func (r *CertReloader) Reload(certFile, keyFile string) error {
    cert, err := tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
        return err
    }
    r.mu.Lock()
    r.cert = &cert
    r.mu.Unlock()
    return nil
}

// Usage
reloader := &CertReloader{}
reloader.Reload("server.crt", "server.key")

tlsConfig := &tls.Config{
    GetCertificate: reloader.GetCertificate,
}

// Reload on SIGHUP
go func() {
    sighup := make(chan os.Signal, 1)
    signal.Notify(sighup, syscall.SIGHUP)
    for range sighup {
        log.Println("Reloading certificates...")
        if err := reloader.Reload("server.crt", "server.key"); err != nil {
            log.Printf("Failed to reload: %v", err)
        }
    }
}()
```

---

## Authentication

### Authentication Mechanisms

Raven supports these SASL mechanisms:

| Mechanism | Security | Description |
|-----------|----------|-------------|
| PLAIN | Low* | Simple base64-encoded credentials |
| LOGIN | Low* | Legacy challenge-response (non-standard) |

*Both mechanisms transmit credentials in base64 (not encrypted). **Always use with TLS.**

### Basic Authentication Setup

```go
config := raven.DefaultServerConfig()
config.Hostname = "mail.example.com"
config.TLSConfig = tlsConfig
config.AuthMechanisms = []string{"PLAIN", "LOGIN"}

config.Callbacks = &raven.Callbacks{
    OnAuth: func(ctx context.Context, conn *raven.Connection, mechanism, identity, password string) error {
        // Verify credentials
        if !verifyUser(identity, password) {
            return fmt.Errorf("authentication failed")
        }
        return nil
    },
}
```

### Requiring Authentication

Force clients to authenticate before sending:

```go
config.RequireAuth = true
```

When enabled:
- MAIL FROM is rejected without authentication
- Response: `554 5.7.0 Authentication required`

### Authentication Flow

**PLAIN mechanism**:
```
C: AUTH PLAIN AGFsaWNlAHNlY3JldA==
S: 235 2.7.0 Authentication successful
```

The base64 decodes to: `\0alice\0secret` (authzid, authcid, password)

**LOGIN mechanism**:
```
C: AUTH LOGIN
S: 334 VXNlcm5hbWU6        (Username:)
C: YWxpY2U=                 (alice)
S: 334 UGFzc3dvcmQ6        (Password:)
C: c2VjcmV0                 (secret)
S: 235 2.7.0 Authentication successful
```

### Password Verification

#### Using bcrypt

```go
import "golang.org/x/crypto/bcrypt"

func verifyUser(username, password string) bool {
    user, err := db.GetUser(username)
    if err != nil {
        return false
    }
    
    err = bcrypt.CompareHashAndPassword(
        []byte(user.PasswordHash), 
        []byte(password),
    )
    return err == nil
}
```

#### Using Argon2

```go
import "golang.org/x/crypto/argon2"

func verifyUser(username, password string) bool {
    user, err := db.GetUser(username)
    if err != nil {
        return false
    }
    
    hash := argon2.IDKey(
        []byte(password),
        user.Salt,
        1, 64*1024, 4, 32,
    )
    return subtle.ConstantTimeCompare(hash, user.PasswordHash) == 1
}
```

### LDAP Authentication

```go
import "github.com/go-ldap/ldap/v3"

func verifyLDAP(username, password string) error {
    conn, err := ldap.DialURL("ldaps://ldap.example.com:636")
    if err != nil {
        return fmt.Errorf("ldap connection failed: %w", err)
    }
    defer conn.Close()
    
    // Build user DN
    userDN := fmt.Sprintf("uid=%s,ou=users,dc=example,dc=com", 
        ldap.EscapeFilter(username))
    
    // Attempt bind with user credentials
    err = conn.Bind(userDN, password)
    if err != nil {
        return fmt.Errorf("authentication failed")
    }
    
    return nil
}

config.Callbacks = &raven.Callbacks{
    OnAuth: func(ctx context.Context, conn *raven.Connection, mechanism, identity, password string) error {
        return verifyLDAP(identity, password)
    },
}
```

### OAuth2/JWT Authentication

For modern applications, you might accept JWT tokens:

```go
import "github.com/golang-jwt/jwt/v5"

var jwtSecret = []byte("your-secret-key")

func verifyJWT(tokenString string) (*jwt.Token, error) {
    return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method")
        }
        return jwtSecret, nil
    })
}

config.Callbacks = &raven.Callbacks{
    OnAuth: func(ctx context.Context, conn *raven.Connection, mechanism, identity, password string) error {
        // For PLAIN auth, password field could contain JWT
        token, err := verifyJWT(password)
        if err != nil {
            return fmt.Errorf("invalid token")
        }
        
        claims := token.Claims.(jwt.MapClaims)
        if claims["email"] != identity {
            return fmt.Errorf("identity mismatch")
        }
        
        return nil
    },
}
```

---

## Security Best Practices

### 1. Always Use TLS for Authentication

```go
config.RequireTLS = true  // Must have TLS before AUTH
config.TLSConfig = tlsConfig
```

### 2. Rate Limit Authentication Attempts

```go
import "golang.org/x/time/rate"

var authLimiters = make(map[string]*rate.Limiter)
var authLimitersMu sync.Mutex

func getAuthLimiter(ip string) *rate.Limiter {
    authLimitersMu.Lock()
    defer authLimitersMu.Unlock()
    
    if limiter, ok := authLimiters[ip]; ok {
        return limiter
    }
    
    // 5 attempts per minute
    limiter := rate.NewLimiter(rate.Every(12*time.Second), 5)
    authLimiters[ip] = limiter
    return limiter
}

config.Callbacks = &raven.Callbacks{
    OnAuth: func(ctx context.Context, conn *raven.Connection, mechanism, identity, password string) error {
        ip := extractIP(conn.RemoteAddr())
        
        if !getAuthLimiter(ip).Allow() {
            return fmt.Errorf("too many authentication attempts")
        }
        
        return verifyUser(identity, password)
    },
}
```

### 3. Log Authentication Events

```go
config.Callbacks = &raven.Callbacks{
    OnAuth: func(ctx context.Context, conn *raven.Connection, mechanism, identity, password string) error {
        ip := conn.RemoteAddr().String()
        
        err := verifyUser(identity, password)
        if err != nil {
            log.Printf("AUTH FAILED: user=%s ip=%s mechanism=%s", 
                identity, ip, mechanism)
            // Consider alerting on repeated failures
            return err
        }
        
        log.Printf("AUTH SUCCESS: user=%s ip=%s mechanism=%s",
            identity, ip, mechanism)
        return nil
    },
}
```

### 4. Sender Verification for Authenticated Users

```go
config.Callbacks = &raven.Callbacks{
    OnMailFrom: func(ctx context.Context, conn *raven.Connection, from raven.Path, params map[string]string) error {
        if conn.IsAuthenticated() {
            // Verify authenticated user can send from this address
            allowed := userCanSendFrom(conn.Auth.Identity, from.Mailbox.String())
            if !allowed {
                return fmt.Errorf("not authorized to send from this address")
            }
        }
        return nil
    },
}
```

### 5. TLS Callback for Logging

```go
config.Callbacks = &raven.Callbacks{
    OnStartTLS: func(ctx context.Context, conn *raven.Connection) error {
        log.Printf("[%s] TLS upgrade from %s", 
            conn.Trace.ID, conn.RemoteAddr())
        return nil
    },
}
```

---

## Complete Secure Server Example

```go
package main

import (
    "context"
    "crypto/tls"
    "fmt"
    "log"
    "log/slog"
    "os"
    "time"

    "github.com/synqronlabs/raven"
    "golang.org/x/crypto/bcrypt"
)

func main() {
    // Load TLS certificate
    cert, err := tls.LoadX509KeyPair(
        "/etc/letsencrypt/live/mail.example.com/fullchain.pem",
        "/etc/letsencrypt/live/mail.example.com/privkey.pem",
    )
    if err != nil {
        log.Fatal("Failed to load certificate:", err)
    }

    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
        MinVersion:   tls.VersionTLS12,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        },
    }

    config := raven.ServerConfig{
        Hostname:       "mail.example.com",
        Addr:           ":587",
        TLSConfig:      tlsConfig,
        RequireTLS:     true,
        RequireAuth:    true,
        MaxMessageSize: 25 * 1024 * 1024,
        MaxRecipients:  100,
        MaxConnections: 1000,
        MaxErrors:      5,
        ReadTimeout:    2 * time.Minute,
        WriteTimeout:   2 * time.Minute,
        DataTimeout:    10 * time.Minute,
        AuthMechanisms: []string{"PLAIN"},
        Logger: slog.New(slog.NewJSONHandler(os.Stdout, nil)),
        Callbacks: &raven.Callbacks{
            OnAuth:     authenticate,
            OnMailFrom: verifySender,
            OnRcptTo:   verifyRecipient,
            OnMessage:  processMessage,
        },
    }

    server, err := raven.NewServer(config)
    if err != nil {
        log.Fatal(err)
    }

    // Set up signal handling for graceful shutdown
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

    // Run server in a goroutine
    go func() {
        log.Printf("Secure SMTP server listening on %s", config.Addr)
        if err := server.ListenAndServe(); err != raven.ErrServerClosed {
            log.Fatal(err)
        }
    }()

    // Wait for shutdown signal
    <-sigChan
    log.Println("Shutting down...")

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    server.Shutdown(ctx)
}

func authenticate(ctx context.Context, conn *raven.Connection, mechanism, identity, password string) error {
    user, err := getUser(identity)
    if err != nil {
        log.Printf("Auth failed - unknown user: %s", identity)
        return fmt.Errorf("authentication failed")
    }

    err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
    if err != nil {
        log.Printf("Auth failed - invalid password: %s", identity)
        return fmt.Errorf("authentication failed")
    }

    log.Printf("Auth success: %s from %s", identity, conn.RemoteAddr())
    return nil
}

func verifySender(ctx context.Context, conn *raven.Connection, from raven.Path, params map[string]string) error {
    // Authenticated users can only send from their own address
    if from.Mailbox.String() != conn.Auth.Identity {
        return fmt.Errorf("sender address mismatch")
    }
    return nil
}

func verifyRecipient(ctx context.Context, conn *raven.Connection, to raven.Path, params map[string]string) error {
    // Authenticated users can relay
    return nil
}

func processMessage(ctx context.Context, conn *raven.Connection, mail *raven.Mail) error {
    log.Printf("Message %s from %s (%s) to %d recipients",
        mail.ID,
        mail.Envelope.From.String(),
        conn.Auth.Identity,
        len(mail.Envelope.To))
    return nil
}

type User struct {
    Email        string
    PasswordHash string
}

func getUser(email string) (*User, error) {
    // Implement user lookup
    return nil, fmt.Errorf("user not found")
}
```

---

## See Also

- [DANE](dane.md) - DANE/TLSA configuration for authenticated delivery
- [Configuration](configuration.md) - Full configuration reference
- [Callbacks](callbacks.md) - Callback system details
- [Examples](examples.md) - More complete examples
