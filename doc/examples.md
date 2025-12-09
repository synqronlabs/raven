# Examples

This document provides complete, working examples for common SMTP server use cases.

## Table of Contents

- [Simple Mail Receiver](#simple-mail-receiver)
- [Mail Relay Server](#mail-relay-server)
- [Submission Server (MSA)](#submission-server-msa)
- [Mail Sink for Testing](#mail-sink-for-testing)
- [Webhook Forwarder](#webhook-forwarder)
- [Database-Backed Mail Server](#database-backed-mail-server)
- [BDAT/CHUNKING Support](#bdatchunking-support)
- [Multi-Domain Virtual Hosting](#multi-domain-virtual-hosting)

---

## Simple Mail Receiver

A basic server that receives and logs all incoming mail.

```go
package main

import (
    "context"
    "fmt"
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
    config.Addr = ":2525"

    config.Callbacks = &raven.Callbacks{
        OnConnect: func(ctx context.Context, conn *raven.Connection) error {
            log.Printf("New connection from %s", conn.RemoteAddr())
            return nil
        },

        OnMailFrom: func(ctx context.Context, conn *raven.Connection, from raven.Path, params map[string]string) error {
            log.Printf("MAIL FROM: %s", from.String())
            return nil
        },

        OnRcptTo: func(ctx context.Context, conn *raven.Connection, to raven.Path, params map[string]string) error {
            log.Printf("RCPT TO: %s", to.String())
            return nil
        },

        OnMessage: func(ctx context.Context, conn *raven.Connection, mail *raven.Mail) error {
            log.Printf("Received message %s:", mail.ID)
            log.Printf("  From: %s", mail.Envelope.From.String())
            log.Printf("  To: %d recipients", len(mail.Envelope.To))
            log.Printf("  Subject: %s", mail.Content.Headers.Get("Subject"))
            log.Printf("  Size: %d bytes", len(mail.Raw))
            return nil
        },

        OnDisconnect: func(ctx context.Context, conn *raven.Connection) {
            log.Printf("Disconnected: %s", conn.RemoteAddr())
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
        log.Printf("SMTP server listening on %s", config.Addr)
        if err := server.ListenAndServe(); err != raven.ErrServerClosed {
            log.Fatal(err)
        }
    }()

    // Wait for shutdown signal
    <-sigChan
    log.Println("Shutting down...")

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    if err := server.Shutdown(ctx); err != nil {
        log.Printf("Shutdown error: %v", err)
    }
    log.Println("Server stopped")
}
```

---

## Mail Relay Server

A server that accepts mail and forwards it to another SMTP server.

```go
package main

import (
    "context"
    "crypto/tls"
    "fmt"
    "log"
    "net/smtp"
    "strings"

    "github.com/synqronlabs/raven"
)

// RelayConfig holds the upstream server configuration
type RelayConfig struct {
    Host     string
    Port     int
    Username string
    Password string
    UseTLS   bool
}

var relayConfig = RelayConfig{
    Host:     "smtp.upstream.com",
    Port:     587,
    Username: "relay@upstream.com",
    Password: "secret",
    UseTLS:   true,
}

func main() {
    config := raven.DefaultServerConfig()
    config.Hostname = "relay.example.com"
    config.Addr = ":25"
    config.MaxMessageSize = 50 * 1024 * 1024 // 50 MB

    config.Callbacks = &raven.Callbacks{
        OnMessage: relayMessage,
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
        log.Printf("Relay server listening on %s", config.Addr)
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

func relayMessage(ctx context.Context, conn *raven.Connection, mail *raven.Mail) error {
    // Build recipient list
    var recipients []string
    for _, rcpt := range mail.Envelope.To {
        recipients = append(recipients, rcpt.Address.Mailbox.String())
    }

    // Connect to upstream
    addr := fmt.Sprintf("%s:%d", relayConfig.Host, relayConfig.Port)
    
    var c *smtp.Client
    var err error

    if relayConfig.UseTLS {
        // Connect with TLS
        tlsConfig := &tls.Config{ServerName: relayConfig.Host}
        conn, err := tls.Dial("tcp", addr, tlsConfig)
        if err != nil {
            return fmt.Errorf("failed to connect to relay: %w", err)
        }
        c, err = smtp.NewClient(conn, relayConfig.Host)
    } else {
        c, err = smtp.Dial(addr)
    }

    if err != nil {
        return fmt.Errorf("failed to connect to relay: %w", err)
    }
    defer c.Close()

    // Authenticate
    auth := smtp.PlainAuth("", relayConfig.Username, relayConfig.Password, relayConfig.Host)
    if err := c.Auth(auth); err != nil {
        return fmt.Errorf("relay authentication failed: %w", err)
    }

    // Send mail
    if err := c.Mail(mail.Envelope.From.Mailbox.String()); err != nil {
        return fmt.Errorf("relay MAIL FROM failed: %w", err)
    }

    for _, rcpt := range recipients {
        if err := c.Rcpt(rcpt); err != nil {
            log.Printf("Relay RCPT TO %s failed: %v", rcpt, err)
            continue
        }
    }

    w, err := c.Data()
    if err != nil {
        return fmt.Errorf("relay DATA failed: %w", err)
    }

    _, err = w.Write(mail.Raw)
    if err != nil {
        return fmt.Errorf("relay write failed: %w", err)
    }

    if err := w.Close(); err != nil {
        return fmt.Errorf("relay close failed: %w", err)
    }

    c.Quit()

    log.Printf("Relayed message %s to %d recipients", mail.ID, len(recipients))
    return nil
}
```

---

## Submission Server (MSA)

A secure mail submission server requiring authentication.

```go
package main

import (
    "context"
    "crypto/tls"
    "fmt"
    "log"
    "log/slog"
    "os"
    "strings"

    "github.com/synqronlabs/raven"
)

// User represents an authenticated user
type User struct {
    Email        string
    PasswordHash string
    AllowedFrom  []string // Addresses user can send from
    MaxMsgSize   int64
}

// In-memory user database (use a real database in production)
var users = map[string]User{
    "alice@example.com": {
        Email:        "alice@example.com",
        PasswordHash: hashPassword("alice123"),
        AllowedFrom:  []string{"alice@example.com", "alice.smith@example.com"},
        MaxMsgSize:   25 * 1024 * 1024,
    },
    "bob@example.com": {
        Email:        "bob@example.com",
        PasswordHash: hashPassword("bob456"),
        AllowedFrom:  []string{"bob@example.com"},
        MaxMsgSize:   10 * 1024 * 1024,
    },
}

func main() {
    // Load TLS certificate
    cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
    if err != nil {
        log.Fatal("Failed to load TLS certificate:", err)
    }

    config := raven.ServerConfig{
        Hostname: "mail.example.com",
        Addr:     ":587", // Submission port
        TLSConfig: &tls.Config{
            Certificates: []tls.Certificate{cert},
            MinVersion:   tls.VersionTLS12,
        },
        RequireTLS:     true,
        RequireAuth:    true,
        MaxMessageSize: 50 * 1024 * 1024,
        AuthMechanisms: []string{"PLAIN"},
        Logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
            Level: slog.LevelInfo,
        })),
        Callbacks: &raven.Callbacks{
            OnAuth:     authenticateUser,
            OnMailFrom: validateSender,
            OnRcptTo:   validateRecipient,
            OnMessage:  queueMessage,
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
        log.Printf("Submission server listening on %s", config.Addr)
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

func authenticateUser(ctx context.Context, conn *raven.Connection, mechanism, identity, password string) error {
    user, ok := users[strings.ToLower(identity)]
    if !ok {
        log.Printf("Auth failed: unknown user %s", identity)
        return fmt.Errorf("authentication failed")
    }

    if !verifyPassword(password, user.PasswordHash) {
        log.Printf("Auth failed: invalid password for %s", identity)
        return fmt.Errorf("authentication failed")
    }

    log.Printf("User %s authenticated successfully", identity)
    return nil
}

func validateSender(ctx context.Context, conn *raven.Connection, from raven.Path, params map[string]string) error {
    if !conn.IsAuthenticated() {
        return fmt.Errorf("authentication required")
    }

    user, ok := users[strings.ToLower(conn.Auth.Identity)]
    if !ok {
        return fmt.Errorf("user not found")
    }

    // Check if user can send from this address
    fromAddr := strings.ToLower(from.Mailbox.String())
    allowed := false
    for _, addr := range user.AllowedFrom {
        if strings.ToLower(addr) == fromAddr {
            allowed = true
            break
        }
    }

    if !allowed {
        return fmt.Errorf("not authorized to send from %s", from.Mailbox.String())
    }

    return nil
}

func validateRecipient(ctx context.Context, conn *raven.Connection, to raven.Path, params map[string]string) error {
    // Authenticated users can send to anyone (relay)
    if conn.IsAuthenticated() {
        return nil
    }
    return fmt.Errorf("relay access denied")
}

func queueMessage(ctx context.Context, conn *raven.Connection, mail *raven.Mail) error {
    log.Printf("Queued message %s from %s (%s) to %d recipients",
        mail.ID,
        mail.Envelope.From.String(),
        conn.Auth.Identity,
        len(mail.Envelope.To))
    
    // In production, queue for delivery via your MTA
    return saveToQueue(mail)
}

// Placeholder functions
func hashPassword(p string) string { return p } // Use bcrypt in production!
func verifyPassword(p, h string) bool { return p == h }
func saveToQueue(mail *raven.Mail) error { return nil }
```

---

## Mail Sink for Testing

A server that accepts all mail and stores it for inspection (useful for testing).

```go
package main

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "sync"
    "time"

    "github.com/synqronlabs/raven"
)

// MailStore holds received messages
type MailStore struct {
    mu       sync.RWMutex
    messages []*StoredMail
    maxSize  int
}

// StoredMail represents a stored message
type StoredMail struct {
    ID         string    `json:"id"`
    ReceivedAt time.Time `json:"received_at"`
    From       string    `json:"from"`
    To         []string  `json:"to"`
    Subject    string    `json:"subject"`
    Size       int       `json:"size"`
    Raw        string    `json:"raw,omitempty"`
}

var store = &MailStore{maxSize: 1000}

func main() {
    // Start SMTP server
    go startSMTPServer()

    // Start HTTP API for viewing messages
    startHTTPServer()
}

func startSMTPServer() {
    config := raven.DefaultServerConfig()
    config.Hostname = "localhost"
    config.Addr = ":2525"

    config.Callbacks = &raven.Callbacks{
        OnMessage: func(ctx context.Context, conn *raven.Connection, mail *raven.Mail) error {
            var to []string
            for _, rcpt := range mail.Envelope.To {
                to = append(to, rcpt.Address.Mailbox.String())
            }

            stored := &StoredMail{
                ID:         mail.ID,
                ReceivedAt: mail.ReceivedAt,
                From:       mail.Envelope.From.Mailbox.String(),
                To:         to,
                Subject:    mail.Content.Headers.Get("Subject"),
                Size:       len(mail.Raw),
                Raw:        string(mail.Raw),
            }

            store.Add(stored)
            log.Printf("Stored message %s", mail.ID)
            return nil
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
        log.Println("SMTP server listening on :2525")
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

func startHTTPServer() {
    http.HandleFunc("/messages", func(w http.ResponseWriter, r *http.Request) {
        messages := store.List()
        
        // Don't include raw content in list
        for i := range messages {
            messages[i].Raw = ""
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(messages)
    })

    http.HandleFunc("/messages/", func(w http.ResponseWriter, r *http.Request) {
        id := r.URL.Path[len("/messages/"):]
        msg := store.Get(id)
        if msg == nil {
            http.NotFound(w, r)
            return
        }

        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(msg)
    })

    http.HandleFunc("/clear", func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
            http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
            return
        }
        store.Clear()
        w.WriteHeader(http.StatusNoContent)
    })

    log.Println("HTTP API listening on :8080")
    log.Println("  GET  /messages     - List all messages")
    log.Println("  GET  /messages/:id - Get specific message")
    log.Println("  POST /clear        - Clear all messages")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func (s *MailStore) Add(mail *StoredMail) {
    s.mu.Lock()
    defer s.mu.Unlock()

    s.messages = append(s.messages, mail)
    
    // Trim if over max size
    if len(s.messages) > s.maxSize {
        s.messages = s.messages[len(s.messages)-s.maxSize:]
    }
}

func (s *MailStore) List() []*StoredMail {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    result := make([]*StoredMail, len(s.messages))
    copy(result, s.messages)
    return result
}

func (s *MailStore) Get(id string) *StoredMail {
    s.mu.RLock()
    defer s.mu.RUnlock()

    for _, msg := range s.messages {
        if msg.ID == id {
            return msg
        }
    }
    return nil
}

func (s *MailStore) Clear() {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.messages = nil
}
```

---

## Webhook Forwarder

Forward incoming emails to a webhook endpoint.

```go
package main

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
    "time"

    "github.com/synqronlabs/raven"
)

const webhookURL = "https://api.example.com/incoming-email"
const webhookSecret = "your-secret-key"

type WebhookPayload struct {
    ID        string   `json:"id"`
    Timestamp string   `json:"timestamp"`
    From      string   `json:"from"`
    To        []string `json:"to"`
    Subject   string   `json:"subject"`
    Headers   []Header `json:"headers"`
    Body      string   `json:"body"`
    Raw       string   `json:"raw"`
}

type Header struct {
    Name  string `json:"name"`
    Value string `json:"value"`
}

func main() {
    config := raven.DefaultServerConfig()
    config.Hostname = "webhook.example.com"
    config.Addr = ":25"

    config.Callbacks = &raven.Callbacks{
        OnMessage: forwardToWebhook,
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
        log.Println("Webhook forwarder listening on :25")
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

func forwardToWebhook(ctx context.Context, conn *raven.Connection, mail *raven.Mail) error {
    // Build recipient list
    var to []string
    for _, rcpt := range mail.Envelope.To {
        to = append(to, rcpt.Address.Mailbox.String())
    }

    // Build headers list
    var headers []Header
    for _, h := range mail.Content.Headers {
        headers = append(headers, Header{Name: h.Name, Value: h.Value})
    }

    payload := WebhookPayload{
        ID:        mail.ID,
        Timestamp: mail.ReceivedAt.Format(time.RFC3339),
        From:      mail.Envelope.From.Mailbox.String(),
        To:        to,
        Subject:   mail.Content.Headers.Get("Subject"),
        Headers:   headers,
        Body:      string(mail.Content.Body),
        Raw:       string(mail.Raw),
    }

    // Send to webhook
    jsonPayload, err := json.Marshal(payload)
    if err != nil {
        return fmt.Errorf("failed to marshal payload: %w", err)
    }

    req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, bytes.NewReader(jsonPayload))
    if err != nil {
        return fmt.Errorf("failed to create request: %w", err)
    }

    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-Webhook-Secret", webhookSecret)
    req.Header.Set("X-Mail-ID", mail.ID)

    client := &http.Client{Timeout: 30 * time.Second}
    resp, err := client.Do(req)
    if err != nil {
        return fmt.Errorf("webhook request failed: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode >= 400 {
        body, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("webhook returned %d: %s", resp.StatusCode, string(body))
    }

    log.Printf("Forwarded message %s to webhook", mail.ID)
    return nil
}
```

---

## Database-Backed Mail Server

Store messages in a SQLite database.

```go
package main

import (
    "context"
    "database/sql"
    "fmt"
    "log"
    "strings"
    "time"

    _ "github.com/mattn/go-sqlite3"
    "github.com/synqronlabs/raven"
)

var db *sql.DB

func main() {
    // Initialize database
    var err error
    db, err = sql.Open("sqlite3", "./mail.db")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    if err := initSchema(); err != nil {
        log.Fatal("Failed to initialize schema:", err)
    }

    // Start server
    config := raven.DefaultServerConfig()
    config.Hostname = "mail.example.com"
    config.Addr = ":25"

    config.Callbacks = &raven.Callbacks{
        OnRcptTo: func(ctx context.Context, conn *raven.Connection, to raven.Path, params map[string]string) error {
            // Only accept for local users
            exists, err := userExists(ctx, to.Mailbox.String())
            if err != nil {
                return fmt.Errorf("temporary error")
            }
            if !exists {
                return fmt.Errorf("user unknown")
            }
            return nil
        },
        OnMessage: storeMessage,
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
        log.Println("Mail server listening on :25")
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

func initSchema() error {
    schema := `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY,
        received_at DATETIME NOT NULL,
        sender TEXT NOT NULL,
        subject TEXT,
        size INTEGER,
        raw BLOB,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS recipients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id TEXT NOT NULL,
        recipient TEXT NOT NULL,
        delivered BOOLEAN DEFAULT FALSE,
        FOREIGN KEY (message_id) REFERENCES messages(id)
    );

    CREATE INDEX IF NOT EXISTS idx_recipients_recipient ON recipients(recipient);
    CREATE INDEX IF NOT EXISTS idx_messages_received ON messages(received_at);

    -- Insert test users
    INSERT OR IGNORE INTO users (email) VALUES ('test@example.com');
    INSERT OR IGNORE INTO users (email) VALUES ('admin@example.com');
    `

    _, err := db.Exec(schema)
    return err
}

func userExists(ctx context.Context, email string) (bool, error) {
    var count int
    err := db.QueryRowContext(ctx, 
        "SELECT COUNT(*) FROM users WHERE LOWER(email) = LOWER(?)", 
        email).Scan(&count)
    return count > 0, err
}

func storeMessage(ctx context.Context, conn *raven.Connection, mail *raven.Mail) error {
    tx, err := db.BeginTx(ctx, nil)
    if err != nil {
        return fmt.Errorf("failed to begin transaction: %w", err)
    }
    defer tx.Rollback()

    // Insert message
    _, err = tx.ExecContext(ctx, `
        INSERT INTO messages (id, received_at, sender, subject, size, raw)
        VALUES (?, ?, ?, ?, ?, ?)
    `,
        mail.ID,
        mail.ReceivedAt,
        mail.Envelope.From.Mailbox.String(),
        mail.Content.Headers.Get("Subject"),
        len(mail.Raw),
        mail.Raw,
    )
    if err != nil {
        return fmt.Errorf("failed to insert message: %w", err)
    }

    // Insert recipients
    for _, rcpt := range mail.Envelope.To {
        _, err = tx.ExecContext(ctx, `
            INSERT INTO recipients (message_id, recipient)
            VALUES (?, ?)
        `, mail.ID, rcpt.Address.Mailbox.String())
        if err != nil {
            return fmt.Errorf("failed to insert recipient: %w", err)
        }
    }

    if err := tx.Commit(); err != nil {
        return fmt.Errorf("failed to commit: %w", err)
    }

    log.Printf("Stored message %s for %d recipients", 
        mail.ID, len(mail.Envelope.To))
    return nil
}
```

---

## BDAT/CHUNKING Support

A server that supports the CHUNKING extension (RFC 3030) for efficient binary message transfer.

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
    config.Addr = ":2525"
    
    // Enable CHUNKING extension
    config.EnableChunking = true
    config.MaxMessageSize = 100 * 1024 * 1024 // 100 MB - BDAT is good for large messages

    config.Callbacks = &raven.Callbacks{
        OnConnect: func(ctx context.Context, conn *raven.Connection) error {
            log.Printf("New connection from %s", conn.RemoteAddr())
            return nil
        },

        OnMailFrom: func(ctx context.Context, conn *raven.Connection, from raven.Path, params map[string]string) error {
            log.Printf("MAIL FROM: %s", from.String())
            return nil
        },

        OnRcptTo: func(ctx context.Context, conn *raven.Connection, to raven.Path, params map[string]string) error {
            log.Printf("RCPT TO: %s", to.String())
            return nil
        },

        // OnBDAT is called for each BDAT chunk received
        OnBDAT: func(ctx context.Context, conn *raven.Connection, size int64, last bool) error {
            log.Printf("BDAT chunk: %d bytes, last=%v", size, last)
            // Return an error here to reject the chunk
            // The server will discard the chunk data and reset the transaction
            return nil
        },

        OnMessage: func(ctx context.Context, conn *raven.Connection, mail *raven.Mail) error {
            log.Printf("Received message %s:", mail.ID)
            log.Printf("  From: %s", mail.Envelope.From.String())
            log.Printf("  To: %d recipients", len(mail.Envelope.To))
            log.Printf("  Size: %d bytes", len(mail.Raw))
            
            // Process the message - works the same whether received via DATA or BDAT
            return processMessage(mail)
        },

        OnDisconnect: func(ctx context.Context, conn *raven.Connection) {
            log.Printf("Disconnected: %s", conn.RemoteAddr())
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
        log.Printf("SMTP server with CHUNKING listening on %s", config.Addr)
        if err := server.ListenAndServe(); err != raven.ErrServerClosed {
            log.Fatal(err)
        }
    }()

    // Wait for shutdown signal
    <-sigChan
    log.Println("Shutting down...")

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    if err := server.Shutdown(ctx); err != nil {
        log.Printf("Shutdown error: %v", err)
    }
    log.Println("Server stopped")
}

func processMessage(mail *raven.Mail) error {
    // Your message processing logic here
    // The mail.Raw contains the full message body regardless of
    // whether it was received via DATA or BDAT commands
    return nil
}
```

### BDAT Protocol Flow

When CHUNKING is enabled, clients can use either DATA or BDAT to send message content:

**DATA command (traditional)**:
```
C: DATA
S: 354 Start mail input; end with <CRLF>.<CRLF>
C: Subject: Test
C: 
C: Hello World
C: .
S: 250 2.0.0 OK, message queued as abc123
```

**BDAT command (chunked)**:
```
C: BDAT 50
C: <50 bytes of binary data>
S: 250 2.0.0 OK, 50 bytes received
C: BDAT 100 LAST
C: <100 bytes of binary data>
S: 250 2.0.0 OK, message queued as abc123
```

### Benefits of CHUNKING

1. **Binary Data**: No dot-stuffing required, binary-safe transfer
2. **Streaming**: Large messages can be sent in manageable chunks
3. **Error Recovery**: Transaction can be aborted mid-transfer with RSET
4. **Size Declaration**: Each chunk declares its exact size upfront

---

## Multi-Domain Virtual Hosting

Handle multiple domains with different configurations.

```go
package main

import (
    "context"
    "fmt"
    "log"
    "strings"

    "github.com/synqronlabs/raven"
)

// DomainConfig holds per-domain settings
type DomainConfig struct {
    Name         string
    MaxMsgSize   int64
    LocalUsers   []string
    ForwardTo    string // Forward all mail to this address
    RejectUnknown bool
}

var domains = map[string]*DomainConfig{
    "example.com": {
        Name:          "example.com",
        MaxMsgSize:    25 * 1024 * 1024,
        LocalUsers:    []string{"admin", "info", "support"},
        RejectUnknown: true,
    },
    "example.org": {
        Name:       "example.org",
        MaxMsgSize: 10 * 1024 * 1024,
        ForwardTo:  "catchall@example.com",
    },
    "test.example.com": {
        Name:          "test.example.com",
        MaxMsgSize:    5 * 1024 * 1024,
        RejectUnknown: false, // Accept all for testing
    },
}

func main() {
    config := raven.DefaultServerConfig()
    config.Hostname = "mx.example.com"
    config.Addr = ":25"
    config.MaxMessageSize = 50 * 1024 * 1024 // Global max

    config.Callbacks = &raven.Callbacks{
        OnRcptTo:  validateRecipient,
        OnMessage: routeMessage,
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
        log.Println("Multi-domain server listening on :25")
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

func validateRecipient(ctx context.Context, conn *raven.Connection, to raven.Path, params map[string]string) error {
    domain := strings.ToLower(to.Mailbox.Domain)
    localPart := strings.ToLower(to.Mailbox.LocalPart)

    domainCfg, ok := domains[domain]
    if !ok {
        return fmt.Errorf("domain not handled here")
    }

    // Check if we should reject unknown users
    if domainCfg.RejectUnknown {
        found := false
        for _, user := range domainCfg.LocalUsers {
            if strings.ToLower(user) == localPart {
                found = true
                break
            }
        }
        if !found {
            return fmt.Errorf("user unknown")
        }
    }

    return nil
}

func routeMessage(ctx context.Context, conn *raven.Connection, mail *raven.Mail) error {
    // Group recipients by domain
    byDomain := make(map[string][]string)
    
    for _, rcpt := range mail.Envelope.To {
        domain := strings.ToLower(rcpt.Address.Mailbox.Domain)
        addr := rcpt.Address.Mailbox.String()
        byDomain[domain] = append(byDomain[domain], addr)
    }

    // Process each domain
    for domain, recipients := range byDomain {
        domainCfg, ok := domains[domain]
        if !ok {
            log.Printf("Unknown domain %s, skipping", domain)
            continue
        }

        // Check message size for this domain
        if domainCfg.MaxMsgSize > 0 && int64(len(mail.Raw)) > domainCfg.MaxMsgSize {
            log.Printf("Message too large for domain %s", domain)
            continue
        }

        // Route message
        if domainCfg.ForwardTo != "" {
            log.Printf("Forwarding to %s for domain %s", 
                domainCfg.ForwardTo, domain)
            // Forward message
            forwardMessage(mail, domainCfg.ForwardTo)
        } else {
            // Deliver locally
            for _, rcpt := range recipients {
                log.Printf("Delivering to local mailbox: %s", rcpt)
                deliverLocal(mail, rcpt)
            }
        }
    }

    return nil
}

func forwardMessage(mail *raven.Mail, to string) error {
    // Implement forwarding logic
    return nil
}

func deliverLocal(mail *raven.Mail, to string) error {
    // Implement local delivery logic
    return nil
}
```

---

## See Also

- [Getting Started](getting-started.md) - Basic setup guide
- [Configuration](configuration.md) - All configuration options
- [Callbacks](callbacks.md) - Callback system details
- [TLS & Authentication](tls-and-auth.md) - Security configuration
