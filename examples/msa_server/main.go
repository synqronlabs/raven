// An MSA is responsible for accepting mail from authenticated users (mail clients)
// and submitting it for delivery. This example shows:
//   - STARTTLS support on port 587 (submission)
//   - Implicit TLS on port 465 (submissions)
//   - SMTP authentication with PLAIN and LOGIN mechanisms
//   - TLS requirement enforcement before authentication
//   - Envelope validation to ensure authenticated users can only send from their addresses
//   - Message queueing simulation
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/synqronlabs/raven"
)

// =============================================================================
// User Database (Replace with actual database/API in production)
// =============================================================================

// User represents an authenticated user in the system.
type User struct {
	Username     string   `json:"username"`
	PasswordHash string   `json:"password_hash"` // In production, use bcrypt or argon2
	AllowedFrom  []string `json:"allowed_from"`  // Email addresses this user can send from
	DailyLimit   int      `json:"daily_limit"`   // Maximum emails per day
	Enabled      bool     `json:"enabled"`
}

// UserDB simulates a user database.
// TODO: Replace with an actual database (PostgreSQL, MySQL, etc.) or
// integrate with your existing user management system (LDAP, OAuth, etc.)
var userDB = map[string]User{
	"alice": {
		Username:     "alice",
		PasswordHash: "password123", // In production: use bcrypt.CompareHashAndPassword
		AllowedFrom:  []string{"alice@example.com", "alice.smith@example.com"},
		DailyLimit:   1000,
		Enabled:      true,
	},
	"bob": {
		Username:     "bob",
		PasswordHash: "secretpass", // In production: use bcrypt.CompareHashAndPassword
		AllowedFrom:  []string{"bob@example.com"},
		DailyLimit:   500,
		Enabled:      true,
	},
	"service": {
		Username:     "service",
		PasswordHash: "svc-token-12345",
		AllowedFrom:  []string{"noreply@example.com", "notifications@example.com"},
		DailyLimit:   10000,
		Enabled:      true,
	},
}

// =============================================================================
// Rate Limiting / Usage Tracking
// =============================================================================

// UsageTracker tracks email sending usage per user.
// TODO: Replace with Redis or database-backed storage for distributed systems.
type UsageTracker struct {
	mu     sync.RWMutex
	counts map[string]*DailyCount
}

type DailyCount struct {
	Count int
	Date  string
}

var usageTracker = &UsageTracker{
	counts: make(map[string]*DailyCount),
}

func (u *UsageTracker) IncrementAndCheck(username string, limit int) bool {
	u.mu.Lock()
	defer u.mu.Unlock()

	today := time.Now().Format("2006-01-02")
	count, exists := u.counts[username]

	if !exists || count.Date != today {
		u.counts[username] = &DailyCount{Count: 1, Date: today}
		return true
	}

	if count.Count >= limit {
		return false
	}

	count.Count++
	return true
}

// =============================================================================
// Message Queue (Replace with actual queue in production)
// =============================================================================

// QueuedMessage represents a message waiting to be delivered.
type QueuedMessage struct {
	ID          string    `json:"id"`
	From        string    `json:"from"`
	To          []string  `json:"to"`
	AuthUser    string    `json:"auth_user"`
	SubmittedAt time.Time `json:"submitted_at"`
	Size        int       `json:"size"`
	Priority    int       `json:"priority"`
}

// MessageQueue simulates a message queue.
// TODO: Replace with an actual message queue (RabbitMQ, Redis, PostgreSQL, etc.)
type MessageQueue struct {
	mu       sync.Mutex
	messages []QueuedMessage
}

var messageQueue = &MessageQueue{
	messages: make([]QueuedMessage, 0),
}

func (q *MessageQueue) Enqueue(msg QueuedMessage) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.messages = append(q.messages, msg)

	// In production, you would:
	// - Persist to database
	// - Push to message queue (RabbitMQ, Kafka, etc.)
	// - Trigger delivery workers

	return nil
}

// =============================================================================
// TLS Configuration
// =============================================================================

// loadTLSConfig loads TLS certificates for the server.
// TODO: Replace with your actual certificate paths or use autocert for Let's Encrypt.
func loadTLSConfig() (*tls.Config, error) {
	// Example using self-signed certificates for development.
	// In production, use certificates from Let's Encrypt or your CA.
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		return nil, fmt.Errorf("loading certificate: %w", err)
	}

	// For this example, we'll create a placeholder config.
	// You MUST replace this with actual certificates in production.
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: true,
		Certificates:             []tls.Certificate{cert},
	}, nil
}

// =============================================================================
// Authentication Handler
// =============================================================================

// authenticateUser validates user credentials.
// This is called by Raven when a client attempts to authenticate.
func authenticateUser(c *raven.Context, mechanism, identity, password string) *raven.Response {
	logger := slog.Default()

	// Look up user in database
	user, exists := userDB[identity]
	if !exists {
		logger.Warn("authentication failed: user not found",
			slog.String("username", identity),
			slog.String("mechanism", mechanism),
			slog.String("remote", c.Connection.RemoteAddr().String()),
		)
		return &raven.Response{
			Code:    535,
			Message: "5.7.8 Authentication credentials invalid",
		}
	}

	// Check if user is enabled
	if !user.Enabled {
		logger.Warn("authentication failed: user disabled",
			slog.String("username", identity),
			slog.String("remote", c.Connection.RemoteAddr().String()),
		)
		return &raven.Response{
			Code:    535,
			Message: "5.7.8 Account disabled",
		}
	}

	// Verify password
	// TODO: In production, use bcrypt.CompareHashAndPassword or similar
	if user.PasswordHash != password {
		logger.Warn("authentication failed: invalid password",
			slog.String("username", identity),
			slog.String("remote", c.Connection.RemoteAddr().String()),
		)
		return &raven.Response{
			Code:    535,
			Message: "5.7.8 Authentication credentials invalid",
		}
	}

	logger.Info("user authenticated",
		slog.String("username", identity),
		slog.String("mechanism", mechanism),
		slog.String("remote", c.Connection.RemoteAddr().String()),
	)

	// Return nil to indicate successful authentication
	return nil
}

// =============================================================================
// Custom Middleware
// =============================================================================

// validateSenderAddress ensures the authenticated user can send from the given address.
func validateSenderAddress(c *raven.Context) *raven.Response {
	logger := slog.Default()

	from := c.Request.From
	if from == nil || from.IsNull() {
		// Null sender (bounces) - not allowed for submission
		return &raven.Response{
			Code:    550,
			Message: "5.7.1 Null sender not allowed for submission",
		}
	}

	identity := c.AuthIdentity()
	user, exists := userDB[identity]
	if !exists {
		return c.TempError("Internal error: user not found")
	}

	senderAddr := strings.ToLower(from.Mailbox.String())

	// Check if user is allowed to send from this address
	allowed := false
	for _, addr := range user.AllowedFrom {
		if strings.ToLower(addr) == senderAddr {
			allowed = true
			break
		}
	}

	if !allowed {
		logger.Warn("sender address not allowed",
			slog.String("username", user.Username),
			slog.String("attempted_from", senderAddr),
			slog.String("allowed", strings.Join(user.AllowedFrom, ", ")),
		)
		return &raven.Response{
			Code:    550,
			Message: fmt.Sprintf("5.7.1 Not authorized to send from <%s>", from.Mailbox.String()),
		}
	}

	// Check daily sending limit
	if !usageTracker.IncrementAndCheck(user.Username, user.DailyLimit) {
		logger.Warn("daily limit exceeded",
			slog.String("username", user.Username),
			slog.Int("limit", user.DailyLimit),
		)
		return &raven.Response{
			Code:    452,
			Message: "4.7.1 Daily sending limit exceeded, try again tomorrow",
		}
	}

	logger.Info("sender validated",
		slog.String("username", user.Username),
		slog.String("from", senderAddr),
	)

	return c.Next()
}

// queueMessage handles the final message processing and queueing.
func queueMessage(c *raven.Context) *raven.Response {
	logger := slog.Default()
	mail := c.Mail

	// Build recipient list
	recipients := make([]string, 0, len(mail.Envelope.To))
	for _, rcpt := range mail.Envelope.To {
		recipients = append(recipients, rcpt.Address.Mailbox.String())
	}

	// Create queue entry
	queuedMsg := QueuedMessage{
		ID:          fmt.Sprintf("%s-%d", c.Connection.Trace.ID, time.Now().UnixNano()),
		From:        mail.Envelope.From.Mailbox.String(),
		To:          recipients,
		AuthUser:    c.AuthIdentity(),
		SubmittedAt: time.Now(),
		Size:        len(mail.Content.Body),
		Priority:    determinePriority(mail),
	}

	// Queue the message
	if err := messageQueue.Enqueue(queuedMsg); err != nil {
		logger.Error("failed to queue message",
			slog.String("id", queuedMsg.ID),
			slog.Any("error", err),
		)
		return c.TempError("Failed to queue message, please try again")
	}

	logger.Info("message queued for delivery",
		slog.String("id", queuedMsg.ID),
		slog.String("from", queuedMsg.From),
		slog.Int("recipients", len(queuedMsg.To)),
		slog.Int("size", queuedMsg.Size),
		slog.String("auth_user", queuedMsg.AuthUser),
	)

	// Log to stdout for demonstration
	jsonMsg, _ := json.MarshalIndent(queuedMsg, "", "  ")
	fmt.Printf("\nMessage Queued:\n%s\n\n", string(jsonMsg))

	return c.OKf("Message queued as %s", queuedMsg.ID)
}

// determinePriority extracts priority from mail headers.
func determinePriority(mail *raven.Mail) int {
	priority := mail.Content.Headers.Get("X-Priority")
	switch priority {
	case "1", "2":
		return 1 // High
	case "4", "5":
		return 3 // Low
	default:
		return 2 // Normal
	}
}

// =============================================================================
// Server Setup
// =============================================================================

func main() {
	// Set up structured logging
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	// Load TLS configuration
	tlsConfig, err := loadTLSConfig()
	if err != nil {
		logger.Error("failed to load TLS config", slog.Any("error", err))
		os.Exit(1)
	}

	// ==========================================================================
	// Option 1: STARTTLS Server (Port 587 - Submission)
	// ==========================================================================
	// This server starts unencrypted but supports STARTTLS upgrade.
	// Clients connect, upgrade to TLS, then authenticate.

	submissionServer := raven.New("mail.example.com").
		Addr(":587").
		Logger(logger).
		TLS(tlsConfig).               // Enable STARTTLS
		RequireTLS().                 // Require TLS before authentication
		MaxMessageSize(25*1024*1024). // 25MB max message size
		MaxRecipients(100).           // Max 100 recipients per message
		ReadTimeout(5*time.Minute).   // Connection read timeout
		WriteTimeout(5*time.Minute).  // Connection write timeout
		DataTimeout(10*time.Minute).  // Message data timeout
		Extension(raven.DSN()).       // Enable Delivery Status Notifications
		Extension(raven.Chunking()).  // Enable CHUNKING/BDAT for large messages
		EnableLoginAuth().            // Enable deprecated LOGIN auth for legacy clients
		Auth(                         // Configure authentication
			[]string{"PLAIN", "LOGIN"}, // Supported mechanisms
			authenticateUser,           // Authentication handler
		).
		RequireAuth(). // Require authentication for mail submission
		OnConnect(
			raven.Recovery(logger), // Recover from panics
			raven.Logger(logger),   // Log all commands
			raven.RateLimit(raven.NewRateLimiter(50, time.Minute)), // 50 connections/min per IP
		).
		OnMailFrom(
			validateSenderAddress, // Validate sender is allowed
		).
		OnMessage(
			queueMessage, // Queue the message for delivery
		)

	// ==========================================================================
	// Option 2: Implicit TLS Server (Port 465 - Submissions)
	// ==========================================================================
	// This server uses TLS from the start (like HTTPS).
	// No STARTTLS needed - connection is encrypted immediately.

	submissionsServer := raven.New("mail.example.com").
		Addr(":465").
		Logger(logger).
		TLS(tlsConfig).
		RequireTLS().
		MaxMessageSize(25*1024*1024).
		MaxRecipients(100).
		ReadTimeout(5*time.Minute).
		WriteTimeout(5*time.Minute).
		DataTimeout(10*time.Minute).
		Extension(raven.DSN()).
		Extension(raven.Chunking()).
		EnableLoginAuth().
		Auth(
			[]string{"PLAIN", "LOGIN"},
			authenticateUser,
		).
		RequireAuth().
		OnConnect(
			raven.Recovery(logger),
			raven.Logger(logger),
			raven.RateLimit(raven.NewRateLimiter(50, time.Minute)),
		).
		OnMailFrom(
			validateSenderAddress,
		).
		OnMessage(
			queueMessage,
		)

	// ==========================================================================
	// Start Both Servers
	// ==========================================================================

	logger.Info("starting MSA servers",
		slog.String("starttls_port", "587"),
		slog.String("implicit_tls_port", "465"),
	)

	// Start STARTTLS server in goroutine
	go func() {
		logger.Info("STARTTLS submission server starting on :587")
		if err := submissionServer.ListenAndServe(); err != raven.ErrServerClosed {
			logger.Error("submission server error", slog.Any("error", err))
		}
	}()

	// Start implicit TLS server (blocks)
	logger.Info("Implicit TLS submission server starting on :465")
	if err := submissionsServer.ListenAndServeTLS(); err != raven.ErrServerClosed {
		logger.Error("submissions server error", slog.Any("error", err))
	}
}
