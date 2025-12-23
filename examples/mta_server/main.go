// An MTA/MX server accepts incoming mail for specific domains that it handles.
// This example shows:
//   - Domain-based mail acceptance (only accepting mail for configured domains)
//   - Full email authentication (SPF, DKIM, DMARC verification)
//   - ARC verification for forwarded messages
//   - Rate limiting and connection management
//   - Mailbox validation and delivery
//   - Spam score calculation based on authentication results
package main

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/synqronlabs/raven"
	"github.com/synqronlabs/raven/arc"
	"github.com/synqronlabs/raven/dkim"
	"github.com/synqronlabs/raven/dmarc"
	ravendns "github.com/synqronlabs/raven/dns"
	"github.com/synqronlabs/raven/spf"
)

// =============================================================================
// Domain Configuration
// =============================================================================

// DomainConfig holds configuration for a hosted domain.
type DomainConfig struct {
	Domain        string
	MXPriority    int
	CatchAll      bool   // Accept mail for any address @domain
	CatchAllAddr  string // Where to deliver catch-all mail
	MaxMailboxes  int
	MaxMessageMB  int64
	RequireDMARC  bool // Require DMARC pass for delivery
	SpamThreshold int  // Spam score threshold (0-100)
}

// LocalDomains holds the domains this MX server handles.
// TODO: Replace with database/API for dynamic domain management.
var localDomains = map[string]*DomainConfig{
	"example.com": {
		Domain:        "example.com",
		MXPriority:    10,
		CatchAll:      false,
		MaxMailboxes:  1000,
		MaxMessageMB:  25,
		RequireDMARC:  false,
		SpamThreshold: 50,
	},
	"example.org": {
		Domain:        "example.org",
		MXPriority:    10,
		CatchAll:      true,
		CatchAllAddr:  "postmaster@example.org",
		MaxMailboxes:  500,
		MaxMessageMB:  10,
		RequireDMARC:  false,
		SpamThreshold: 40,
	},
}

// =============================================================================
// Mailbox Database
// =============================================================================

// Mailbox represents a user mailbox.
type Mailbox struct {
	Address     string   `json:"address"`
	DisplayName string   `json:"display_name"`
	Active      bool     `json:"active"`
	QuotaMB     int64    `json:"quota_mb"`
	UsedMB      int64    `json:"used_mb"`
	Aliases     []string `json:"aliases"`
	ForwardTo   []string `json:"forward_to,omitempty"`
	AutoReply   string   `json:"auto_reply,omitempty"`
}

// MailboxDB simulates a mailbox database.
// TODO: Replace with actual database (PostgreSQL, MySQL, etc.)
type MailboxDB struct {
	mu        sync.RWMutex
	mailboxes map[string]*Mailbox // key: lowercase email address
	aliases   map[string]string   // alias -> primary address mapping
}

var mailboxDB = &MailboxDB{
	mailboxes: map[string]*Mailbox{
		"alice@example.com": {
			Address:     "alice@example.com",
			DisplayName: "Alice Smith",
			Active:      true,
			QuotaMB:     1024,
			UsedMB:      256,
			Aliases:     []string{"alice.smith@example.com"},
		},
		"bob@example.com": {
			Address:     "bob@example.com",
			DisplayName: "Bob Jones",
			Active:      true,
			QuotaMB:     512,
			UsedMB:      128,
		},
		"postmaster@example.com": {
			Address:     "postmaster@example.com",
			DisplayName: "Postmaster",
			Active:      true,
			QuotaMB:     2048,
		},
		"admin@example.org": {
			Address:     "admin@example.org",
			DisplayName: "Administrator",
			Active:      true,
			QuotaMB:     1024,
		},
		"postmaster@example.org": {
			Address:     "postmaster@example.org",
			DisplayName: "Postmaster",
			Active:      true,
			QuotaMB:     2048,
		},
	},
	aliases: map[string]string{
		"alice.smith@example.com": "alice@example.com",
	},
}

// LookupMailbox looks up a mailbox by address.
func (db *MailboxDB) LookupMailbox(address string) (*Mailbox, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	addr := strings.ToLower(address)

	// Check direct mailbox
	if mb, ok := db.mailboxes[addr]; ok {
		return mb, true
	}

	// Check aliases
	if primary, ok := db.aliases[addr]; ok {
		if mb, ok := db.mailboxes[primary]; ok {
			return mb, true
		}
	}

	return nil, false
}

// =============================================================================
// Message Storage
// =============================================================================

// StoredMessage represents a delivered message.
type StoredMessage struct {
	ID          string            `json:"id"`
	Mailbox     string            `json:"mailbox"`
	From        string            `json:"from"`
	To          string            `json:"to"`
	Subject     string            `json:"subject"`
	ReceivedAt  time.Time         `json:"received_at"`
	Size        int               `json:"size"`
	SpamScore   int               `json:"spam_score"`
	AuthResults map[string]string `json:"auth_results"`
	IsSpam      bool              `json:"is_spam"`
	Headers     map[string]string `json:"headers"`
}

// MessageStore simulates message storage.
// TODO: Replace with actual storage (Maildir, database, object storage, etc.)
type MessageStore struct {
	mu       sync.Mutex
	messages map[string][]StoredMessage // mailbox -> messages
}

var messageStore = &MessageStore{
	messages: make(map[string][]StoredMessage),
}

// Store stores a message in the mailbox.
func (s *MessageStore) Store(msg StoredMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.messages[msg.Mailbox] = append(s.messages[msg.Mailbox], msg)

	// In production, you would:
	// - Write to Maildir format
	// - Store in database
	// - Index for search
	// - Notify connected IMAP clients

	return nil
}

// =============================================================================
// Spam Scoring
// =============================================================================

// SpamScore calculates a spam score based on authentication results.
// Returns a score from 0 (definitely not spam) to 100 (definitely spam).
func calculateSpamScore(c *raven.Context) int {
	score := 0

	// SPF check
	if statusVal, ok := c.Get(spf.ContextKeySPFStatus); ok {
		if status, ok := statusVal.(spf.Status); ok {
			switch status {
			case spf.StatusPass:
				score -= 10
			case spf.StatusFail:
				score += 30
			case spf.StatusSoftfail:
				score += 15
			case spf.StatusNeutral, spf.StatusNone:
				score += 5
			case spf.StatusTemperror, spf.StatusPermerror:
				score += 10
			}
		}
	}

	// DKIM check
	if resultsVal, ok := c.Get(dkim.ContextKeyDKIMResults); ok {
		if results, ok := resultsVal.([]dkim.Result); ok {
			hasPass := false
			hasFail := false
			for _, r := range results {
				if r.Status == dkim.StatusPass {
					hasPass = true
				} else if r.Status == dkim.StatusFail {
					hasFail = true
				}
			}
			if hasPass {
				score -= 15
			}
			if hasFail {
				score += 25
			}
			if len(results) == 0 {
				score += 5 // No DKIM signature
			}
		}
	}

	// DMARC check
	if resultVal, ok := c.Get(dmarc.ContextKeyDMARCResult); ok {
		if result, ok := resultVal.(*dmarc.Result); ok {
			switch result.Status {
			case dmarc.StatusPass:
				score -= 20
			case dmarc.StatusFail:
				score += 35
				if result.Reject {
					score += 20 // Policy says reject
				}
			}
		}
	}

	// ARC check (for forwarded mail)
	if resultVal, ok := c.Get(arc.ContextKeyARCResult); ok {
		if result, ok := resultVal.(*arc.Result); ok {
			switch result.Status {
			case arc.StatusPass:
				score -= 5 // Valid ARC chain reduces suspicion
			case arc.StatusFail:
				score += 15
			}
		}
	}

	// Clamp score to 0-100
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}

// =============================================================================
// TLS Configuration
// =============================================================================

func loadTLSConfig() (*tls.Config, error) {
	// TODO: Load actual certificates
	// cert, err := tls.LoadX509KeyPair("/etc/ssl/certs/mx.example.com.crt", "/etc/ssl/private/mx.example.com.key")
	// if err != nil {
	//     return nil, err
	// }

	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		// Certificates: []tls.Certificate{cert},
	}, nil
}

// =============================================================================
// DNS Resolvers
// =============================================================================

var (
	dnsResolver ravendns.Resolver
	spfResolver spf.Resolver
)

func initResolvers() {
	dnsResolver = ravendns.NewResolver(ravendns.ResolverConfig{
		Nameservers: []string{"8.8.8.8:53", "1.1.1.1:53"},
		DNSSEC:      true,
		Timeout:     10 * time.Second,
	})

	spfResolver = spf.NewResolver(spf.ResolverConfig{
		DNSSEC:  true,
		Timeout: 10 * time.Second,
	})
}

// =============================================================================
// Custom Middleware
// =============================================================================

// validateLocalDomain checks if we accept mail for the recipient domain.
func validateLocalDomain(c *raven.Context) *raven.Response {
	to := c.Request.To
	if to == nil {
		return c.Next()
	}

	domain := strings.ToLower(to.Mailbox.Domain)
	domainConfig, isLocal := localDomains[domain]

	if !isLocal {
		return &raven.Response{
			Code:    550,
			Message: fmt.Sprintf("5.1.1 User not local; we do not relay for %s", domain),
		}
	}

	// Store domain config for later use
	c.Set("domain_config", domainConfig)

	return c.Next()
}

// validateMailbox checks if the recipient mailbox exists.
func validateMailbox(c *raven.Context) *raven.Response {
	logger := slog.Default()
	to := c.Request.To
	if to == nil {
		return c.Next()
	}

	address := to.Mailbox.String()
	domain := strings.ToLower(to.Mailbox.Domain)

	// Look up mailbox
	mailbox, exists := mailboxDB.LookupMailbox(address)

	if !exists {
		// Check for catch-all
		domainConfig, _ := localDomains[domain]
		if domainConfig != nil && domainConfig.CatchAll {
			logger.Info("using catch-all for unknown address",
				slog.String("address", address),
				slog.String("catch_all", domainConfig.CatchAllAddr),
			)
			c.Set("catch_all", true)
			c.Set("catch_all_addr", domainConfig.CatchAllAddr)
			return c.Next()
		}

		return &raven.Response{
			Code:    550,
			Message: fmt.Sprintf("5.1.1 Mailbox <%s> does not exist", address),
		}
	}

	if !mailbox.Active {
		return &raven.Response{
			Code:    550,
			Message: fmt.Sprintf("5.2.1 Mailbox <%s> is disabled", address),
		}
	}

	// Check quota
	// TODO: Calculate actual message size
	estimatedSize := int64(c.Mail.Content.Headers.Count("Content-Length"))
	if estimatedSize == 0 {
		estimatedSize = 1 // Assume at least 1MB for quota check
	}

	if mailbox.UsedMB+estimatedSize > mailbox.QuotaMB {
		return &raven.Response{
			Code:    452,
			Message: fmt.Sprintf("4.2.2 Mailbox <%s> is full", address),
		}
	}

	// Store mailbox for delivery
	c.Set("mailbox", mailbox)

	return c.Next()
}

// deliverMessage stores the message in the recipient's mailbox.
func deliverMessage(c *raven.Context) *raven.Response {
	logger := slog.Default()
	mail := c.Mail

	// Calculate spam score
	spamScore := calculateSpamScore(c)
	c.Set("spam_score", spamScore)

	// Check spam threshold
	var domainConfig *DomainConfig
	if configVal, ok := c.Get("domain_config"); ok {
		domainConfig = configVal.(*DomainConfig)
	}

	isSpam := false
	if domainConfig != nil && spamScore >= domainConfig.SpamThreshold {
		isSpam = true
		logger.Warn("message marked as spam",
			slog.Int("score", spamScore),
			slog.Int("threshold", domainConfig.SpamThreshold),
		)
	}

	// Check DMARC requirement
	if domainConfig != nil && domainConfig.RequireDMARC {
		if statusVal, ok := c.Get(dmarc.ContextKeyDMARCStatus); ok {
			if status, ok := statusVal.(dmarc.Status); ok && status != dmarc.StatusPass {
				return &raven.Response{
					Code:    550,
					Message: "5.7.1 DMARC verification required but failed",
				}
			}
		}
	}

	// Get authentication results for storage
	authResults := make(map[string]string)

	if statusVal, ok := c.Get(spf.ContextKeySPFStatus); ok {
		if status, ok := statusVal.(spf.Status); ok {
			authResults["spf"] = string(status)
		}
	}

	if statusVal, ok := c.Get(dkim.ContextKeyDKIMStatus); ok {
		if status, ok := statusVal.(dkim.Status); ok {
			authResults["dkim"] = string(status)
		}
	}

	if statusVal, ok := c.Get(dmarc.ContextKeyDMARCStatus); ok {
		if status, ok := statusVal.(dmarc.Status); ok {
			authResults["dmarc"] = string(status)
		}
	}

	// Determine delivery address
	deliveryAddr := ""
	if mailboxVal, ok := c.Get("mailbox"); ok {
		deliveryAddr = mailboxVal.(*Mailbox).Address
	} else if catchAllVal, ok := c.Get("catch_all"); ok && catchAllVal.(bool) {
		if addrVal, ok := c.Get("catch_all_addr"); ok {
			deliveryAddr = addrVal.(string)
		}
	}

	if deliveryAddr == "" {
		return c.TempError("Internal error: no delivery address")
	}

	// Create stored message
	storedMsg := StoredMessage{
		ID:          fmt.Sprintf("%s-%d", c.Connection.Trace.ID, time.Now().UnixNano()),
		Mailbox:     deliveryAddr,
		From:        mail.Envelope.From.Mailbox.String(),
		To:          deliveryAddr,
		Subject:     mail.Content.Headers.Get("Subject"),
		ReceivedAt:  time.Now(),
		Size:        len(mail.Content.Body),
		SpamScore:   spamScore,
		AuthResults: authResults,
		IsSpam:      isSpam,
		Headers: map[string]string{
			"From":       mail.Content.Headers.Get("From"),
			"To":         mail.Content.Headers.Get("To"),
			"Date":       mail.Content.Headers.Get("Date"),
			"Message-ID": mail.Content.Headers.Get("Message-ID"),
		},
	}

	// Store the message
	if err := messageStore.Store(storedMsg); err != nil {
		logger.Error("failed to store message",
			slog.String("id", storedMsg.ID),
			slog.Any("error", err),
		)
		return c.TempError("Failed to deliver message")
	}

	logger.Info("message delivered",
		slog.String("id", storedMsg.ID),
		slog.String("from", storedMsg.From),
		slog.String("to", storedMsg.To),
		slog.Int("size", storedMsg.Size),
		slog.Int("spam_score", spamScore),
		slog.Bool("is_spam", isSpam),
	)

	// Log authentication results
	for auth, result := range authResults {
		logger.Debug("authentication result",
			slog.String("id", storedMsg.ID),
			slog.String("auth", auth),
			slog.String("result", result),
		)
	}

	return c.OKf("Message delivered to %s [%s]", deliveryAddr, storedMsg.ID)
}

// =============================================================================
// Connection Handlers
// =============================================================================

// logConnection logs connection details.
func logConnection(c *raven.Context) *raven.Response {
	logger := slog.Default()

	// Perform reverse DNS lookup
	remoteAddr := c.Connection.RemoteAddr()
	var reverseDNS string
	if tcpAddr, ok := remoteAddr.(*net.TCPAddr); ok {
		names, err := net.LookupAddr(tcpAddr.IP.String())
		if err == nil && len(names) > 0 {
			reverseDNS = names[0]
		}
	}

	logger.Info("new connection",
		slog.String("remote", remoteAddr.String()),
		slog.String("reverse_dns", reverseDNS),
		slog.String("conn_id", c.Connection.Trace.ID),
	)

	if reverseDNS != "" {
		c.Set("reverse_dns", reverseDNS)
	}

	return c.Next()
}

// =============================================================================
// Main Server
// =============================================================================

func main() {
	// Set up structured logging
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	// Initialize DNS resolvers
	initResolvers()

	// Load TLS configuration
	tlsConfig, err := loadTLSConfig()
	if err != nil {
		logger.Error("failed to load TLS config", slog.Any("error", err))
		os.Exit(1)
	}

	// Log configured domains
	for domain := range localDomains {
		logger.Info("accepting mail for domain", slog.String("domain", domain))
	}

	// Create rate limiter
	rateLimiter := raven.NewRateLimiter(100, time.Minute) // 100 connections/min per IP

	// Create the MX server
	server := raven.New("mx.example.com").
		Addr(":25").
		Logger(logger).
		TLS(tlsConfig).               // Enable STARTTLS
		MaxMessageSize(25*1024*1024). // 25MB max
		MaxRecipients(100).
		ReadTimeout(5*time.Minute).
		WriteTimeout(5*time.Minute).
		DataTimeout(10*time.Minute).
		IdleTimeout(5*time.Minute).
		MaxReceivedHeaders(100). // Loop detection
		Extension(raven.DSN()).
		Extension(raven.Chunking()).
		OnConnect(
			raven.Recovery(logger),
			raven.Logger(logger),
			raven.RateLimit(rateLimiter),
			logConnection,
		).
		OnMailFrom(
			// SPF verification middleware
			// Checks if the sending server is authorized to send for the domain
			spf.Middleware(spf.MiddlewareConfig{
				Resolver:            spfResolver,
				Policy:              spf.PolicyRejectFail, // Reject on hard SPF fail
				Logger:              logger,
				SkipIfAuthenticated: false, // Always check SPF for inbound mail
				Timeout:             20 * time.Second,
			}),
		).
		OnRcptTo(
			validateLocalDomain, // Check we accept mail for this domain
			validateMailbox,     // Check mailbox exists and has quota
		).
		OnData(
			// DKIM verification middleware
			// Verifies DKIM signatures on incoming messages
			dkim.Middleware(dkim.MiddlewareConfig{
				Resolver:            dnsResolver,
				Logger:              logger,
				MinRSAKeyBits:       1024,
				SkipIfAuthenticated: false,
				RejectOnFail:        false, // Don't reject on DKIM fail (use DMARC for policy)
				RequireSignature:    false, // Allow unsigned messages
				Timeout:             30 * time.Second,
			}),
			// DMARC verification middleware
			// Must run after SPF and DKIM
			// Evaluates DMARC policy based on SPF and DKIM results
			dmarc.Middleware(dmarc.MiddlewareConfig{
				Resolver:              dnsResolver,
				Policy:                dmarc.MiddlewarePolicyEnforce, // Enforce DMARC policy
				Logger:                logger,
				SkipIfAuthenticated:   false,
				ApplyRandomPercentage: true, // Respect pct= field
				Timeout:               30 * time.Second,
			}),
			// ARC verification middleware
			// Must run after SPF, DKIM, and DMARC
			// Verifies ARC chain for forwarded messages
			arc.Middleware(arc.MiddlewareConfig{
				Resolver:            dnsResolver,
				Logger:              logger,
				MinRSAKeyBits:       1024,
				SkipIfAuthenticated: false,
				TrustedSealers: []string{
					// List of domains whose ARC seals you trust
					"google.com",
					"microsoft.com",
					"yahoo.com",
				},
				Timeout: 30 * time.Second,
			}),
		).
		OnMessage(
			deliverMessage, // Store the message
		)

	// Start the server
	logger.Info("starting MX server",
		slog.String("hostname", "mx.example.com"),
		slog.String("addr", ":25"),
	)

	if err := server.ListenAndServe(); err != raven.ErrServerClosed {
		logger.Error("server error", slog.Any("error", err))
		os.Exit(1)
	}
}
