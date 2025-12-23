// A Relay server accepts mail from trusted/whitelisted hosts and forwards it
// to the destination MX servers. This example shows:
//   - IP-based whitelisting for trusted senders
//   - MX record lookup and delivery
//   - DKIM signing of outgoing messages
//   - ARC sealing for forwarded messages
//   - Opportunistic TLS for outbound connections
//   - Connection pooling for efficient delivery
package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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
	ravendns "github.com/synqronlabs/raven/dns"
)

// =============================================================================
// Configuration
// =============================================================================

// RelayConfig holds the relay server configuration.
type RelayConfig struct {
	Hostname       string
	ListenAddr     string
	WhitelistedIPs []string
	WhitelistCIDRs []string
	SigningDomains map[string]*DomainSigningConfig
}

// DomainSigningConfig holds DKIM/ARC signing configuration for a domain.
type DomainSigningConfig struct {
	Domain     string
	Selector   string
	PrivateKey crypto.Signer
}

// Default configuration
// TODO: Replace with your actual configuration (from file, environment, etc.)
var config = RelayConfig{
	Hostname:   "relay.example.com",
	ListenAddr: ":25",
	// Whitelisted IPs that can relay through this server
	// TODO: Replace with your actual trusted IP addresses
	WhitelistedIPs: []string{
		"127.0.0.1",
		"10.0.0.1",
		"192.168.1.100",
	},
	// Whitelisted CIDR networks
	WhitelistCIDRs: []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	},
	SigningDomains: make(map[string]*DomainSigningConfig),
}

// =============================================================================
// Signing Key Management
// =============================================================================

// KeyStore manages DKIM/ARC signing keys for domains.
// TODO: Replace with actual key storage (HSM, Vault, encrypted files, etc.)
type KeyStore struct {
	mu   sync.RWMutex
	keys map[string]*DomainSigningConfig
}

var keyStore = &KeyStore{
	keys: make(map[string]*DomainSigningConfig),
}

// GetSigningConfig returns the signing configuration for a domain.
func (k *KeyStore) GetSigningConfig(domain string) *DomainSigningConfig {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.keys[strings.ToLower(domain)]
}

// AddSigningConfig adds a signing configuration for a domain.
func (k *KeyStore) AddSigningConfig(config *DomainSigningConfig) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.keys[strings.ToLower(config.Domain)] = config
}

// LoadPrivateKey loads a private key from PEM data.
// Supports RSA and Ed25519 keys.
func LoadPrivateKey(pemData []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("key is not a signer")
		}
		return signer, nil
	case "ED25519 PRIVATE KEY":
		if len(block.Bytes) != ed25519.SeedSize {
			return nil, fmt.Errorf("invalid ed25519 key size")
		}
		return ed25519.NewKeyFromSeed(block.Bytes), nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}
}

// generateDemoKey generates a demo RSA key for testing.
// TODO: In production, use pre-generated keys stored securely.
func generateDemoKey() (crypto.Signer, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// initializeSigningKeys sets up signing keys for configured domains.
func initializeSigningKeys() error {
	logger := slog.Default()

	// TODO: Load keys from secure storage. Example:
	//
	// keyPEM, err := os.ReadFile("/etc/dkim/example.com.key")
	// if err != nil {
	//     return err
	// }
	// privateKey, err := LoadPrivateKey(keyPEM)
	// if err != nil {
	//     return err
	// }

	// For demo purposes, generate keys for test domains
	demoDomains := []string{"example.com", "example.org"}

	for _, domain := range demoDomains {
		privateKey, err := generateDemoKey()
		if err != nil {
			return fmt.Errorf("generating key for %s: %w", domain, err)
		}

		keyStore.AddSigningConfig(&DomainSigningConfig{
			Domain:     domain,
			Selector:   "relay1", // TODO: Use actual selector from DNS
			PrivateKey: privateKey,
		})

		logger.Info("initialized signing key",
			slog.String("domain", domain),
			slog.String("selector", "relay1"),
		)
	}

	return nil
}

// =============================================================================
// IP Whitelisting
// =============================================================================

// IPWhitelist manages trusted IP addresses and networks.
type IPWhitelist struct {
	ips      map[string]bool
	networks []*net.IPNet
}

var whitelist = &IPWhitelist{
	ips:      make(map[string]bool),
	networks: make([]*net.IPNet, 0),
}

// Initialize initializes the whitelist from configuration.
func (w *IPWhitelist) Initialize(ips []string, cidrs []string) error {
	for _, ip := range ips {
		w.ips[ip] = true
	}

	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid CIDR %s: %w", cidr, err)
		}
		w.networks = append(w.networks, network)
	}

	return nil
}

// IsAllowed checks if an IP is whitelisted.
func (w *IPWhitelist) IsAllowed(ip net.IP) bool {
	ipStr := ip.String()

	// Check exact IP match
	if w.ips[ipStr] {
		return true
	}

	// Check CIDR networks
	for _, network := range w.networks {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// =============================================================================
// MX Lookup and Delivery
// =============================================================================

// MXResolver handles MX record lookups.
type MXResolver struct {
	resolver ravendns.Resolver
	cache    sync.Map // Simple cache, TODO: Use proper TTL-based caching
}

var mxResolver = &MXResolver{}

// Initialize initializes the MX resolver.
func (m *MXResolver) Initialize() {
	m.resolver = ravendns.NewResolver(ravendns.ResolverConfig{
		Nameservers: []string{"8.8.8.8:53", "1.1.1.1:53"},
		DNSSEC:      true,
		Timeout:     10 * time.Second,
	})
}

// LookupMX looks up MX records for a domain.
func (m *MXResolver) LookupMX(ctx context.Context, domain string) ([]string, error) {
	// Check cache first
	if cached, ok := m.cache.Load(domain); ok {
		return cached.([]string), nil
	}

	// Perform lookup
	mxRecords, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("MX lookup failed for %s: %w", domain, err)
	}

	if len(mxRecords) == 0 {
		// Fall back to A record (RFC 5321)
		return []string{domain}, nil
	}

	// Sort by preference and extract hosts
	hosts := make([]string, 0, len(mxRecords))
	for _, mx := range mxRecords {
		hosts = append(hosts, strings.TrimSuffix(mx.Host, "."))
	}

	// Cache result (simple caching, TODO: respect TTL)
	m.cache.Store(domain, hosts)

	return hosts, nil
}

// =============================================================================
// Delivery Queue
// =============================================================================

// DeliveryTask represents a message to be delivered.
type DeliveryTask struct {
	ID        string
	Mail      *raven.Mail // Mail with DKIM/ARC headers already added
	Recipient string
	Domain    string
	Attempts  int
	LastError error
	CreatedAt time.Time
}

// DeliveryQueue manages message delivery.
// TODO: Replace with persistent queue (Redis, RabbitMQ, database, etc.)
type DeliveryQueue struct {
	mu    sync.Mutex
	tasks chan *DeliveryTask
}

var deliveryQueue = &DeliveryQueue{
	tasks: make(chan *DeliveryTask, 1000),
}

// Enqueue adds a delivery task to the queue.
func (q *DeliveryQueue) Enqueue(task *DeliveryTask) {
	q.tasks <- task
}

// StartWorkers starts delivery worker goroutines.
func (q *DeliveryQueue) StartWorkers(count int, logger *slog.Logger) {
	for i := 0; i < count; i++ {
		go q.worker(i, logger)
	}
}

func (q *DeliveryQueue) worker(id int, logger *slog.Logger) {
	logger.Info("delivery worker started", slog.Int("worker_id", id))

	for task := range q.tasks {
		q.deliverTask(task, logger)
	}
}

func (q *DeliveryQueue) deliverTask(task *DeliveryTask, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	logger.Info("delivering message",
		slog.String("task_id", task.ID),
		slog.String("recipient", task.Recipient),
		slog.String("domain", task.Domain),
		slog.Int("attempt", task.Attempts+1),
	)

	// Look up MX records
	mxHosts, err := mxResolver.LookupMX(ctx, task.Domain)
	if err != nil {
		logger.Error("MX lookup failed",
			slog.String("task_id", task.ID),
			slog.String("domain", task.Domain),
			slog.Any("error", err),
		)
		q.handleDeliveryFailure(task, err, logger)
		return
	}

	// Try each MX host in order
	var lastErr error
	for _, mxHost := range mxHosts {
		err := q.attemptDelivery(ctx, task, mxHost, logger)
		if err == nil {
			logger.Info("message delivered successfully",
				slog.String("task_id", task.ID),
				slog.String("recipient", task.Recipient),
				slog.String("mx_host", mxHost),
			)
			return
		}
		lastErr = err
		logger.Warn("delivery attempt failed",
			slog.String("task_id", task.ID),
			slog.String("mx_host", mxHost),
			slog.Any("error", err),
		)
	}

	q.handleDeliveryFailure(task, lastErr, logger)
}

func (q *DeliveryQueue) attemptDelivery(ctx context.Context, task *DeliveryTask, mxHost string, logger *slog.Logger) error {
	// Create dialer with opportunistic TLS
	dialer := raven.NewDialer(mxHost, 25)
	dialer.LocalName = config.Hostname
	dialer.ConnectTimeout = 30 * time.Second
	dialer.ReadTimeout = 5 * time.Minute
	dialer.WriteTimeout = 5 * time.Minute
	dialer.StartTLS = true // Opportunistic STARTTLS

	// Dial connection
	client, err := dialer.DialContext(ctx)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	defer client.Quit()

	// Create mail for this specific recipient
	// The mail already has DKIM and ARC headers from signing
	deliveryMail := &raven.Mail{
		Envelope: raven.Envelope{
			From: task.Mail.Envelope.From,
			To: []raven.Recipient{{
				Address: raven.Path{
					Mailbox: raven.MailboxAddress{
						LocalPart: strings.Split(task.Recipient, "@")[0],
						Domain:    task.Domain,
					},
				},
			}},
		},
		Content: task.Mail.Content, // Use content with DKIM/ARC headers
	}

	// Send
	result, err := client.Send(deliveryMail)
	if err != nil {
		return fmt.Errorf("send failed: %w", err)
	}

	if !result.Success {
		return fmt.Errorf("delivery rejected: %s", result.Response.Message)
	}

	return nil
}

func (q *DeliveryQueue) handleDeliveryFailure(task *DeliveryTask, err error, logger *slog.Logger) {
	task.Attempts++
	task.LastError = err

	// Retry logic with exponential backoff
	maxAttempts := 5
	if task.Attempts < maxAttempts {
		delay := time.Duration(1<<task.Attempts) * time.Minute
		logger.Info("scheduling retry",
			slog.String("task_id", task.ID),
			slog.Int("attempt", task.Attempts),
			slog.Duration("delay", delay),
		)

		// TODO: Use proper delayed queue
		go func() {
			time.Sleep(delay)
			q.Enqueue(task)
		}()
	} else {
		logger.Error("message delivery failed permanently",
			slog.String("task_id", task.ID),
			slog.String("recipient", task.Recipient),
			slog.Int("attempts", task.Attempts),
			slog.Any("last_error", err),
		)
		// TODO: Generate bounce message
	}
}

// =============================================================================
// DKIM Signing
// =============================================================================

// signMessageDKIM signs a mail message with DKIM for the sender's domain.
// Uses the dkim.SignMail convenience function to sign raven.Mail objects directly.
//
// Alternative: For simple use cases, you can use dkim.QuickSign:
//
//	err := dkim.QuickSign(mail, "example.com", "selector1", privateKey)
func signMessageDKIM(mail *raven.Mail, logger *slog.Logger) error {
	fromDomain := mail.Envelope.From.Mailbox.Domain
	signingConfig := keyStore.GetSigningConfig(fromDomain)

	if signingConfig == nil {
		logger.Debug("no signing key for domain, skipping DKIM",
			slog.String("domain", fromDomain),
		)
		return nil
	}

	// Create DKIM signer with full configuration
	signer := &dkim.Signer{
		Domain:                 signingConfig.Domain,
		Selector:               signingConfig.Selector,
		PrivateKey:             signingConfig.PrivateKey,
		Headers:                dkim.DefaultSignedHeaders,
		HeaderCanonicalization: dkim.CanonRelaxed,
		BodyCanonicalization:   dkim.CanonRelaxed,
		Expiration:             7 * 24 * time.Hour, // Signature valid for 7 days
		OversignHeaders:        true,               // Prevent header injection
	}

	// Sign the mail using the convenience function
	// This adds the DKIM-Signature header directly to mail.Content.Headers
	if err := dkim.SignMail(mail, signer); err != nil {
		return fmt.Errorf("DKIM signing failed: %w", err)
	}

	logger.Info("message signed with DKIM",
		slog.String("domain", signingConfig.Domain),
		slog.String("selector", signingConfig.Selector),
	)

	return nil
}

// =============================================================================
// ARC Sealing
// =============================================================================

// sealMessageARC adds ARC headers to a mail message.
// Uses the arc.SignMail convenience function to seal raven.Mail objects directly.
//
// Alternative: For simple use cases, you can use arc.QuickSeal:
//
//	err := arc.QuickSeal(mail, "example.com", "arc1", privateKey, authServID, authResults, chainValidation)
func sealMessageARC(mail *raven.Mail, authResults string, chainValidation arc.ChainValidationStatus, logger *slog.Logger) error {
	fromDomain := mail.Envelope.From.Mailbox.Domain
	signingConfig := keyStore.GetSigningConfig(fromDomain)

	if signingConfig == nil {
		logger.Debug("no signing key for domain, skipping ARC",
			slog.String("domain", fromDomain),
		)
		return nil
	}

	// Create ARC sealer with full configuration
	sealer := &arc.Sealer{
		Domain:                 signingConfig.Domain,
		Selector:               signingConfig.Selector,
		PrivateKey:             signingConfig.PrivateKey,
		Headers:                arc.DefaultSignedHeaders,
		HeaderCanonicalization: arc.CanonRelaxed,
		BodyCanonicalization:   arc.CanonRelaxed,
	}

	// Seal the mail using the convenience function
	// This adds ARC-Seal, ARC-Message-Signature, and ARC-Authentication-Results
	// headers directly to mail.Content.Headers
	if err := arc.SignMail(mail, sealer, config.Hostname, authResults, chainValidation); err != nil {
		return fmt.Errorf("ARC sealing failed: %w", err)
	}

	logger.Info("message sealed with ARC",
		slog.String("domain", signingConfig.Domain),
	)

	return nil
}

// =============================================================================
// Request Handlers
// =============================================================================

// checkWhitelist verifies the connecting IP is whitelisted.
func checkWhitelist(c *raven.Context) *raven.Response {
	logger := slog.Default()

	// Extract IP from remote address
	remoteAddr := c.Connection.RemoteAddr()
	tcpAddr, ok := remoteAddr.(*net.TCPAddr)
	if !ok {
		logger.Warn("could not determine remote IP type",
			slog.String("remote", remoteAddr.String()),
		)
		return c.PermError("Connection not allowed")
	}

	if !whitelist.IsAllowed(tcpAddr.IP) {
		logger.Warn("connection rejected: IP not whitelisted",
			slog.String("ip", tcpAddr.IP.String()),
		)
		return c.PermError("Relay not permitted from your IP address")
	}

	logger.Debug("connection accepted from whitelisted IP",
		slog.String("ip", tcpAddr.IP.String()),
	)

	return c.Next()
}

// processAndQueue signs the message and queues it for delivery.
func processAndQueue(c *raven.Context) *raven.Response {
	logger := slog.Default()
	mail := c.Mail

	logger.Info("processing message for relay",
		slog.String("from", mail.Envelope.From.Mailbox.String()),
		slog.Int("recipients", len(mail.Envelope.To)),
	)

	// Sign message with DKIM
	// This modifies mail.Content.Headers in place, adding DKIM-Signature
	if err := signMessageDKIM(mail, logger); err != nil {
		logger.Error("DKIM signing failed", slog.Any("error", err))
		return c.TempError("Message signing failed")
	}

	// Build authentication results for ARC
	// In a real implementation, this would include SPF/DKIM verification results
	authResults := fmt.Sprintf("smtp.mailfrom=%s", mail.Envelope.From.Mailbox.String())

	// Seal message with ARC
	// This modifies mail.Content.Headers in place, adding ARC headers
	// For new messages (not forwards), use ChainValidationNone
	if err := sealMessageARC(mail, authResults, arc.ChainValidationNone, logger); err != nil {
		logger.Error("ARC sealing failed", slog.Any("error", err))
		// Continue without ARC - it's not critical
	}

	// Group recipients by domain for efficient delivery
	recipientsByDomain := make(map[string][]string)
	for _, rcpt := range mail.Envelope.To {
		domain := rcpt.Address.Mailbox.Domain
		addr := rcpt.Address.Mailbox.String()
		recipientsByDomain[domain] = append(recipientsByDomain[domain], addr)
	}

	// Queue delivery tasks
	taskID := fmt.Sprintf("%s-%d", c.Connection.Trace.ID, time.Now().UnixNano())
	for domain, recipients := range recipientsByDomain {
		for _, recipient := range recipients {
			task := &DeliveryTask{
				ID:        fmt.Sprintf("%s-%s", taskID, recipient),
				Mail:      mail, // Mail now contains DKIM and ARC headers
				Recipient: recipient,
				Domain:    domain,
				CreatedAt: time.Now(),
			}
			deliveryQueue.Enqueue(task)

			logger.Info("delivery task queued",
				slog.String("task_id", task.ID),
				slog.String("recipient", recipient),
				slog.String("domain", domain),
			)
		}
	}

	return c.OKf("Message accepted for relay [%s]", taskID)
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

	// Initialize whitelist
	if err := whitelist.Initialize(config.WhitelistedIPs, config.WhitelistCIDRs); err != nil {
		logger.Error("failed to initialize whitelist", slog.Any("error", err))
		os.Exit(1)
	}
	logger.Info("IP whitelist initialized",
		slog.Int("ips", len(config.WhitelistedIPs)),
		slog.Int("networks", len(config.WhitelistCIDRs)),
	)

	// Initialize signing keys
	if err := initializeSigningKeys(); err != nil {
		logger.Error("failed to initialize signing keys", slog.Any("error", err))
		os.Exit(1)
	}

	// Initialize MX resolver
	mxResolver.Initialize()

	// Start delivery workers
	deliveryQueue.StartWorkers(5, logger)
	logger.Info("delivery workers started", slog.Int("count", 5))

	// Create and configure the relay server
	server := raven.New(config.Hostname).
		Addr(config.ListenAddr).
		Logger(logger).
		MaxMessageSize(50*1024*1024). // 50MB max message size
		MaxRecipients(500).           // Allow more recipients for relay
		ReadTimeout(5*time.Minute).
		WriteTimeout(5*time.Minute).
		DataTimeout(15*time.Minute).
		IdleTimeout(5*time.Minute).
		Extension(raven.DSN()).
		Extension(raven.Chunking()).
		OnConnect(
			raven.Recovery(logger),
			raven.Logger(logger),
			checkWhitelist, // Only allow whitelisted IPs
		).
		OnMailFrom(
			func(c *raven.Context) *raven.Response {
				// Log sender for relay
				logger.Debug("relay sender",
					slog.String("from", c.Request.From.String()),
					slog.String("remote", c.RemoteAddr()),
				)
				return c.Next()
			},
		).
		OnRcptTo(
			func(c *raven.Context) *raven.Response {
				// Accept all recipients for relay
				// In production, you might want to validate domains or check blacklists
				logger.Debug("relay recipient",
					slog.String("to", c.Request.To.Mailbox.String()),
				)
				return c.Next()
			},
		).
		OnMessage(
			processAndQueue, // Sign and queue for delivery
		)

	// Start the server
	logger.Info("starting SMTP relay server",
		slog.String("hostname", config.Hostname),
		slog.String("addr", config.ListenAddr),
	)

	if err := server.ListenAndServe(); err != raven.ErrServerClosed {
		logger.Error("server error", slog.Any("error", err))
		os.Exit(1)
	}
}
