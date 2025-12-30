package dkim

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/synqronlabs/raven"
	ravendns "github.com/synqronlabs/raven/dns"
)

// MiddlewareConfig configures the DKIM verification middleware.
type MiddlewareConfig struct {
	// Resolver is the DNS resolver to use. Required.
	Resolver ravendns.Resolver

	// Logger for DKIM events. Optional.
	Logger *slog.Logger

	// Policy is a function that can reject signatures based on policy.
	// Return an error to reject the signature.
	Policy func(*Signature) error

	// IgnoreTestMode ignores the t=y flag in DKIM records.
	IgnoreTestMode bool

	// MinRSAKeyBits is the minimum RSA key size to accept.
	// Default is 1024.
	MinRSAKeyBits int

	// Timeout for DKIM verification. Default is 30 seconds.
	Timeout time.Duration

	// SkipIfAuthenticated skips DKIM checks for authenticated senders.
	// Default is true.
	SkipIfAuthenticated bool

	// WhitelistIPs is a list of IPs that bypass DKIM checks.
	WhitelistIPs []net.IP

	// WhitelistNetworks is a list of CIDR networks that bypass DKIM checks.
	WhitelistNetworks []*net.IPNet

	// RejectOnFail rejects messages with DKIM verification failures.
	// Default is false (messages are accepted with Authentication-Results header).
	RejectOnFail bool

	// RequireSignature rejects messages without a DKIM signature.
	// Default is false.
	RequireSignature bool
}

// Context keys for storing DKIM results.
const (
	// ContextKeyDKIMResults is the key for storing []Result.
	ContextKeyDKIMResults = "dkim_results"

	// ContextKeyDKIMStatus is the key for storing the overall Status.
	ContextKeyDKIMStatus = "dkim_status"

	// ContextKeyDKIMDomain is the key for storing the signing domain.
	ContextKeyDKIMDomain = "dkim_domain"
)

// Middleware returns a Raven handler that performs DKIM verification.
//
// The handler runs after the DATA command and verifies all DKIM signatures
// in the message. Results are stored in the context and an Authentication-Results
// header is added to the message.
//
// Example usage:
//
//	resolver := dns.NewResolver(dns.ResolverConfig{
//	    DNSSEC: true,
//	})
//
//	server := raven.New("mx.example.com")
//	server.OnData(dkim.Middleware(dkim.MiddlewareConfig{
//	    Resolver: resolver,
//	}))
func Middleware(config MiddlewareConfig) raven.HandlerFunc {
	if config.Resolver == nil {
		panic("dkim: resolver is required")
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.MinRSAKeyBits == 0 {
		config.MinRSAKeyBits = 1024
	}

	return func(c *raven.Context) *raven.Response {
		return handleDKIM(c, config)
	}
}

func handleDKIM(c *raven.Context, config MiddlewareConfig) *raven.Response {
	// Only process if we have mail data
	if c.Mail == nil || len(c.Mail.Content.Body) == 0 {
		return c.Next()
	}

	// Skip for authenticated senders
	if config.SkipIfAuthenticated && c.Connection.IsAuthenticated() {
		return c.Next()
	}

	// Check whitelist
	remoteIP := getRemoteIP(c)
	if remoteIP != nil && isWhitelisted(remoteIP, config.WhitelistIPs, config.WhitelistNetworks) {
		config.Logger.Debug("IP whitelisted, skipping DKIM check",
			slog.String("ip", remoteIP.String()),
		)
		return c.Next()
	}

	// Build raw message from Content
	rawMessage := c.Mail.Content.ToRaw()

	// Create verifier
	verifier := &Verifier{
		Resolver:       config.Resolver,
		IgnoreTestMode: config.IgnoreTestMode,
		Policy:         config.Policy,
		MinRSAKeyBits:  config.MinRSAKeyBits,
	}

	// Create context with timeout
	verifyCtx, cancel := context.WithTimeout(c.Connection.Context(), config.Timeout)
	defer cancel()

	// Verify signatures
	results, err := verifier.Verify(verifyCtx, rawMessage)
	if err != nil {
		config.Logger.Error("DKIM verification error",
			slog.Any("error", err),
		)
		// Continue processing, don't reject on verification errors
	}

	// Store results in context
	c.Set(ContextKeyDKIMResults, results)

	// Determine overall status
	overallStatus := StatusNone
	var signingDomain string

	for _, r := range results {
		if r.Status == StatusPass {
			overallStatus = StatusPass
			if r.Signature != nil {
				signingDomain = r.Signature.Domain
			}
			break
		}
		if r.Status == StatusFail && overallStatus != StatusPass {
			overallStatus = StatusFail
		}
	}

	c.Set(ContextKeyDKIMStatus, overallStatus)
	c.Set(ContextKeyDKIMDomain, signingDomain)

	// Log results
	for _, r := range results {
		domain := ""
		selector := ""
		if r.Signature != nil {
			domain = r.Signature.Domain
			selector = r.Signature.Selector
		}

		config.Logger.Info("DKIM verification",
			slog.String("status", string(r.Status)),
			slog.String("domain", domain),
			slog.String("selector", selector),
			slog.Any("error", r.Err),
		)
	}

	// Add Authentication-Results header
	authResults := generateAuthResults(c.Connection.ServerHostname, results)
	c.Mail.Content.Headers = append(raven.Headers{{
		Name:  "Authentication-Results",
		Value: authResults,
	}}, c.Mail.Content.Headers...)

	// Check if we should reject
	if config.RequireSignature && len(results) == 0 {
		return &raven.Response{
			Code:         550,
			EnhancedCode: "5.7.1",
			Message:      "DKIM signature required",
		}
	}

	if config.RejectOnFail && overallStatus == StatusFail {
		return &raven.Response{
			Code:         550,
			EnhancedCode: "5.7.1",
			Message:      "DKIM verification failed",
		}
	}

	return c.Next()
}

// generateAuthResults generates an Authentication-Results header value.
func generateAuthResults(hostname string, results []Result) string {
	var b strings.Builder

	b.WriteString(hostname)

	if len(results) == 0 {
		b.WriteString("; dkim=none")
		return b.String()
	}

	for _, r := range results {
		b.WriteString("; dkim=")
		b.WriteString(string(r.Status))

		if r.Signature != nil {
			b.WriteString(" header.d=")
			b.WriteString(r.Signature.Domain)

			b.WriteString(" header.s=")
			b.WriteString(r.Signature.Selector)

			if r.Signature.Identity != "" {
				b.WriteString(" header.i=")
				b.WriteString(r.Signature.Identity)
			}
		}

		if r.Err != nil {
			b.WriteString(" (")
			// Sanitize error message for header
			errMsg := r.Err.Error()
			errMsg = strings.ReplaceAll(errMsg, "\r", "")
			errMsg = strings.ReplaceAll(errMsg, "\n", " ")
			if len(errMsg) > 100 {
				errMsg = errMsg[:100]
			}
			b.WriteString(errMsg)
			b.WriteString(")")
		}
	}

	return b.String()
}

// getRemoteIP extracts the remote IP from the context.
func getRemoteIP(c *raven.Context) net.IP {
	addr := c.Connection.RemoteAddr()
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		return tcpAddr.IP
	}
	// Try parsing string representation
	host, _, _ := net.SplitHostPort(addr.String())
	return net.ParseIP(host)
}

// isWhitelisted checks if an IP is in the whitelist.
func isWhitelisted(ip net.IP, ips []net.IP, networks []*net.IPNet) bool {
	for _, whiteIP := range ips {
		if ip.Equal(whiteIP) {
			return true
		}
	}
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
