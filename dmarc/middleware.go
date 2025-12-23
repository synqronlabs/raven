package dmarc

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/synqronlabs/raven"
	"github.com/synqronlabs/raven/dkim"
	ravendns "github.com/synqronlabs/raven/dns"
	"github.com/synqronlabs/raven/spf"
)

// MiddlewarePolicy determines how the DMARC middleware handles verification results.
type MiddlewarePolicy int

const (
	// MiddlewarePolicyMark adds the Authentication-Results header but never rejects.
	MiddlewarePolicyMark MiddlewarePolicy = iota

	// MiddlewarePolicyEnforce rejects messages based on the published DMARC policy.
	// Messages that fail DMARC with p=reject will be rejected.
	// Messages that fail DMARC with p=quarantine will be marked.
	MiddlewarePolicyEnforce

	// MiddlewarePolicyStrict rejects all messages that fail DMARC,
	// regardless of the published policy.
	MiddlewarePolicyStrict
)

// MiddlewareConfig configures the DMARC middleware.
type MiddlewareConfig struct {
	// Resolver is the DNS resolver to use. Required.
	Resolver ravendns.Resolver

	// Policy determines how to handle DMARC results.
	// Default is MiddlewarePolicyMark.
	Policy MiddlewarePolicy

	// Logger for DMARC events. Optional.
	Logger *slog.Logger

	// SkipIfAuthenticated skips DMARC checks for authenticated senders.
	// Default is true.
	SkipIfAuthenticated bool

	// WhitelistIPs is a list of IPs that bypass DMARC checks.
	WhitelistIPs []net.IP

	// WhitelistNetworks is a list of CIDR networks that bypass DMARC checks.
	WhitelistNetworks []*net.IPNet

	// Timeout for DMARC verification. Default is 30 seconds.
	Timeout time.Duration

	// ApplyRandomPercentage honors the pct= field in DMARC records.
	// When true (default), only the specified percentage of messages
	// will have the policy enforced.
	ApplyRandomPercentage bool

	// RejectOnPermerror rejects messages when DMARC verification encounters
	// a permanent error (e.g., malformed DMARC record).
	// Default is false.
	RejectOnPermerror bool
}

// Context keys for storing DMARC results.
const (
	// ContextKeyDMARCResult is the key for storing the Result.
	ContextKeyDMARCResult = "dmarc_result"

	// ContextKeyDMARCStatus is the key for storing the Status.
	ContextKeyDMARCStatus = "dmarc_status"

	// ContextKeyDMARCDomain is the key for storing the DMARC policy domain.
	ContextKeyDMARCDomain = "dmarc_domain"

	// ContextKeyDMARCUseResult is the key for storing whether the result
	// should be used (based on pct= sampling).
	ContextKeyDMARCUseResult = "dmarc_use_result"
)

// Middleware returns a Raven handler that performs DMARC verification.
//
// The handler should be used AFTER SPF and DKIM handlers, as it depends
// on their results. It runs after the DATA command and:
//  1. Extracts the From header domain
//  2. Retrieves SPF and DKIM results from context
//  3. Looks up and evaluates the DMARC policy
//  4. Adds Authentication-Results header
//  5. Optionally rejects based on policy
//
// Example usage:
//
//	resolver := dns.NewResolver(dns.ResolverConfig{
//	    DNSSEC: true,
//	})
//
//	server := raven.New("mx.example.com")
//	server.OnMailFrom(spf.Middleware(spf.MiddlewareConfig{...}))
//	server.OnData(dkim.Middleware(dkim.MiddlewareConfig{...}))
//	server.OnData(dmarc.Middleware(dmarc.MiddlewareConfig{
//	    Resolver: resolver,
//	    Policy:   dmarc.MiddlewarePolicyEnforce,
//	}))
func Middleware(config MiddlewareConfig) raven.HandlerFunc {
	if config.Resolver == nil {
		panic("dmarc: resolver is required")
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	// Default to applying random percentage (respecting pct= field)
	if config.Policy == MiddlewarePolicyEnforce {
		config.ApplyRandomPercentage = true
	}

	return func(c *raven.Context) *raven.Response {
		return handleDMARC(c, config)
	}
}

func handleDMARC(c *raven.Context, config MiddlewareConfig) *raven.Response {
	// Only process if we have mail data
	if c.Mail == nil || len(c.Mail.Content.Body) == 0 {
		return c.Next()
	}

	// Skip for authenticated senders
	if config.SkipIfAuthenticated && c.IsAuthenticated() {
		return c.Next()
	}

	// Check whitelist
	remoteIP := getRemoteIP(c)
	if remoteIP != nil && isWhitelisted(remoteIP, config.WhitelistIPs, config.WhitelistNetworks) {
		config.Logger.Debug("IP whitelisted, skipping DMARC check",
			slog.String("ip", remoteIP.String()),
		)
		return c.Next()
	}

	// Get From header
	fromHeader := c.Mail.Content.Headers.Get("From")
	if fromHeader == "" {
		config.Logger.Warn("no From header found, skipping DMARC check")
		return c.Next()
	}

	// Extract From domain
	fromDomain, err := ExtractFromDomain(fromHeader)
	if err != nil {
		config.Logger.Warn("failed to extract From domain",
			slog.String("from_header", fromHeader),
			slog.Any("error", err),
		)
		// Continue without DMARC check
		return c.Next()
	}

	// Get SPF results from context
	spfStatus := spf.StatusNone
	var spfDomain string

	if statusVal, ok := c.Get(spf.ContextKeySPFStatus); ok {
		if s, ok := statusVal.(spf.Status); ok {
			spfStatus = s
		}
	}
	if domainVal, ok := c.Get(spf.ContextKeySPFDomain); ok {
		if d, ok := domainVal.(string); ok {
			spfDomain = d
		}
	}

	// Get DKIM results from context
	var dkimResults []dkim.Result
	if resultsVal, ok := c.Get(dkim.ContextKeyDKIMResults); ok {
		if r, ok := resultsVal.([]dkim.Result); ok {
			dkimResults = r
		}
	}

	// Create verification context with timeout
	verifyCtx, cancel := context.WithTimeout(c.Connection.Context(), config.Timeout)
	defer cancel()

	// Build verification arguments
	args := VerifyArgs{
		FromDomain:  fromDomain,
		SPFResult:   spfStatus,
		SPFDomain:   spfDomain,
		DKIMResults: dkimResults,
	}

	// Perform DMARC verification
	useResult, result := Verify(verifyCtx, config.Resolver, args, config.ApplyRandomPercentage)

	// Store results in context
	c.Set(ContextKeyDMARCResult, result)
	c.Set(ContextKeyDMARCStatus, result.Status)
	c.Set(ContextKeyDMARCDomain, result.Domain)
	c.Set(ContextKeyDMARCUseResult, useResult)

	// Log result
	config.Logger.Info("DMARC verification",
		slog.String("from_domain", fromDomain),
		slog.String("dmarc_domain", result.Domain),
		slog.String("status", string(result.Status)),
		slog.Bool("aligned_spf", result.AlignedSPFPass),
		slog.Bool("aligned_dkim", result.AlignedDKIMPass),
		slog.Bool("reject", result.Reject),
		slog.Bool("use_result", useResult),
		slog.Any("error", result.Err),
	)

	// Add Authentication-Results header
	authResults := generateAuthResults(c.Connection.ServerHostname, result, fromDomain)
	c.Mail.Content.Headers = append(raven.Headers{{
		Name:  "Authentication-Results",
		Value: authResults,
	}}, c.Mail.Content.Headers...)

	// Determine if we should reject
	shouldReject := false

	switch config.Policy {
	case MiddlewarePolicyEnforce:
		// Respect the published policy
		shouldReject = useResult && result.Reject

	case MiddlewarePolicyStrict:
		// Reject any failure
		shouldReject = result.Status == StatusFail
	}

	// Handle permerror if configured
	if config.RejectOnPermerror && result.Status == StatusPermerror {
		shouldReject = true
	}

	if shouldReject {
		policy := ""
		if result.Record != nil {
			policy = string(result.Record.Policy)
		}
		return &raven.Response{
			Code:         550,
			EnhancedCode: "5.7.1",
			Message:      fmt.Sprintf("DMARC policy violation: %s (p=%s)", result.Status, policy),
		}
	}

	return c.Next()
}

// generateAuthResults generates an Authentication-Results header value for DMARC.
func generateAuthResults(hostname string, result Result, fromDomain string) string {
	var b strings.Builder

	b.WriteString(hostname)
	b.WriteString("; dmarc=")
	b.WriteString(string(result.Status))

	// Add the From domain
	b.WriteString(" header.from=")
	b.WriteString(fromDomain)

	// Add policy domain if different
	if result.Domain != "" && result.Domain != fromDomain {
		b.WriteString(" policy.domain=")
		b.WriteString(result.Domain)
	}

	// Add policy if we have a record
	if result.Record != nil {
		b.WriteString(" policy.published=")
		b.WriteString(string(result.Record.Policy))

		if result.Record.SubdomainPolicy != PolicyEmpty {
			b.WriteString(" policy.subdomain=")
			b.WriteString(string(result.Record.SubdomainPolicy))
		}
	}

	// Add alignment results
	if result.AlignedSPFPass {
		b.WriteString(" spf=pass")
	}
	if result.AlignedDKIMPass {
		b.WriteString(" dkim=pass")
	}

	// Add error if present
	if result.Err != nil {
		b.WriteString(" reason=\"")
		errMsg := result.Err.Error()
		errMsg = strings.ReplaceAll(errMsg, "\"", "'")
		errMsg = strings.ReplaceAll(errMsg, "\r", "")
		errMsg = strings.ReplaceAll(errMsg, "\n", " ")
		if len(errMsg) > 100 {
			errMsg = errMsg[:100]
		}
		b.WriteString(errMsg)
		b.WriteString("\"")
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
