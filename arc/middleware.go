package arc

import (
	"context"
	"crypto"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/synqronlabs/raven"
	"github.com/synqronlabs/raven/dkim"
	"github.com/synqronlabs/raven/dmarc"
	ravendns "github.com/synqronlabs/raven/dns"
	"github.com/synqronlabs/raven/spf"
)

// MiddlewareConfig configures the ARC middleware.
type MiddlewareConfig struct {
	// Resolver is the DNS resolver to use. Required.
	Resolver ravendns.Resolver

	// Logger for ARC events. Optional.
	Logger *slog.Logger

	// Timeout for ARC verification. Default is 30 seconds.
	Timeout time.Duration

	// SkipIfAuthenticated skips ARC checks for authenticated senders.
	// Default is true.
	SkipIfAuthenticated bool

	// WhitelistIPs is a list of IPs that bypass ARC checks.
	WhitelistIPs []net.IP

	// WhitelistNetworks is a list of CIDR networks that bypass ARC checks.
	WhitelistNetworks []*net.IPNet

	// MinRSAKeyBits is the minimum RSA key size to accept.
	// Default is 1024.
	MinRSAKeyBits int

	// TrustedSealers is a list of domains whose ARC seals are trusted.
	// This is used for DMARC override decisions.
	TrustedSealers []string

	// SealingConfig provides configuration for adding ARC headers.
	// If nil, the middleware only verifies but does not seal.
	SealingConfig *SealingConfig
}

// SealingConfig configures ARC sealing (adding ARC headers).
type SealingConfig struct {
	// Domain is the signing domain.
	Domain string

	// Selector is the DKIM selector for the signing key.
	Selector string

	// PrivateKey is the signing key.
	PrivateKey crypto.Signer

	// Headers is the list of headers to sign.
	// If empty, DefaultSignedHeaders is used.
	Headers []string

	// HeaderCanonicalization for signing. Default is relaxed.
	HeaderCanonicalization Canonicalization

	// BodyCanonicalization for signing. Default is relaxed.
	BodyCanonicalization Canonicalization
}

// Context keys for storing ARC results.
const (
	// ContextKeyARCResult is the key for storing the *Result.
	ContextKeyARCResult = "arc_result"

	// ContextKeyARCStatus is the key for storing the Status.
	ContextKeyARCStatus = "arc_status"

	// ContextKeyARCChainValidation is the key for storing the ChainValidationStatus
	// to use when sealing.
	ContextKeyARCChainValidation = "arc_chain_validation"

	// ContextKeyARCTrusted is the key for storing whether the chain was sealed
	// by a trusted domain.
	ContextKeyARCTrusted = "arc_trusted"
)

// Middleware returns a Raven handler that performs ARC verification and optionally sealing.
//
// The handler should be used AFTER SPF, DKIM, and DMARC handlers, as ARC sealing
// requires their results. It runs after the DATA command and:
//  1. Verifies any existing ARC chain
//  2. Stores the result in the context
//  3. Adds Authentication-Results header for ARC
//  4. Optionally seals the message with a new ARC set
//
// Example usage:
//
//	resolver := dns.NewResolver(dns.ResolverConfig{
//	    DNSSEC: true,
//	})
//
//	server := raven.New("mx.example.com")
//	server.OnMailFrom(spf.Middleware(...))
//	server.OnData(dkim.Middleware(...))
//	server.OnData(dmarc.Middleware(...))
//	server.OnData(arc.Middleware(arc.MiddlewareConfig{
//	    Resolver: resolver,
//	    SealingConfig: &arc.SealingConfig{
//	        Domain:     "example.com",
//	        Selector:   "arc1",
//	        PrivateKey: privateKey,
//	    },
//	}))
func Middleware(config MiddlewareConfig) raven.HandlerFunc {
	if config.Resolver == nil {
		panic("arc: resolver is required")
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
		return handleARC(c, config)
	}
}

func handleARC(c *raven.Context, config MiddlewareConfig) *raven.Response {
	// Only process if we have message content
	if c.Mail == nil || len(c.Mail.Content.Body) == 0 {
		return c.Next()
	}

	// Check if authenticated sender should skip
	if config.SkipIfAuthenticated && c.Connection.IsAuthenticated() {
		config.Logger.Debug("skipping ARC for authenticated sender",
			slog.String("conn_id", c.Connection.Trace.ID),
		)
		return c.Next()
	}

	// Check whitelist
	remoteIP := getRemoteIP(c)
	if remoteIP != nil && isWhitelisted(remoteIP, config.WhitelistIPs, config.WhitelistNetworks) {
		config.Logger.Debug("skipping ARC for whitelisted IP",
			slog.String("conn_id", c.Connection.Trace.ID),
			slog.String("ip", remoteIP.String()),
		)
		return c.Next()
	}

	// Create verification context with timeout
	verifyCtx, cancel := context.WithTimeout(c.Connection.Context(), config.Timeout)
	defer cancel()

	// Verify existing ARC chain
	verifier := &Verifier{
		Resolver:      config.Resolver,
		MinRSAKeyBits: config.MinRSAKeyBits,
	}

	rawMessage := c.Mail.Content.ToRaw()
	result, err := verifier.Verify(verifyCtx, rawMessage)

	// Handle verification error
	if err != nil {
		config.Logger.Error("ARC verification error",
			slog.String("conn_id", c.Connection.Trace.ID),
			slog.Any("error", err),
		)
		// Continue processing - store the result with error
	}

	// Store result in context
	c.Set(ContextKeyARCResult, result)
	c.Set(ContextKeyARCStatus, result.Status)

	// Determine chain validation status for potential sealing
	chainValidation := GetARCChainStatus(result)
	c.Set(ContextKeyARCChainValidation, chainValidation)

	// Check if chain is from trusted sealer
	if len(config.TrustedSealers) > 0 {
		trusted, _ := EvaluateARCForDMARC(result, config.TrustedSealers)
		c.Set(ContextKeyARCTrusted, trusted)
	}

	// Log verification result
	config.Logger.Info("ARC verification complete",
		slog.String("conn_id", c.Connection.Trace.ID),
		slog.String("status", string(result.Status)),
		slog.Int("sets", len(result.Sets)),
		slog.Int("failed_instance", result.FailedInstance),
	)

	// Add Authentication-Results header for ARC
	authResults := buildARCAuthResults(c.Connection.ServerHostname, result)
	c.Mail.AddHeader("Authentication-Results", authResults)

	// Seal the message if configured
	if config.SealingConfig != nil {
		if err := sealMessage(c, config); err != nil {
			config.Logger.Error("ARC sealing error",
				slog.String("conn_id", c.Connection.Trace.ID),
				slog.Any("error", err),
			)
			// Continue without sealing - don't fail the message
		} else {
			config.Logger.Info("ARC sealing complete",
				slog.String("conn_id", c.Connection.Trace.ID),
				slog.String("domain", config.SealingConfig.Domain),
			)
		}
	}

	return c.Next()
}

// sealMessage adds ARC headers to the message.
func sealMessage(c *raven.Context, config MiddlewareConfig) error {
	sc := config.SealingConfig

	sealer := &Sealer{
		Domain:                 sc.Domain,
		Selector:               sc.Selector,
		PrivateKey:             sc.PrivateKey,
		Headers:                sc.Headers,
		HeaderCanonicalization: sc.HeaderCanonicalization,
		BodyCanonicalization:   sc.BodyCanonicalization,
	}

	// Get chain validation status from context
	chainValidation := ChainValidationNone
	if cv, ok := c.Get(ContextKeyARCChainValidation); ok {
		if cvs, ok := cv.(ChainValidationStatus); ok {
			chainValidation = cvs
		}
	}

	// Build authentication results string from previous middleware results
	authResults := buildSealingAuthResults(c)

	return SignMail(c.Mail, sealer, sc.Domain, authResults, chainValidation)
}

// buildARCAuthResults builds the Authentication-Results value for ARC verification.
func buildARCAuthResults(hostname string, result *Result) string {
	var b strings.Builder
	b.WriteString(hostname)
	b.WriteString("; arc=")
	b.WriteString(string(result.Status))

	if result.Status == StatusPass && len(result.Sets) > 0 {
		// Add info about the newest set
		newest := result.Sets[len(result.Sets)-1]
		if newest.Seal != nil {
			b.WriteString(" (i=")
			b.WriteString(fmt.Sprintf("%d", newest.Instance))
			b.WriteString(" d=")
			b.WriteString(newest.Seal.Domain)
			b.WriteString(")")
		}
	} else if result.Status == StatusFail {
		b.WriteString(" (")
		if result.FailedInstance > 0 {
			b.WriteString(fmt.Sprintf("i=%d ", result.FailedInstance))
		}
		if result.FailedReason != "" {
			b.WriteString(result.FailedReason)
		}
		b.WriteString(")")
	}

	return b.String()
}

// buildSealingAuthResults builds the auth results string for ARC sealing.
// This combines results from SPF, DKIM, and DMARC middleware.
func buildSealingAuthResults(c *raven.Context) string {
	var parts []string

	// Get SPF result
	if spfResult, ok := c.Get(spf.ContextKeySPFResult); ok {
		if r, ok := spfResult.(spf.Received); ok {
			parts = append(parts, fmt.Sprintf("spf=%s smtp.mailfrom=%s", r.Result, r.EnvelopeFrom))
		}
	}

	// Get DKIM results
	if dkimResults, ok := c.Get(dkim.ContextKeyDKIMResults); ok {
		if results, ok := dkimResults.([]dkim.Result); ok {
			for _, r := range results {
				part := fmt.Sprintf("dkim=%s", r.Status)
				if r.Signature != nil {
					part += fmt.Sprintf(" header.d=%s header.s=%s", r.Signature.Domain, r.Signature.Selector)
				}
				parts = append(parts, part)
			}
		}
	}

	// Get DMARC result
	if dmarcResult, ok := c.Get(dmarc.ContextKeyDMARCResult); ok {
		if r, ok := dmarcResult.(dmarc.Result); ok {
			parts = append(parts, fmt.Sprintf("dmarc=%s header.from=%s", r.Status, r.Domain))
		}
	}

	// Get existing ARC result
	if arcResult, ok := c.Get(ContextKeyARCResult); ok {
		if r, ok := arcResult.(*Result); ok {
			parts = append(parts, fmt.Sprintf("arc=%s", r.Status))
		}
	}

	return strings.Join(parts, ";\r\n\t")
}

// isWhitelisted checks if an IP is in the whitelist.
func isWhitelisted(ip net.IP, ips []net.IP, networks []*net.IPNet) bool {
	if ip == nil {
		return false
	}

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

// getRemoteIP extracts the IP address from the context.
func getRemoteIP(c *raven.Context) net.IP {
	addrStr := c.Connection.RemoteAddr().String()
	if addrStr == "" {
		return nil
	}

	// Try parsing as host:port
	host, _, err := net.SplitHostPort(addrStr)
	if err != nil {
		// Maybe it's just an IP without port
		host = addrStr
	}
	return net.ParseIP(host)
}

// VerificationMiddleware returns a handler that only verifies ARC chains without sealing.
// This is a convenience function for receivers that don't need to forward messages.
func VerificationMiddleware(config MiddlewareConfig) raven.HandlerFunc {
	config.SealingConfig = nil
	return Middleware(config)
}

// GetARCResultFromContext retrieves the ARC result from a raven context.
func GetARCResultFromContext(c *raven.Context) (*Result, bool) {
	if result, ok := c.Get(ContextKeyARCResult); ok {
		if r, ok := result.(*Result); ok {
			return r, true
		}
	}
	return nil, false
}

// GetARCStatusFromContext retrieves the ARC status from a raven context.
func GetARCStatusFromContext(c *raven.Context) (Status, bool) {
	if status, ok := c.Get(ContextKeyARCStatus); ok {
		if s, ok := status.(Status); ok {
			return s, true
		}
	}
	return "", false
}

// IsTrustedChain checks if the ARC chain was sealed by a trusted domain.
func IsTrustedChain(c *raven.Context) bool {
	if trusted, ok := c.Get(ContextKeyARCTrusted); ok {
		if t, ok := trusted.(bool); ok {
			return t
		}
	}
	return false
}
