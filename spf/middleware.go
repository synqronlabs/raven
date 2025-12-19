package spf

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/synqronlabs/raven"
)

// Policy determines how the SPF middleware handles verification results.
type Policy int

const (
	// PolicyMark adds the Received-SPF header but never rejects mail.
	PolicyMark Policy = iota

	// PolicyRejectFail rejects mail on SPF "fail" result.
	PolicyRejectFail

	// PolicyRejectFailAndSoftfail rejects mail on "fail" and "softfail".
	PolicyRejectFailAndSoftfail

	// PolicyRejectAll rejects mail on any result that isn't "pass" or "none".
	PolicyRejectAll
)

// MiddlewareConfig configures the SPF middleware.
type MiddlewareConfig struct {
	// Resolver is the DNS resolver to use. Required.
	Resolver Resolver

	// Policy determines how to handle SPF results. Default is PolicyMark.
	Policy Policy

	// Logger for SPF verification events. Optional.
	Logger *slog.Logger

	// SkipIfAuthenticated skips SPF checks for authenticated senders.
	// Default is true.
	SkipIfAuthenticated bool

	// LocalIP is the receiving server's IP. Used for macro expansion.
	// If nil, attempts to determine from the connection.
	LocalIP net.IP

	// WhitelistIPs is a list of IPs that bypass SPF checks.
	WhitelistIPs []net.IP

	// WhitelistNetworks is a list of CIDR networks that bypass SPF checks.
	WhitelistNetworks []*net.IPNet

	// Timeout for SPF verification. Default is 20 seconds.
	Timeout time.Duration

	// FailOpenOnError returns StatusNone instead of rejecting on DNS errors.
	// Default is false (errors result in temperror and potential rejection).
	FailOpenOnError bool
}

// Context keys for storing SPF results.
const (
	// ContextKeySPFResult is the key for storing the SPF Received struct.
	ContextKeySPFResult = "spf_result"

	// ContextKeySPFStatus is the key for storing the SPF Status.
	ContextKeySPFStatus = "spf_status"

	// ContextKeySPFDomain is the key for storing the checked domain.
	ContextKeySPFDomain = "spf_domain"

	// ContextKeySPFExplanation is the key for storing the fail explanation.
	ContextKeySPFExplanation = "spf_explanation"
)

// Middleware returns a Raven middleware that performs SPF verification.
//
// The middleware runs after MAIL FROM is received and stores results in the
// context for use by later handlers. The Received-SPF header is added to
// incoming messages automatically.
//
// Example usage:
//
//	resolver := spf.NewResolver(spf.ResolverConfig{
//	    DNSSEC: true,
//	})
//
//	server := raven.New("mx.example.com").
//	    Use(spf.Middleware(spf.MiddlewareConfig{
//	        Resolver: resolver,
//	        Policy:   spf.PolicyRejectFail,
//	    }))
func Middleware(config MiddlewareConfig) raven.Middleware {
	if config.Resolver == nil {
		panic("spf: resolver is required")
	}
	if config.Timeout == 0 {
		config.Timeout = 20 * time.Second
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	// Default to skipping authenticated senders
	if !config.SkipIfAuthenticated {
		config.SkipIfAuthenticated = true
	}

	return func(next raven.HandlerFunc) raven.HandlerFunc {
		return func(ctx *raven.Context) error {
			return handleSPF(ctx, next, config)
		}
	}
}

func handleSPF(ctx *raven.Context, next raven.HandlerFunc, config MiddlewareConfig) error {
	// Only process if we have MAIL FROM
	fromVal, ok := ctx.Get("from")
	if !ok {
		return next(ctx)
	}

	from, ok := fromVal.(raven.Path)
	if !ok {
		return next(ctx)
	}

	// Skip for null sender (bounces)
	if from.IsNull() {
		return next(ctx)
	}

	// Skip for authenticated senders
	if config.SkipIfAuthenticated && ctx.IsAuthenticated() {
		return next(ctx)
	}

	// Get remote IP
	remoteIP := getRemoteIP(ctx)
	if remoteIP == nil {
		config.Logger.Warn("could not determine remote IP for SPF check")
		return next(ctx)
	}

	// Check whitelist
	if isWhitelisted(remoteIP, config.WhitelistIPs, config.WhitelistNetworks) {
		config.Logger.Debug("IP whitelisted, skipping SPF check",
			slog.String("ip", remoteIP.String()),
		)
		return next(ctx)
	}

	// Get HELO domain
	heloDomain := ctx.ClientHostname()
	helloIsIP := net.ParseIP(heloDomain) != nil

	// Determine local hostname
	localHostname := ctx.Connection.ServerHostname

	// Determine local IP
	localIP := config.LocalIP
	if localIP == nil {
		localIP = getLocalIP(ctx)
	}

	// Build SPF args
	args := Args{
		RemoteIP:       remoteIP,
		MailFromDomain: from.Mailbox.Domain,
		MailFromLocal:  from.Mailbox.LocalPart,
		HelloDomain:    heloDomain,
		HelloIsIP:      helloIsIP,
		LocalIP:        localIP,
		LocalHostname:  localHostname,
		Logger:         config.Logger,
	}

	// Create context with timeout
	verifyCtx, cancel := context.WithTimeout(ctx.Connection.Context(), config.Timeout)
	defer cancel()

	// Perform SPF verification
	received, domain, explanation, authentic, err := Verify(verifyCtx, config.Resolver, args)

	// Store results in context
	ctx.Set(ContextKeySPFResult, received)
	ctx.Set(ContextKeySPFStatus, received.Result)
	ctx.Set(ContextKeySPFDomain, domain)
	ctx.Set(ContextKeySPFExplanation, explanation)

	// Log result
	config.Logger.Info("SPF verification",
		slog.String("remote_ip", remoteIP.String()),
		slog.String("mail_from", from.String()),
		slog.String("domain", domain),
		slog.String("result", string(received.Result)),
		slog.String("mechanism", received.Mechanism),
		slog.Bool("authentic", authentic),
	)

	// Handle errors
	if err != nil {
		config.Logger.Warn("SPF verification error",
			slog.Any("error", err),
		)

		if config.FailOpenOnError {
			received.Result = StatusNone
			ctx.Set(ContextKeySPFStatus, StatusNone)
		}
	}

	// Apply policy
	reject, msg := shouldReject(received.Result, explanation, config.Policy)
	if reject {
		return fmt.Errorf("%s", msg)
	}

	return next(ctx)
}

// shouldReject determines if the message should be rejected based on policy.
func shouldReject(status Status, explanation string, policy Policy) (bool, string) {
	switch policy {
	case PolicyMark:
		return false, ""

	case PolicyRejectFail:
		if status == StatusFail {
			msg := "SPF check failed"
			if explanation != "" {
				msg = explanation
			}
			return true, msg
		}

	case PolicyRejectFailAndSoftfail:
		if status == StatusFail {
			msg := "SPF check failed"
			if explanation != "" {
				msg = explanation
			}
			return true, msg
		}
		if status == StatusSoftfail {
			return true, "SPF softfail"
		}

	case PolicyRejectAll:
		switch status {
		case StatusPass, StatusNone:
			return false, ""
		case StatusFail:
			msg := "SPF check failed"
			if explanation != "" {
				msg = explanation
			}
			return true, msg
		case StatusSoftfail:
			return true, "SPF softfail"
		case StatusNeutral:
			return true, "SPF neutral"
		case StatusTemperror:
			return true, "SPF temporary error"
		case StatusPermerror:
			return true, "SPF permanent error"
		}
	}

	return false, ""
}

// getRemoteIP extracts the remote IP from the connection.
func getRemoteIP(ctx *raven.Context) net.IP {
	addr := ctx.Connection.RemoteAddr()
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		return tcpAddr.IP
	}

	// Try parsing from string
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	return net.ParseIP(host)
}

// getLocalIP attempts to get the local IP from the connection.
func getLocalIP(ctx *raven.Context) net.IP {
	addr := ctx.Connection.LocalAddr()
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		return tcpAddr.IP
	}

	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	return net.ParseIP(host)
}

// isWhitelisted checks if an IP is in the whitelist.
func isWhitelisted(ip net.IP, ips []net.IP, networks []*net.IPNet) bool {
	if slices.ContainsFunc(ips, ip.Equal) {
		return true
	}

	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// AddReceivedSPFHeader adds the Received-SPF header to a mail message.
// This should be called in the OnMessage callback.
func AddReceivedSPFHeader(ctx *raven.Context, mail *raven.Mail) {
	resultVal, ok := ctx.Get(ContextKeySPFResult)
	if !ok {
		return
	}

	received, ok := resultVal.(Received)
	if !ok {
		return
	}

	header := received.Header()
	mail.Content.Headers = append(raven.Headers{{
		Name:  "Received-SPF",
		Value: strings.TrimPrefix(header, "Received-SPF: "),
	}}, mail.Content.Headers...)
}

// GetSPFResult retrieves the SPF result from the context.
func GetSPFResult(ctx *raven.Context) (Received, bool) {
	val, ok := ctx.Get(ContextKeySPFResult)
	if !ok {
		return Received{}, false
	}
	received, ok := val.(Received)
	return received, ok
}

// GetSPFStatus retrieves the SPF status from the context.
func GetSPFStatus(ctx *raven.Context) Status {
	val, ok := ctx.Get(ContextKeySPFStatus)
	if !ok {
		return StatusNone
	}
	status, ok := val.(Status)
	if !ok {
		return StatusNone
	}
	return status
}

// getRemoteIPFromConn extracts the remote IP from a connection.
func getRemoteIPFromConn(conn *raven.Connection) net.IP {
	addr := conn.RemoteAddr()
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		return tcpAddr.IP
	}

	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	return net.ParseIP(host)
}

// getClientHostnameFromConn gets the HELO/EHLO hostname from a connection.
func getClientHostnameFromConn(conn *raven.Connection) string {
	// Access the Trace.ClientHostname directly since it's a public field
	return conn.Trace.ClientHostname
}
