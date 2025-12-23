package raven

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Logger returns a handler that logs all SMTP command execution.
func Logger(logger *slog.Logger) HandlerFunc {
	return func(c *Context) *Response {
		start := time.Now()
		resp := c.Next()
		duration := time.Since(start)

		attrs := []any{
			slog.String("conn_id", c.Connection.Trace.ID),
			slog.String("remote", c.RemoteAddr()),
			slog.String("command", string(c.Request.Command)),
			slog.Duration("duration", duration),
		}

		if resp != nil {
			attrs = append(attrs,
				slog.Int("code", int(resp.Code)),
				slog.String("message", resp.Message),
			)
			if resp.Code >= 400 {
				logger.Warn("handler completed with error", attrs...)
			} else {
				logger.Debug("handler completed", attrs...)
			}
		} else {
			logger.Debug("handler completed (no response)", attrs...)
		}

		return resp
	}
}

// Recovery returns a handler that recovers from panics.
func Recovery(logger *slog.Logger) HandlerFunc {
	return func(c *Context) (resp *Response) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("panic recovered",
					slog.String("conn_id", c.Connection.Trace.ID),
					slog.Any("panic", r),
				)
				resp = c.TempError("Internal server error")
			}
		}()
		return c.Next()
	}
}

// RateLimiter provides connection rate limiting.
type RateLimiter struct {
	mu       sync.Mutex
	counts   map[string]*rateLimitEntry
	limit    int
	window   time.Duration
	cleanupT time.Duration
}

type rateLimitEntry struct {
	count       int
	windowStart time.Time
}

// NewRateLimiter creates a rate limiter.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		counts:   make(map[string]*rateLimitEntry),
		limit:    limit,
		window:   window,
		cleanupT: window * 2,
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.cleanupT)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, entry := range rl.counts {
			if now.Sub(entry.windowStart) > rl.window {
				delete(rl.counts, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// Allow checks if the IP is allowed and increments the counter.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	entry, ok := rl.counts[ip]

	if !ok || now.Sub(entry.windowStart) > rl.window {
		// New window
		rl.counts[ip] = &rateLimitEntry{count: 1, windowStart: now}
		return true
	}

	if entry.count >= rl.limit {
		return false
	}

	entry.count++
	return true
}

// RateLimit returns a handler that limits connections per IP.
func RateLimit(limiter *RateLimiter) HandlerFunc {
	return func(c *Context) *Response {
		ip := extractIP(c.Connection.RemoteAddr())
		if !limiter.Allow(ip) {
			return c.TempError("Too many connections, please try again later")
		}
		return c.Next()
	}
}

// IPFilter provides IP-based access control.
type IPFilter struct {
	mu        sync.RWMutex
	allowList map[string]bool
	denyList  map[string]bool
	mode      IPFilterMode
}

// IPFilterMode determines how the filter operates.
type IPFilterMode int

const (
	// IPFilterModeAllow only allows IPs in the allow list.
	IPFilterModeAllow IPFilterMode = iota
	// IPFilterModeDeny only denies IPs in the deny list.
	IPFilterModeDeny
)

// NewIPFilter creates a new IP filter.
func NewIPFilter(mode IPFilterMode) *IPFilter {
	return &IPFilter{
		allowList: make(map[string]bool),
		denyList:  make(map[string]bool),
		mode:      mode,
	}
}

// Allow adds an IP to the allow list.
func (f *IPFilter) Allow(ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.allowList[ip] = true
}

// Deny adds an IP to the deny list.
func (f *IPFilter) Deny(ip string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.denyList[ip] = true
}

// IsAllowed checks if an IP is allowed.
func (f *IPFilter) IsAllowed(ip string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	switch f.mode {
	case IPFilterModeAllow:
		return f.allowList[ip]
	case IPFilterModeDeny:
		return !f.denyList[ip]
	}
	return true
}

// IPFilterHandler returns a handler that filters connections by IP.
func IPFilterHandler(filter *IPFilter) HandlerFunc {
	return func(c *Context) *Response {
		ip := extractIP(c.Connection.RemoteAddr())
		if !filter.IsAllowed(ip) {
			return c.PermError("Connection not allowed from your IP address")
		}
		return c.Next()
	}
}

// DomainValidator validates sender and recipient domains.
type DomainValidator struct {
	allowedDomains map[string]bool
	localDomains   map[string]bool
}

// NewDomainValidator creates a domain validator.
func NewDomainValidator() *DomainValidator {
	return &DomainValidator{
		allowedDomains: make(map[string]bool),
		localDomains:   make(map[string]bool),
	}
}

// AddLocalDomain adds a domain that this server handles mail for.
func (v *DomainValidator) AddLocalDomain(domain string) {
	v.localDomains[domain] = true
}

// AddAllowedDomain adds a domain that can send mail through this server.
func (v *DomainValidator) AddAllowedDomain(domain string) {
	v.allowedDomains[domain] = true
}

// IsLocalDomain checks if the domain is local.
func (v *DomainValidator) IsLocalDomain(domain string) bool {
	return v.localDomains[domain]
}

// IsAllowedSender checks if the sender domain is allowed.
func (v *DomainValidator) IsAllowedSender(domain string) bool {
	if len(v.allowedDomains) == 0 {
		return true // No restrictions
	}
	return v.allowedDomains[domain]
}

// ValidateSender returns a handler that validates sender domains.
func ValidateSender(validator *DomainValidator) HandlerFunc {
	return func(c *Context) *Response {
		from := c.Request.From
		if from == nil {
			return c.Next()
		}

		if from.IsNull() {
			// Null sender (bounce) is always allowed
			return c.Next()
		}

		if !validator.IsAllowedSender(from.Mailbox.Domain) {
			return c.PermError(fmt.Sprintf("Sender domain %s is not allowed", from.Mailbox.Domain))
		}

		return c.Next()
	}
}

// ValidateRecipient returns a handler that validates recipient domains.
func ValidateRecipient(validator *DomainValidator) HandlerFunc {
	return func(c *Context) *Response {
		to := c.Request.To
		if to == nil {
			return c.Next()
		}

		if !validator.IsLocalDomain(to.Mailbox.Domain) {
			// Check if client is authenticated for relay
			if !c.IsAuthenticated() {
				return c.PermError(fmt.Sprintf("Relay not permitted for %s", to.Mailbox.Domain))
			}
		}

		return c.Next()
	}
}

func extractIP(addr net.Addr) string {
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		return tcpAddr.IP.String()
	}
	// Fallback: parse the string representation
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// SecureDefaults returns a set of handlers suitable for production use.
// This includes recovery, logging, and rate limiting.
func SecureDefaults(logger *slog.Logger) []HandlerFunc {
	return []HandlerFunc{
		Recovery(logger),
		Logger(logger),
		RateLimit(NewRateLimiter(100, time.Minute)), // 100 connections/minute per IP
	}
}

// DevelopmentDefaults returns handlers suitable for development.
// This includes recovery and verbose logging.
func DevelopmentDefaults(logger *slog.Logger) []HandlerFunc {
	return []HandlerFunc{
		Recovery(logger),
		Logger(logger),
	}
}
