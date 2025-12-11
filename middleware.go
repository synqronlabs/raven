package raven

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// ---- Built-in Middleware ----

// Logger returns middleware that logs all SMTP events.
func Logger(logger *slog.Logger) Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return func(ctx *Context) error {
			start := time.Now()
			err := next(ctx)
			duration := time.Since(start)

			attrs := []any{
				slog.String("conn_id", ctx.Connection.Trace.ID),
				slog.String("remote", ctx.RemoteAddr()),
				slog.Duration("duration", duration),
			}

			if err != nil {
				logger.Error("handler error", append(attrs, slog.Any("error", err))...)
			} else {
				logger.Debug("handler completed", attrs...)
			}

			return err
		}
	}
}

// Recovery returns middleware that recovers from panics.
func Recovery(logger *slog.Logger) Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return func(ctx *Context) (err error) {
			defer func() {
				if r := recover(); r != nil {
					logger.Error("panic recovered",
						slog.String("conn_id", ctx.Connection.Trace.ID),
						slog.Any("panic", r),
					)
					err = errors.New("internal server error")
				}
			}()
			return next(ctx)
		}
	}
}

// ---- Rate Limiting Middleware ----

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
// limit is the maximum connections per window from a single IP.
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

// RateLimit returns middleware that limits connections per IP.
func RateLimit(limiter *RateLimiter) Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return func(ctx *Context) error {
			ip := extractIP(ctx.Connection.RemoteAddr())
			if !limiter.Allow(ip) {
				return errors.New("too many connections, please try again later")
			}
			return next(ctx)
		}
	}
}

// ---- IP Filtering Middleware ----

// IPFilter allows or denies connections based on IP addresses.
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

// IPFilterMiddleware returns middleware that filters connections by IP.
func IPFilterMiddleware(filter *IPFilter) Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return func(ctx *Context) error {
			ip := extractIP(ctx.Connection.RemoteAddr())
			if !filter.IsAllowed(ip) {
				return errors.New("connection not allowed from your IP address")
			}
			return next(ctx)
		}
	}
}

// ---- Domain Validation Middleware ----

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
	return func(ctx *Context) error {
		from, ok := ctx.Get("from")
		if !ok {
			return ctx.Next()
		}

		path := from.(Path)
		if path.IsNull() {
			// Null sender (bounce) is always allowed
			return ctx.Next()
		}

		if !validator.IsAllowedSender(path.Mailbox.Domain) {
			return fmt.Errorf("sender domain %s is not allowed", path.Mailbox.Domain)
		}

		return ctx.Next()
	}
}

// ValidateRecipient returns a handler that validates recipient domains.
func ValidateRecipient(validator *DomainValidator) HandlerFunc {
	return func(ctx *Context) error {
		to, ok := ctx.Get("to")
		if !ok {
			return ctx.Next()
		}

		path := to.(Path)
		if !validator.IsLocalDomain(path.Mailbox.Domain) {
			// Check if client is authenticated for relay
			if !ctx.IsAuthenticated() {
				return fmt.Errorf("relay not permitted for %s", path.Mailbox.Domain)
			}
		}

		return ctx.Next()
	}
}

// ---- Helper Functions ----

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

// ---- Convenience Middleware Groups ----

// SecureDefaults returns a set of middleware suitable for production use.
// This includes logging, recovery, and rate limiting.
func SecureDefaults(logger *slog.Logger) []Middleware {
	return []Middleware{
		Recovery(logger),
		Logger(logger),
		RateLimit(NewRateLimiter(100, time.Minute)), // 100 connections/minute per IP
	}
}

// DevelopmentDefaults returns middleware suitable for development.
// This includes verbose logging and recovery.
func DevelopmentDefaults(logger *slog.Logger) []Middleware {
	return []Middleware{
		Recovery(logger),
		Logger(logger),
	}
}
