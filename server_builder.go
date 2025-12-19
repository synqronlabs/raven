package raven

import (
	"context"
	"crypto/tls"
	"log/slog"
	"time"
)

// HandlerFunc is the function signature for SMTP handlers.
// Returning an error will send an appropriate SMTP error response to the client.
type HandlerFunc func(ctx *Context) error

// Middleware wraps handlers to add functionality.
type Middleware func(HandlerFunc) HandlerFunc

// Context provides request-scoped values and methods for handlers.
type Context struct {
	Connection *Connection
	Mail       *Mail
	Keys       map[string]any
	handlers   []HandlerFunc
	index      int
}

// Set stores a value in the context for later retrieval.
func (c *Context) Set(key string, value any) {
	if c.Keys == nil {
		c.Keys = make(map[string]any)
	}
	c.Keys[key] = value
}

// Get retrieves a value from the context.
func (c *Context) Get(key string) (any, bool) {
	if c.Keys == nil {
		return nil, false
	}
	val, ok := c.Keys[key]
	return val, ok
}

// MustGet retrieves a value or panics if not found.
func (c *Context) MustGet(key string) any {
	val, ok := c.Get(key)
	if !ok {
		panic("Key \"" + key + "\" does not exist in context")
	}
	return val
}

// GetString retrieves a string value from the context.
func (c *Context) GetString(key string) string {
	if val, ok := c.Get(key); ok {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return ""
}

// Next executes the next handler in the chain.
func (c *Context) Next() error {
	c.index++
	for c.index < len(c.handlers) {
		if err := c.handlers[c.index](c); err != nil {
			return err
		}
		c.index++
	}
	return nil
}

// Abort stops the handler chain execution.
func (c *Context) Abort() {
	c.index = len(c.handlers)
}

// RemoteAddr returns the client's remote address as a string.
func (c *Context) RemoteAddr() string {
	return c.Connection.RemoteAddr().String()
}

// ClientHostname returns the hostname provided in HELO/EHLO.
func (c *Context) ClientHostname() string {
	c.Connection.mu.RLock()
	defer c.Connection.mu.RUnlock()
	return c.Connection.Trace.ClientHostname
}

// IsTLS returns whether the connection is using TLS.
func (c *Context) IsTLS() bool {
	return c.Connection.IsTLS()
}

// IsAuthenticated returns whether the client is authenticated.
func (c *Context) IsAuthenticated() bool {
	return c.Connection.IsAuthenticated()
}

// AuthIdentity returns the authenticated identity, or empty string if not authenticated.
func (c *Context) AuthIdentity() string {
	c.Connection.mu.RLock()
	defer c.Connection.mu.RUnlock()
	if c.Connection.Auth.Authenticated {
		return c.Connection.Auth.Identity
	}
	return ""
}

// ServerBuilder provides a fluent API for configuring an SMTP server.
type ServerBuilder struct {
	hostname           string
	addr               string
	logger             *slog.Logger
	tlsConfig          *tls.Config
	requireTLS         bool
	readTimeout        time.Duration
	writeTimeout       time.Duration
	dataTimeout        time.Duration
	idleTimeout        time.Duration
	maxMessageSize     int64
	maxRecipients      int
	maxConnections     int
	maxCommands        int64
	maxErrors          int
	maxLineLength      int
	maxReceivedHeaders int
	extensions         []ExtensionConfig
	authConfig         *AuthConfig
	onConnect          []HandlerFunc
	onDisconnect       []HandlerFunc
	onHelo             []HandlerFunc
	onEhlo             []HandlerFunc
	onMailFrom         []HandlerFunc
	onRcptTo           []HandlerFunc
	onData             []HandlerFunc
	onMessage          []HandlerFunc
	onReset            []HandlerFunc
	onHelp             []HandlerFunc
	middleware         []Middleware
	gracefulShutdown   *bool
	shutdownTimeout    time.Duration
}

// ExtensionConfig holds configuration for an SMTP extension.
type ExtensionConfig struct {
	Name    Extension
	Enabled bool
	Params  map[string]any
}

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	Mechanisms      []string
	RequireAuth     bool
	EnableLoginAuth bool // Deprecated LOGIN mechanism for legacy clients
	Handler         func(ctx context.Context, conn *Connection, mechanism, identity, password string) error
}

// New creates a new ServerBuilder.
func New(hostname string) *ServerBuilder {
	return &ServerBuilder{
		hostname:           hostname,
		addr:               ":25",
		readTimeout:        5 * time.Minute,
		writeTimeout:       5 * time.Minute,
		dataTimeout:        10 * time.Minute,
		idleTimeout:        5 * time.Minute,
		maxLineLength:      RecommendedLineLength,
		maxReceivedHeaders: 100, // Recommended minimum for loop detection
		logger:             slog.Default(),
	}
}

// Addr sets the address to listen on (e.g., ":25", "0.0.0.0:587").
func (b *ServerBuilder) Addr(addr string) *ServerBuilder {
	b.addr = addr
	return b
}

// Logger sets the structured logger for the server.
func (b *ServerBuilder) Logger(logger *slog.Logger) *ServerBuilder {
	b.logger = logger
	return b
}

// TLS configures TLS for the server.
// This enables the STARTTLS extension.
func (b *ServerBuilder) TLS(config *tls.Config) *ServerBuilder {
	b.tlsConfig = config
	return b
}

// RequireTLS requires clients to use TLS before authentication.
func (b *ServerBuilder) RequireTLS() *ServerBuilder {
	b.requireTLS = true
	return b
}

// ReadTimeout sets the timeout for reading commands.
func (b *ServerBuilder) ReadTimeout(d time.Duration) *ServerBuilder {
	b.readTimeout = d
	return b
}

// WriteTimeout sets the timeout for writing responses.
func (b *ServerBuilder) WriteTimeout(d time.Duration) *ServerBuilder {
	b.writeTimeout = d
	return b
}

// DataTimeout sets the timeout for reading message data.
func (b *ServerBuilder) DataTimeout(d time.Duration) *ServerBuilder {
	b.dataTimeout = d
	return b
}

// IdleTimeout sets the maximum idle time before disconnect.
func (b *ServerBuilder) IdleTimeout(d time.Duration) *ServerBuilder {
	b.idleTimeout = d
	return b
}

// MaxMessageSize sets the maximum allowed message size in bytes.
// This enables the SIZE extension and advertises the limit.
func (b *ServerBuilder) MaxMessageSize(size int64) *ServerBuilder {
	b.maxMessageSize = size
	return b
}

// MaxRecipients sets the maximum recipients per message.
func (b *ServerBuilder) MaxRecipients(n int) *ServerBuilder {
	b.maxRecipients = n
	return b
}

// MaxConnections sets the maximum concurrent connections.
func (b *ServerBuilder) MaxConnections(n int) *ServerBuilder {
	b.maxConnections = n
	return b
}

// MaxCommands sets the maximum commands per connection.
func (b *ServerBuilder) MaxCommands(n int64) *ServerBuilder {
	b.maxCommands = n
	return b
}

// MaxErrors sets the maximum errors before disconnect.
func (b *ServerBuilder) MaxErrors(n int) *ServerBuilder {
	b.maxErrors = n
	return b
}

// MaxLineLength sets the maximum command line length.
func (b *ServerBuilder) MaxLineLength(n int) *ServerBuilder {
	b.maxLineLength = n
	return b
}

// MaxReceivedHeaders sets the maximum number of Received headers allowed
// before rejecting the message (loop detection).
// Recommended: at least 100. Default: 100 (0 = unlimited)
func (b *ServerBuilder) MaxReceivedHeaders(n int) *ServerBuilder {
	b.maxReceivedHeaders = n
	return b
}

// GracefulShutdown enables or disables automatic graceful shutdown on SIGINT/SIGTERM.
// When enabled (default), the server will automatically call Shutdown() when
// receiving interrupt signals, allowing active connections to complete.
// Disable this if you want to handle signals yourself.
func (b *ServerBuilder) GracefulShutdown(enabled bool) *ServerBuilder {
	b.gracefulShutdown = &enabled
	return b
}

// ShutdownTimeout sets the timeout for graceful shutdown.
// After this duration, remaining connections will be forcefully closed.
// Default: 30 seconds.
func (b *ServerBuilder) ShutdownTimeout(d time.Duration) *ServerBuilder {
	b.shutdownTimeout = d
	return b
}

// Use adds global middleware that will be applied to all handlers.
func (b *ServerBuilder) Use(middleware ...Middleware) *ServerBuilder {
	b.middleware = append(b.middleware, middleware...)
	return b
}

// OnConnect adds handlers for new connections.
// Return an error to reject the connection.
func (b *ServerBuilder) OnConnect(handlers ...HandlerFunc) *ServerBuilder {
	b.onConnect = append(b.onConnect, handlers...)
	return b
}

// OnDisconnect adds handlers for disconnections.
func (b *ServerBuilder) OnDisconnect(handlers ...HandlerFunc) *ServerBuilder {
	b.onDisconnect = append(b.onDisconnect, handlers...)
	return b
}

// OnHelo adds handlers for HELO commands.
func (b *ServerBuilder) OnHelo(handlers ...HandlerFunc) *ServerBuilder {
	b.onHelo = append(b.onHelo, handlers...)
	return b
}

// OnEhlo adds handlers for EHLO commands.
func (b *ServerBuilder) OnEhlo(handlers ...HandlerFunc) *ServerBuilder {
	b.onEhlo = append(b.onEhlo, handlers...)
	return b
}

// OnMailFrom adds handlers for MAIL FROM commands.
// The Path is accessible via ctx.Get("from").
func (b *ServerBuilder) OnMailFrom(handlers ...HandlerFunc) *ServerBuilder {
	b.onMailFrom = append(b.onMailFrom, handlers...)
	return b
}

// OnRcptTo adds handlers for RCPT TO commands.
// The Path is accessible via ctx.Get("to").
func (b *ServerBuilder) OnRcptTo(handlers ...HandlerFunc) *ServerBuilder {
	b.onRcptTo = append(b.onRcptTo, handlers...)
	return b
}

// OnData adds handlers for DATA commands.
func (b *ServerBuilder) OnData(handlers ...HandlerFunc) *ServerBuilder {
	b.onData = append(b.onData, handlers...)
	return b
}

// OnMessage adds handlers for received messages.
// This is called after the full message has been received.
// The Mail object is accessible via ctx.Mail.
func (b *ServerBuilder) OnMessage(handlers ...HandlerFunc) *ServerBuilder {
	b.onMessage = append(b.onMessage, handlers...)
	return b
}

// OnReset adds handlers for RSET commands.
func (b *ServerBuilder) OnReset(handlers ...HandlerFunc) *ServerBuilder {
	b.onReset = append(b.onReset, handlers...)
	return b
}

// OnHelp adds handlers for HELP commands.
// The topic is accessible via ctx.GetString("topic").
// Set ctx.Set("help", []string{...}) to provide custom help text.
// If no custom help is set, the default help response is used.
func (b *ServerBuilder) OnHelp(handlers ...HandlerFunc) *ServerBuilder {
	b.onHelp = append(b.onHelp, handlers...)
	return b
}

// Auth configures authentication for the server.
// Pass mechanisms (e.g., "PLAIN", "LOGIN") and an optional handler.
func (b *ServerBuilder) Auth(mechanisms []string, handler func(ctx context.Context, conn *Connection, mechanism, identity, password string) error) *ServerBuilder {
	b.authConfig = &AuthConfig{
		Mechanisms: mechanisms,
		Handler:    handler,
	}
	return b
}

// RequireAuth requires authentication before sending mail.
// If no mechanisms are configured, this defaults to PLAIN only.
// Use EnableLoginAuth() to also enable the deprecated LOGIN mechanism.
func (b *ServerBuilder) RequireAuth() *ServerBuilder {
	if b.authConfig == nil {
		b.authConfig = &AuthConfig{
			Mechanisms: []string{"PLAIN"},
		}
	}
	b.authConfig.RequireAuth = true
	return b
}

// EnableLoginAuth enables the deprecated LOGIN authentication mechanism.
// LOGIN should only be used for compatibility with legacy clients that
// do not support PLAIN. This method has no effect if Auth() has not been called.
func (b *ServerBuilder) EnableLoginAuth() *ServerBuilder {
	if b.authConfig == nil {
		b.authConfig = &AuthConfig{
			Mechanisms: []string{"PLAIN"},
		}
	}
	b.authConfig.EnableLoginAuth = true
	return b
}

// Extension adds an opt-in SMTP extension.
// Use the extension helper functions like DSN(), Chunking(), etc.
func (b *ServerBuilder) Extension(ext ExtensionConfig) *ServerBuilder {
	b.extensions = append(b.extensions, ext)
	return b
}

// Build creates a Server from the builder configuration.
func (b *ServerBuilder) Build() (*Server, error) {
	// Build callbacks from handlers
	callbacks := b.buildCallbacks()

	// Build config
	config := ServerConfig{
		Hostname:           b.hostname,
		Addr:               b.addr,
		TLSConfig:          b.tlsConfig,
		RequireTLS:         b.requireTLS,
		MaxMessageSize:     b.maxMessageSize,
		MaxRecipients:      b.maxRecipients,
		MaxConnections:     b.maxConnections,
		MaxCommands:        b.maxCommands,
		MaxErrors:          b.maxErrors,
		ReadTimeout:        b.readTimeout,
		WriteTimeout:       b.writeTimeout,
		DataTimeout:        b.dataTimeout,
		IdleTimeout:        b.idleTimeout,
		MaxLineLength:      b.maxLineLength,
		MaxReceivedHeaders: b.maxReceivedHeaders,
		GracefulShutdown:   true, // Default enabled
		ShutdownTimeout:    30 * time.Second,
		Logger:             b.logger,
		Callbacks:          callbacks,
		// Note: Intrinsic extensions (8BITMIME, SMTPUTF8, ENHANCEDSTATUSCODES, PIPELINING)
		// are always enabled and require no configuration.
	}

	// Apply graceful shutdown settings if explicitly set
	if b.gracefulShutdown != nil {
		config.GracefulShutdown = *b.gracefulShutdown
	}
	if b.shutdownTimeout > 0 {
		config.ShutdownTimeout = b.shutdownTimeout
	}

	// Process opt-in extensions
	for _, ext := range b.extensions {
		switch ext.Name {
		case ExtDSN:
			config.EnableDSN = true
		case ExtChunking:
			config.EnableChunking = true
		}
	}

	// Process auth config
	if b.authConfig != nil {
		config.AuthMechanisms = b.authConfig.Mechanisms
		config.RequireAuth = b.authConfig.RequireAuth
		config.EnableLoginAuth = b.authConfig.EnableLoginAuth
	} else {
		config.AuthMechanisms = nil // Disable AUTH if not configured
	}

	return NewServer(config)
}

// Run builds and starts the server.
// This is a convenience method equivalent to Build() followed by ListenAndServe().
func (b *ServerBuilder) Run() error {
	server, err := b.Build()
	if err != nil {
		return err
	}
	return server.ListenAndServe()
}

// RunTLS builds and starts the server with implicit TLS.
// TLS must be configured with TLS() before calling this method.
func (b *ServerBuilder) RunTLS() error {
	server, err := b.Build()
	if err != nil {
		return err
	}
	return server.ListenAndServeTLS()
}

// buildCallbacks creates the Callbacks struct from the handler chains.
func (b *ServerBuilder) buildCallbacks() *Callbacks {
	cb := &Callbacks{}

	// Wrap handlers with global middleware
	wrapHandlers := func(handlers []HandlerFunc) []HandlerFunc {
		wrapped := make([]HandlerFunc, len(handlers))
		for i, h := range handlers {
			finalHandler := h
			// Apply middleware in reverse order
			for j := len(b.middleware) - 1; j >= 0; j-- {
				finalHandler = b.middleware[j](finalHandler)
			}
			wrapped[i] = finalHandler
		}
		return wrapped
	}

	if len(b.onConnect) > 0 {
		handlers := wrapHandlers(b.onConnect)
		cb.OnConnect = func(ctx context.Context, conn *Connection) error {
			c := &Context{Connection: conn, handlers: handlers, index: -1}
			return c.Next()
		}
	}

	if len(b.onDisconnect) > 0 {
		handlers := wrapHandlers(b.onDisconnect)
		cb.OnDisconnect = func(ctx context.Context, conn *Connection) {
			c := &Context{Connection: conn, handlers: handlers, index: -1}
			_ = c.Next()
		}
	}

	if len(b.onHelo) > 0 {
		handlers := wrapHandlers(b.onHelo)
		cb.OnHelo = func(ctx context.Context, conn *Connection, hostname string) error {
			c := &Context{Connection: conn, handlers: handlers, index: -1}
			c.Set("hostname", hostname)
			return c.Next()
		}
	}

	if len(b.onEhlo) > 0 {
		handlers := wrapHandlers(b.onEhlo)
		cb.OnEhlo = func(ctx context.Context, conn *Connection, hostname string) (map[Extension]string, error) {
			c := &Context{Connection: conn, handlers: handlers, index: -1}
			c.Set("hostname", hostname)
			err := c.Next()
			// Check if handler wants to override extensions
			if ext, ok := c.Get("extensions"); ok {
				return ext.(map[Extension]string), err
			}
			return nil, err
		}
	}

	if len(b.onMailFrom) > 0 {
		handlers := wrapHandlers(b.onMailFrom)
		cb.OnMailFrom = func(ctx context.Context, conn *Connection, from Path, params map[string]string) error {
			c := &Context{Connection: conn, handlers: handlers, index: -1}
			c.Set("from", from)
			c.Set("params", params)
			return c.Next()
		}
	}

	if len(b.onRcptTo) > 0 {
		handlers := wrapHandlers(b.onRcptTo)
		cb.OnRcptTo = func(ctx context.Context, conn *Connection, to Path, params map[string]string) error {
			c := &Context{Connection: conn, handlers: handlers, index: -1}
			c.Set("to", to)
			c.Set("params", params)
			return c.Next()
		}
	}

	if len(b.onData) > 0 {
		handlers := wrapHandlers(b.onData)
		cb.OnData = func(ctx context.Context, conn *Connection) error {
			c := &Context{Connection: conn, handlers: handlers, index: -1}
			return c.Next()
		}
	}

	if len(b.onMessage) > 0 {
		handlers := wrapHandlers(b.onMessage)
		cb.OnMessage = func(ctx context.Context, conn *Connection, mail *Mail) error {
			c := &Context{Connection: conn, Mail: mail, handlers: handlers, index: -1}
			return c.Next()
		}
	}

	if len(b.onReset) > 0 {
		handlers := wrapHandlers(b.onReset)
		cb.OnReset = func(ctx context.Context, conn *Connection) {
			c := &Context{Connection: conn, handlers: handlers, index: -1}
			_ = c.Next()
		}
	}

	if len(b.onHelp) > 0 {
		handlers := wrapHandlers(b.onHelp)
		cb.OnHelp = func(ctx context.Context, conn *Connection, topic string) []string {
			c := &Context{Connection: conn, handlers: handlers, index: -1}
			c.Set("topic", topic)
			_ = c.Next()
			// Check if handler set custom help text
			if help, ok := c.Get("help"); ok {
				if lines, ok := help.([]string); ok {
					return lines
				}
			}
			return nil
		}
	}

	// Auth callback
	if b.authConfig != nil && b.authConfig.Handler != nil {
		cb.OnAuth = b.authConfig.Handler
	}

	return cb
}
