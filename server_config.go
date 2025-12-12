package raven

import (
	"context"
	"crypto/tls"
	"log/slog"
	"time"
)

// ServerConfig contains configuration options for the SMTP server.
// Prefer using the builder pattern via raven.New().
type ServerConfig struct {
	Hostname           string
	Addr               string
	TLSConfig          *tls.Config
	RequireTLS         bool
	AuthMechanisms     []string
	RequireAuth        bool
	EnableLoginAuth    bool
	MaxMessageSize     int64
	MaxRecipients      int
	MaxConnections     int
	MaxCommands        int64
	MaxErrors          int
	ReadTimeout        time.Duration
	WriteTimeout       time.Duration
	DataTimeout        time.Duration
	IdleTimeout        time.Duration
	MaxLineLength      int
	EnableDSN          bool
	EnableChunking     bool
	MaxReceivedHeaders int
	GracefulShutdown   bool
	ShutdownTimeout    time.Duration
	Logger             *slog.Logger
	Callbacks          *Callbacks
}

// DefaultServerConfig returns a ServerConfig with sensible defaults.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Addr:               ":25",
		ReadTimeout:        5 * time.Minute,
		WriteTimeout:       5 * time.Minute,
		DataTimeout:        10 * time.Minute,
		IdleTimeout:        5 * time.Minute,
		MaxLineLength:      512,
		MaxReceivedHeaders: 100, // RFC 5321 Section 6.3 recommends at least 100
		// Opt-in extensions - disabled by default
		EnableDSN:      false,
		EnableChunking: false,
		// Auth disabled by default (set AuthMechanisms to enable)
		AuthMechanisms:   nil,
		GracefulShutdown: true,
		ShutdownTimeout:  30 * time.Second,
		Logger:           slog.Default(),
	}
}

// SubmissionConfig returns a ServerConfig for mail submission (port 587).
func SubmissionConfig() ServerConfig {
	config := DefaultServerConfig()
	config.Addr = ":587"
	config.AuthMechanisms = []string{"PLAIN"}
	config.RequireAuth = true
	config.RequireTLS = true
	return config
}

// Callbacks defines event handlers for SMTP server events.
// All callbacks are optional. Return an error to reject the action.
type Callbacks struct {
	OnConnect    func(ctx context.Context, conn *Connection) error
	OnDisconnect func(ctx context.Context, conn *Connection)
	OnHelo       func(ctx context.Context, conn *Connection, hostname string) error
	OnEhlo       func(ctx context.Context, conn *Connection, hostname string) (extensions map[Extension]string, err error)
	OnStartTLS   func(ctx context.Context, conn *Connection) error
	OnAuth       func(ctx context.Context, conn *Connection, mechanism, identity, password string) error
	// OnMailFrom is called when MAIL FROM command is received.
	// Return an error to reject the sender with a 550 response.
	OnMailFrom func(ctx context.Context, conn *Connection, from Path, params map[string]string) error

	// OnRcptTo is called for each RCPT TO command.
	// Return an error to reject the recipient with a 550 response.
	OnRcptTo func(ctx context.Context, conn *Connection, to Path, params map[string]string) error

	// OnData is called when DATA command is received and before message content.
	// Return an error to reject with a 554 response.
	OnData func(ctx context.Context, conn *Connection) error

	// OnBDAT is called when BDAT command is received (CHUNKING extension).
	// The size parameter indicates the chunk size, last indicates if this is the final chunk.
	// Return an error to reject with a 554 response.
	OnBDAT func(ctx context.Context, conn *Connection, size int64, last bool) error

	// OnMessage is called when a complete message has been received.
	// The Mail object contains the envelope and content.
	// Return an error to reject the message with a 554 response.
	OnMessage func(ctx context.Context, conn *Connection, mail *Mail) error

	// OnReset is called when RSET command is received.
	OnReset func(ctx context.Context, conn *Connection)

	// OnVerify is called when VRFY command is received.
	// Return the verified address or an error.
	OnVerify func(ctx context.Context, conn *Connection, address string) (MailboxAddress, error)

	// OnExpand is called when EXPN command is received.
	// Return the list of addresses or an error.
	OnExpand func(ctx context.Context, conn *Connection, listName string) ([]MailboxAddress, error)

	// OnHelp is called when HELP command is received.
	// Return a slice of help text lines, or nil to use the default response.
	// The topic parameter contains the optional argument (e.g., "HELP MAIL" -> topic="MAIL").
	OnHelp func(ctx context.Context, conn *Connection, topic string) []string
}
