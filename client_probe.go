package raven

import (
	"fmt"
	"maps"
	"strings"
)

// ServerCapabilities represents SMTP server capabilities.
type ServerCapabilities struct {
	IsESMTP             bool
	Greeting            string
	Hostname            string
	Extensions          map[Extension]string
	TLS                 bool
	Auth                []string
	MaxSize             int64
	Pipelining          bool
	EightBitMIME        bool
	SMTPUTF8            bool
	DSN                 bool
	Chunking            bool
	BinaryMIME          bool
	EnhancedStatusCodes bool
}

// HasExtension checks if a specific extension is supported.
func (s *ServerCapabilities) HasExtension(ext Extension) bool {
	_, ok := s.Extensions[ext]
	return ok
}

// GetExtensionParam returns the parameters for an extension.
func (s *ServerCapabilities) GetExtensionParam(ext Extension) string {
	return s.Extensions[ext]
}

// SupportsAuth checks if a specific auth mechanism is supported.
func (s *ServerCapabilities) SupportsAuth(mechanism string) bool {
	mechanism = strings.ToUpper(mechanism)
	for _, m := range s.Auth {
		if strings.ToUpper(m) == mechanism {
			return true
		}
	}
	return false
}

// String returns a human-readable summary of the server capabilities.
func (s *ServerCapabilities) String() string {
	var sb strings.Builder

	sb.WriteString("Server Capabilities:\n")
	sb.WriteString(fmt.Sprintf("  ESMTP: %v\n", s.IsESMTP))
	sb.WriteString(fmt.Sprintf("  Hostname: %s\n", s.Hostname))

	if s.MaxSize > 0 {
		sb.WriteString(fmt.Sprintf("  Max Size: %d bytes\n", s.MaxSize))
	}

	sb.WriteString("  Extensions:\n")
	for ext, param := range s.Extensions {
		if param != "" {
			sb.WriteString(fmt.Sprintf("    - %s %s\n", ext, param))
		} else {
			sb.WriteString(fmt.Sprintf("    - %s\n", ext))
		}
	}

	if len(s.Auth) > 0 {
		sb.WriteString(fmt.Sprintf("  Auth Mechanisms: %s\n", strings.Join(s.Auth, ", ")))
	}

	return sb.String()
}

// Extensions returns the client's discovered server extensions.
func (c *Client) Extensions() map[Extension]string {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Return a copy to prevent modification
	result := make(map[Extension]string, len(c.extensions))
	maps.Copy(result, c.extensions)
	return result
}

// HasExtension checks if the server supports a specific extension.
func (c *Client) HasExtension(ext Extension) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, ok := c.extensions[ext]
	return ok
}

// GetExtensionParam returns the parameter value for an extension.
func (c *Client) GetExtensionParam(ext Extension) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.extensions[ext]
}

// Capabilities returns a detailed analysis of the server's capabilities.
// Hello() must be called first to probe the server.
func (c *Client) Capabilities() *ServerCapabilities {
	c.mu.Lock()
	defer c.mu.Unlock()

	caps := &ServerCapabilities{
		IsESMTP:    c.isESMTP,
		Greeting:   c.greeting,
		Extensions: make(map[Extension]string, len(c.extensions)),
	}

	// Copy extensions
	maps.Copy(caps.Extensions, c.extensions)

	// Parse specific extensions
	for ext, param := range c.extensions {
		switch ext {
		case ExtSTARTTLS:
			caps.TLS = true
		case ExtAuth:
			caps.Auth = strings.Fields(param)
		case ExtSize:
			if param != "" {
				fmt.Sscanf(param, "%d", &caps.MaxSize)
			}
		case ExtPipelining:
			caps.Pipelining = true
		case Ext8BitMIME:
			caps.EightBitMIME = true
		case ExtSMTPUTF8:
			caps.SMTPUTF8 = true
		case ExtDSN:
			caps.DSN = true
		case ExtChunking:
			caps.Chunking = true
		case ExtBinaryMIME:
			caps.BinaryMIME = true
		case ExtEnhancedStatusCodes:
			caps.EnhancedStatusCodes = true
		}
	}

	return caps
}

// Probe connects to a server and returns its capabilities.
func Probe(address string) (*ServerCapabilities, error) {
	return ProbeWithConfig(address, nil)
}

// ProbeWithConfig probes a server with custom configuration.
func ProbeWithConfig(address string, config *ClientConfig) (*ServerCapabilities, error) {
	client := NewClient(config)

	if err := client.Dial(address); err != nil {
		return nil, err
	}
	defer client.Close()

	if err := client.Hello(); err != nil {
		return nil, err
	}

	return client.Capabilities(), nil
}

// ProbeTLS probes a server using implicit TLS (typically port 465).
func ProbeTLS(address string) (*ServerCapabilities, error) {
	return ProbeTLSWithConfig(address, nil)
}

// ProbeTLSWithConfig probes a server using implicit TLS with custom configuration.
func ProbeTLSWithConfig(address string, config *ClientConfig) (*ServerCapabilities, error) {
	client := NewClient(config)

	if err := client.DialTLS(address); err != nil {
		return nil, err
	}
	defer client.Close()

	if err := client.Hello(); err != nil {
		return nil, err
	}

	caps := client.Capabilities()
	// Note: Already using TLS, so STARTTLS won't be advertised
	return caps, nil
}

// ProbeWithSTARTTLS probes a server, upgrades to TLS via STARTTLS, and returns capabilities.
func ProbeWithSTARTTLS(address string) (*ServerCapabilities, error) {
	return ProbeWithSTARTTLSConfig(address, nil)
}

// ProbeWithSTARTTLSConfig probes a server with STARTTLS using custom configuration.
func ProbeWithSTARTTLSConfig(address string, config *ClientConfig) (*ServerCapabilities, error) {
	client := NewClient(config)

	if err := client.Dial(address); err != nil {
		return nil, err
	}
	defer client.Close()

	// First EHLO to check for STARTTLS
	if err := client.Hello(); err != nil {
		return nil, err
	}

	if !client.HasExtension(ExtSTARTTLS) {
		return nil, ErrTLSNotSupported
	}

	// Upgrade to TLS
	if err := client.StartTLS(); err != nil {
		return nil, err
	}

	// EHLO again after STARTTLS
	if err := client.Hello(); err != nil {
		return nil, err
	}

	return client.Capabilities(), nil
}

// IsTLS returns whether the connection is using TLS.
func (c *Client) IsTLS() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isTLS
}

// IsESMTP returns whether the server supports Extended SMTP.
func (c *Client) IsESMTP() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isESMTP
}

// IsAuthenticated returns whether the client has authenticated.
func (c *Client) IsAuthenticated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.authenticated
}

// Greeting returns the server's initial greeting message.
func (c *Client) Greeting() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.greeting
}

// LastResponse returns the most recent server response.
func (c *Client) LastResponse() *ClientResponse {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastResponse
}
