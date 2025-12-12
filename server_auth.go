package raven

import (
	"bufio"
	"fmt"
	"slices"
	"strings"
	"time"

	ravenio "github.com/synqronlabs/raven/io"
	"github.com/synqronlabs/raven/sasl"
)

// handleAuth processes the AUTH command.
func (s *Server) handleAuth(conn *Connection, args string, reader *bufio.Reader) *Response {
	if conn.State() < StateGreeted {
		resp := ResponseBadSequence("Send EHLO first")
		return &resp
	}
	if conn.IsAuthenticated() {
		resp := ResponseBadSequence("Already authenticated")
		return &resp
	}
	if (s.config.RequireTLS) && !conn.IsTLS() {
		// 530 must be returned when TLS is required
		resp := ResponseAuthRequired("Must issue a STARTTLS command first")
		return &resp
	}

	parts := strings.SplitN(args, " ", 2)
	mechanismName := strings.ToUpper(parts[0])

	effectiveMechanisms := s.getEffectiveAuthMechanisms()

	supported := slices.Contains(effectiveMechanisms, mechanismName)
	if !supported {
		return &Response{Code: CodeParameterNotImpl, EnhancedCode: string(ESCInvalidArgs), Message: "Mechanism not supported"}
	}

	var mechanism sasl.Mechanism
	switch mechanismName {
	case "PLAIN":
		mechanism = sasl.NewPlain()
	case "LOGIN":
		mechanism = sasl.NewLogin()
	default:
		return &Response{Code: CodeParameterNotImpl, EnhancedCode: string(ESCInvalidArgs), Message: "Mechanism not implemented"}
	}

	// Get initial response if provided
	var initialResponse string
	if len(parts) > 1 {
		initialResponse = parts[1]
	}

	// Run the SASL exchange
	creds, err := s.runSASLExchange(conn, mechanism, initialResponse, reader)
	if err != nil {
		// 535 for authentication credentials invalid
		resp := ResponseAuthCredentialsInvalid(fmt.Sprintf("Authentication failed: %v", err))
		return &resp
	}

	if s.config.Callbacks != nil && s.config.Callbacks.OnAuth != nil {
		if err := s.config.Callbacks.OnAuth(conn.Context(), conn, mechanismName, creds.Identity(), creds.Password); err != nil {
			resp := ResponseAuthCredentialsInvalid("")
			return &resp
		}
	}

	// Set authenticated state
	conn.mu.Lock()
	conn.Auth = AuthInfo{
		Authenticated:   true,
		Mechanism:       mechanismName,
		Identity:        creds.Identity(),
		AuthenticatedAt: time.Now(),
	}
	conn.mu.Unlock()

	return &Response{
		Code:         CodeAuthSuccess,
		EnhancedCode: string(ESCSecuritySuccess),
		Message:      "Authentication successful",
	}
}

// runSASLExchange runs the SASL authentication exchange with the client.
func (s *Server) runSASLExchange(conn *Connection, mechanism sasl.Mechanism, initialResponse string, reader *bufio.Reader) (*sasl.Credentials, error) {
	// Start the mechanism
	challenge, done, err := mechanism.Start(initialResponse)
	if err != nil {
		return nil, err
	}

	// Continue the exchange until done
	for !done {
		// Send challenge to client
		s.writeResponse(conn, Response{Code: 334, Message: challenge})

		// Read response from client
		response, err := ravenio.ReadLine(reader, s.config.MaxLineLength, true)
		if err != nil {
			return nil, err
		}

		// Process the response
		challenge, done, err = mechanism.Next(response)
		if err != nil {
			return nil, err
		}
	}

	return mechanism.Credentials(), nil
}

// getEffectiveAuthMechanisms returns enabled auth mechanisms.
func (s *Server) getEffectiveAuthMechanisms() []string {
	if !s.config.EnableLoginAuth {
		// Filter out LOGIN
		result := make([]string, 0, len(s.config.AuthMechanisms))
		for _, m := range s.config.AuthMechanisms {
			if strings.ToUpper(m) != "LOGIN" {
				result = append(result, m)
			}
		}
		return result
	}
	return s.config.AuthMechanisms
}
