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
		return &Response{Code: CodeBadSequence, Message: "Send EHLO first"}
	}
	if conn.IsAuthenticated() {
		return &Response{Code: CodeBadSequence, Message: "Already authenticated"}
	}
	if s.requireTLS && !conn.IsTLS() {
		return &Response{Code: CodeAuthRequired, EnhancedCode: string(ESCSecurityError), Message: "Must issue a STARTTLS command first"}
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
		return &Response{Code: CodeAuthCredentialsInvalid, EnhancedCode: string(ESCAuthCredentialsInvalid), Message: fmt.Sprintf("Authentication failed: %v", err)}
	}

	// Call custom auth handler if provided
	if s.authHandler != nil {
		ctx := s.newContext(conn, nil)
		ctx.Request = Request{Command: CmdAuth, Args: args}
		if resp := s.authHandler(ctx, mechanismName, creds.Identity(), creds.Password); resp != nil {
			return resp
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
		response, err := ravenio.ReadLine(reader, s.maxLineLength, true)
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
