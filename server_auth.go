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
func (s *Server) handleAuth(client *Connection, args string, reader *bufio.Reader) *Response {
	if client.State() < StateGreeted {
		return &Response{Code: CodeBadSequence, Message: "Send EHLO first"}
	}
	if client.IsAuthenticated() {
		return &Response{Code: CodeBadSequence, Message: "Already authenticated"}
	}
	if s.requireTLS && !client.IsTLS() {
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
	creds, err := s.runSASLExchange(client, mechanism, initialResponse, reader)
	if err != nil {
		return &Response{Code: CodeAuthCredentialsInvalid, EnhancedCode: string(ESCAuthCredentialsInvalid), Message: fmt.Sprintf("Authentication failed: %v", err)}
	}

	// Call custom auth handler if provided
	if s.authHandler != nil {
		ctx := s.newContext(client, nil)
		ctx.Request = Request{Command: CmdAuth, Args: args}
		if resp := s.authHandler(ctx, mechanismName, creds.Identity(), creds.Password); resp != nil {
			return resp
		}
	}

	// Set authenticated state
	client.mu.Lock()
	client.Auth = AuthInfo{
		Authenticated:   true,
		Mechanism:       mechanismName,
		Identity:        creds.Identity(),
		AuthenticatedAt: time.Now(),
	}
	client.mu.Unlock()

	return &Response{
		Code:         CodeAuthSuccess,
		EnhancedCode: string(ESCSecuritySuccess),
		Message:      "Authentication successful",
	}
}

// runSASLExchange runs the SASL authentication exchange with the client.
func (s *Server) runSASLExchange(client *Connection, mechanism sasl.Mechanism, initialResponse string, reader *bufio.Reader) (*sasl.Credentials, error) {
	// Start the mechanism
	challenge, done, err := mechanism.Start(initialResponse)
	if err != nil {
		return nil, err
	}

	// Continue the exchange until done
	for !done {
		// Send challenge to client
		s.writeResponse(client, Response{Code: 334, Message: challenge})

		// Set read deadline for AUTH response
		if err := client.conn.SetReadDeadline(time.Now().Add(client.Limits.ReadTimeout)); err != nil {
			return nil, err
		}

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
