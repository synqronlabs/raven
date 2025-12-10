package raven

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"time"
)

// handleAuth processes the AUTH command.
func (s *Server) handleAuth(conn *Connection, args string, reader *bufio.Reader) *Response {
	if conn.State() < StateGreeted {
		return &Response{Code: CodeBadSequence, Message: "Send EHLO first"}
	}
	if conn.IsAuthenticated() {
		return &Response{Code: CodeBadSequence, Message: "Already authenticated"}
	}
	if (s.config.RequireTLS) && !conn.IsTLS() {
		return &Response{
			Code:         530,
			EnhancedCode: "5.7.0",
			Message:      "Must issue a STARTTLS command first",
		}
	}

	parts := strings.SplitN(args, " ", 2)
	mechanism := strings.ToUpper(parts[0])

	// Check if mechanism is supported
	supported := slices.Contains(s.config.AuthMechanisms, mechanism)
	if !supported {
		return &Response{Code: CodeParameterNotImpl, Message: "Mechanism not supported"}
	}

	var identity, password string
	var err error

	switch mechanism {
	case "PLAIN":
		identity, password, err = s.handleAuthPlain(conn, parts, reader)
	case "LOGIN":
		identity, password, err = s.handleAuthLogin(conn, reader)
	default:
		return &Response{Code: CodeParameterNotImpl, Message: "Mechanism not implemented"}
	}

	if err != nil {
		conn.RecordError(err)
		return &Response{Code: CodeTransactionFailed, Message: "Authentication failed"}
	}

	// Callback for verification
	if s.config.Callbacks != nil && s.config.Callbacks.OnAuth != nil {
		if err := s.config.Callbacks.OnAuth(conn.Context(), conn, mechanism, identity, password); err != nil {
			conn.RecordError(err)
			return &Response{
				Code:         CodeTransactionFailed,
				EnhancedCode: "5.7.8",
				Message:      "Authentication credentials invalid",
			}
		}
	}

	// Set authenticated state
	conn.mu.Lock()
	conn.Auth = AuthInfo{
		Authenticated:   true,
		Mechanism:       mechanism,
		Identity:        identity,
		AuthenticatedAt: time.Now(),
	}
	conn.mu.Unlock()

	return &Response{
		Code:         CodeAuthSuccess,
		EnhancedCode: "2.7.0",
		Message:      "Authentication successful",
	}
}

// handleAuthPlain processes PLAIN authentication.
func (s *Server) handleAuthPlain(conn *Connection, parts []string, reader *bufio.Reader) (identity, password string, err error) {
	var encoded string

	if len(parts) > 1 && parts[1] != "" {
		// Initial response provided
		encoded = parts[1]
	} else {
		// Request credentials
		s.writeResponse(conn, Response{Code: 334, Message: ""})
		line, err := s.readLine(reader)
		if err != nil {
			return "", "", err
		}
		encoded = line
	}

	// Cancel
	if encoded == "*" {
		return "", "", errors.New("authentication cancelled")
	}

	// Decode base64
	decoded, err := decodeBase64(encoded)
	if err != nil {
		return "", "", err
	}

	// Format: authzid\0authcid\0password
	parts2 := bytes.Split(decoded, []byte{0})
	if len(parts2) != 3 {
		return "", "", errors.New("invalid PLAIN format")
	}

	// authzid is optional, authcid is identity
	identity = string(parts2[1])
	if identity == "" {
		identity = string(parts2[0])
	}
	password = string(parts2[2])

	return identity, password, nil
}

// handleAuthLogin processes LOGIN authentication.
func (s *Server) handleAuthLogin(conn *Connection, reader *bufio.Reader) (identity, password string, err error) {
	// Request username
	s.writeResponse(conn, Response{Code: 334, Message: "VXNlcm5hbWU6"}) // "Username:" base64

	line, err := s.readLine(reader)
	if err != nil {
		return "", "", err
	}
	if line == "*" {
		return "", "", errors.New("authentication cancelled")
	}

	userBytes, err := decodeBase64(line)
	if err != nil {
		return "", "", err
	}
	identity = string(userBytes)

	// Request password
	s.writeResponse(conn, Response{Code: 334, Message: "UGFzc3dvcmQ6"}) // "Password:" base64

	line, err = s.readLine(reader)
	if err != nil {
		return "", "", err
	}
	if line == "*" {
		return "", "", errors.New("authentication cancelled")
	}

	passBytes, err := decodeBase64(line)
	if err != nil {
		return "", "", err
	}
	password = string(passBytes)

	return identity, password, nil
}

// decodeBase64 decodes a base64 string.
func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
