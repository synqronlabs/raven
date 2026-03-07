// Package sasl implements SASL mechanisms for SMTP authentication (RFC 4954).
package sasl

import (
	"errors"
)

var (
	// ErrAuthenticationCancelled is returned when the client sends "*" to cancel authentication.
	ErrAuthenticationCancelled = errors.New("authentication cancelled")

	// ErrInvalidFormat is returned when the authentication data format is invalid.
	ErrInvalidFormat = errors.New("invalid authentication format")

	// ErrInvalidBase64 is returned when base64 decoding fails.
	ErrInvalidBase64 = errors.New("invalid base64 encoding")
)

// Credentials represents authentication credentials from a SASL exchange.
type Credentials struct {
	AuthorizationID  string // Identity to act as (authzid)
	AuthenticationID string // Identity being authenticated (authcid)
	Password         string
}

// Identity returns the effective identity for authorization.
func (c *Credentials) Identity() string {
	if c.AuthorizationID != "" {
		return c.AuthorizationID
	}
	return c.AuthenticationID
}

// Mechanism defines the interface for SASL authentication mechanisms.
// This is used on the server side to process client authentication.
type Mechanism interface {
	Name() string
	Start(initialResponse string) (challenge string, done bool, err error)
	Next(response string) (challenge string, done bool, err error)
	Credentials() *Credentials
}

// Server is the server-side interface for SASL authentication.
// It handles the authentication exchange and validates credentials.
type Server interface {
	// Next processes a response from the client and returns a challenge.
	// If done is true, authentication is complete.
	// If err is nil and done is true, authentication succeeded.
	// If err is not nil and done is true, authentication failed.
	Next(response []byte) (challenge []byte, done bool, err error)
}
