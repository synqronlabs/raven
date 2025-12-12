package sasl

import (
	"bytes"
	"encoding/base64"
)

// Plain implements the PLAIN SASL mechanism (RFC 4616).
// Use only over TLS - passwords are transmitted in clear text.
type Plain struct {
	creds *Credentials
	done  bool
}

// NewPlain creates a new PLAIN mechanism handler.
func NewPlain() *Plain {
	return &Plain{}
}

// Name returns "PLAIN".
func (p *Plain) Name() string {
	return "PLAIN"
}

// Start processes the initial response or requests credentials.
func (p *Plain) Start(initialResponse string) (challenge string, done bool, err error) {
	if initialResponse == "" {
		// Request credentials - send empty challenge per RFC 4954
		return "", false, nil
	}

	return p.processResponse(initialResponse)
}

// Next processes the client's response to the challenge.
func (p *Plain) Next(response string) (challenge string, done bool, err error) {
	return p.processResponse(response)
}

// processResponse decodes and validates the PLAIN authentication data.
func (p *Plain) processResponse(response string) (challenge string, done bool, err error) {
	if response == "*" {
		p.done = true
		return "", true, ErrAuthenticationCancelled
	}

	decoded, err := base64.StdEncoding.DecodeString(response)
	if err != nil {
		p.done = true
		return "", true, ErrInvalidBase64
	}

	// Parse: authzid NUL authcid NUL passwd
	parts := bytes.Split(decoded, []byte{0})
	if len(parts) != 3 {
		p.done = true
		return "", true, ErrInvalidFormat
	}

	authzid := string(parts[0])
	authcid := string(parts[1])
	passwd := string(parts[2])

	if authcid == "" {
		p.done = true
		return "", true, ErrInvalidFormat
	}

	p.creds = &Credentials{
		AuthorizationID:  authzid,
		AuthenticationID: authcid,
		Password:         passwd,
	}
	p.done = true

	return "", true, nil
}

// Credentials returns the extracted credentials.
func (p *Plain) Credentials() *Credentials {
	return p.creds
}
