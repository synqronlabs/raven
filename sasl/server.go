package sasl

import (
	"encoding/base64"
	"errors"
	"fmt"
)

var errNilVerifyFunc = errors.New("nil verify func")

// VerifyFunc validates credentials extracted from a SASL exchange.
//
// Return nil to accept the credentials. Any non-nil error marks the
// authentication attempt as failed.
type VerifyFunc func(creds *Credentials) error

// NewPlainServer creates a sasl.Server for the PLAIN mechanism.
//
// On successful verification, the server exposes the authenticated identity via
// an AuthIdentity method so Raven's SMTP server can publish it on Conn.
func NewPlainServer(verify VerifyFunc) Server {
	return newVerifiedServer(NewPlain(), verify)
}

// NewLoginServer creates a sasl.Server for the LOGIN mechanism.
//
// On successful verification, the server exposes the authenticated identity via
// an AuthIdentity method so Raven's SMTP server can publish it on Conn.
func NewLoginServer(verify VerifyFunc) Server {
	return newVerifiedServer(NewLogin(), verify)
}

type verifiedServer struct {
	mechanism    Mechanism
	verify       VerifyFunc
	started      bool
	done         bool
	authIdentity string
}

func newVerifiedServer(mechanism Mechanism, verify VerifyFunc) Server {
	return &verifiedServer{
		mechanism: mechanism,
		verify:    verify,
	}
}

func (s *verifiedServer) Next(response []byte) (challenge []byte, done bool, err error) {
	if s.done {
		return nil, true, ErrInvalidFormat
	}

	encodedResponse := ""
	if len(response) > 0 {
		encodedResponse = base64.StdEncoding.EncodeToString(response)
	}

	var encodedChallenge string
	if !s.started {
		s.started = true
		encodedChallenge, done, err = s.mechanism.Start(encodedResponse)
	} else {
		encodedChallenge, done, err = s.mechanism.Next(encodedResponse)
	}
	if done {
		s.done = true
	}
	if err != nil {
		return nil, done, err
	}

	if !done {
		if encodedChallenge == "" {
			return nil, false, nil
		}

		challenge, err = base64.StdEncoding.DecodeString(encodedChallenge)
		if err != nil {
			s.done = true
			return nil, true, fmt.Errorf("%w: decoding %s challenge: %w", ErrInvalidBase64, s.mechanism.Name(), err)
		}

		return challenge, false, nil
	}

	if s.verify == nil {
		return nil, true, errNilVerifyFunc
	}

	creds := s.mechanism.Credentials()
	if creds == nil {
		return nil, true, ErrInvalidFormat
	}

	if err := s.verify(creds); err != nil {
		return nil, true, err
	}

	s.authIdentity = creds.Identity()
	return nil, true, nil
}

func (s *verifiedServer) AuthIdentity() string {
	return s.authIdentity
}
