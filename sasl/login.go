package sasl

import (
	"encoding/base64"
)

// Login state constants
const (
	loginStateInitial = iota
	loginStateUsername
	loginStatePassword
	loginStateDone
)

// Base64-encoded challenge strings for LOGIN mechanism
const (
	// LoginChallengeUsername is "Username:" encoded in base64
	LoginChallengeUsername = "VXNlcm5hbWU6"
	// LoginChallengePassword is "Password:" encoded in base64
	LoginChallengePassword = "UGFzc3dvcmQ6"
)

// Login implements the LOGIN SASL mechanism.
// DEPRECATED: Use PLAIN instead. Only for legacy client compatibility.
type Login struct {
	state    int
	username string
	creds    *Credentials
}

// NewLogin creates a new LOGIN mechanism handler.
func NewLogin() *Login {
	return &Login{
		state: loginStateInitial,
	}
}

// Name returns "LOGIN".
func (l *Login) Name() string {
	return "LOGIN"
}

// Start begins the LOGIN authentication exchange.
func (l *Login) Start(initialResponse string) (challenge string, done bool, err error) {
	l.state = loginStateUsername
	return LoginChallengeUsername, false, nil
}

// Next processes the client's response to a challenge.
func (l *Login) Next(response string) (challenge string, done bool, err error) {
	// Check for authentication cancellation
	if response == "*" {
		l.state = loginStateDone
		return "", true, ErrAuthenticationCancelled
	}

	switch l.state {
	case loginStateUsername:
		// Decode username
		decoded, err := base64.StdEncoding.DecodeString(response)
		if err != nil {
			l.state = loginStateDone
			return "", true, ErrInvalidBase64
		}
		l.username = string(decoded)

		// Request password
		l.state = loginStatePassword
		return LoginChallengePassword, false, nil

	case loginStatePassword:
		// Decode password
		decoded, err := base64.StdEncoding.DecodeString(response)
		if err != nil {
			l.state = loginStateDone
			return "", true, ErrInvalidBase64
		}

		// LOGIN doesn't support authzid, so AuthenticationID == Identity
		l.creds = &Credentials{
			AuthorizationID:  "",
			AuthenticationID: l.username,
			Password:         string(decoded),
		}
		l.state = loginStateDone

		return "", true, nil

	default:
		l.state = loginStateDone
		return "", true, ErrInvalidFormat
	}
}

// Credentials returns the extracted credentials.
func (l *Login) Credentials() *Credentials {
	return l.creds
}
