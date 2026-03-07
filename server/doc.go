// Package server provides an idiomatic Go SMTP server implementation.
//
// This package uses the Backend/Session pattern, similar to database/sql
// and emersion/go-smtp. It separates the concerns of:
//   - Protocol handling (the Server and Conn types)
//   - Business logic (the Backend and Session interfaces)
//
// # Basic Usage
//
// Implement the Backend and Session interfaces:
//
//	type MyBackend struct{}
//
//	func (b *MyBackend) NewSession(c *server.Conn) (server.Session, error) {
//	    return &MySession{}, nil
//	}
//
//	type MySession struct {
//	    from string
//	    to   []string
//	}
//
//	func (s *MySession) Mail(from string, opts *server.MailOptions) error {
//	    s.from = from
//	    return nil
//	}
//
//	func (s *MySession) Rcpt(to string, opts *server.RcptOptions) error {
//	    s.to = append(s.to, to)
//	    return nil
//	}
//
//	func (s *MySession) Data(r io.Reader) error {
//	    // Process message from r
//	    return nil
//	}
//
//	func (s *MySession) Reset() {}
//
//	func (s *MySession) Logout() error { return nil }
//
// Then create and start the server:
//
//	cfg := server.ServerConfig{
//	    Domain:          "mail.example.com",
//	    Addr:            ":25",
//	    MaxMessageBytes: 25 * 1024 * 1024,
//	}
//
//	srv := server.NewServer(&MyBackend{}, cfg)
//	err := srv.ListenAndServe(context.Background())
//
// # Authentication
//
// To support SMTP authentication, implement the AuthSession interface:
//
//	type MySession struct {
//	    // ...
//	}
//
//	func (s *MySession) AuthMechanisms() []string {
//	    return []string{"PLAIN", "LOGIN"}
//	}
//
//	func (s *MySession) Auth(mech string) (sasl.Server, error) {
//	    return &mySASLServer{}, nil
//	}
//
// The server automatically detects if your Session implements AuthSession
// using a type assertion and advertises AUTH accordingly.
//
// # CHUNKING (BDAT)
//
// To support the CHUNKING extension, implement the ChunkingSession interface:
//
//	func (s *MySession) Chunk(data []byte, last bool) error {
//	    // Process chunk
//	    return nil
//	}
//
// # Error Handling
//
// Return *SMTPError from Session methods to send specific SMTP response codes:
//
//	func (s *MySession) Rcpt(to string, opts *server.RcptOptions) error {
//	    if !isValidRecipient(to) {
//	        return &server.SMTPError{
//	            Code:         550,
//	            EnhancedCode: server.EnhancedCode{5, 1, 1},
//	            Message:      "User unknown",
//	        }
//	    }
//	    return nil
//	}
//
// Common errors are pre-defined: ErrAuthRequired, ErrMailboxNotFound, etc.
package server
