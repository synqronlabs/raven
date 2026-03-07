# server

Package `server` implements an SMTP server with a Backend/Session design.

## Import

```go
import "github.com/synqronlabs/raven/server"
```

## What It Does

- Handles SMTP protocol flow and connection lifecycle.
- Delegates business logic to your `Backend` and `Session` implementations.
- Supports optional extensions like AUTH, STARTTLS, CHUNKING, DSN, SMTPUTF8.

## Key API

- `NewServer(backend, cfg)`
- `(*Server).ListenAndServe(ctx)`
- `Backend`, `Session`, `AuthSession`, `ChunkingSession`
- `MailOptions`, `RcptOptions`, `SMTPError`

## Example

```go
type Backend struct{}

func (b *Backend) NewSession(c *server.Conn) (server.Session, error) {
    return &Session{}, nil
}

type Session struct{}

func (s *Session) Mail(from string, opts *server.MailOptions) error { return nil }
func (s *Session) Rcpt(to string, opts *server.RcptOptions) error    { return nil }
func (s *Session) Data(r io.Reader) error                            { return nil }
func (s *Session) Reset()                                             {}
func (s *Session) Logout() error                                      { return nil }

srv := server.NewServer(&Backend{}, server.ServerConfig{
    Domain: "mx.example.com",
    Addr:   ":2525",
})

if err := srv.ListenAndServe(ctx); err != nil {
    panic(err)
}
```
