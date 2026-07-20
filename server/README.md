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
- `Backend`, `Session`, `AuthSession`
- `MailOptions`, `RcptOptions`, `SMTPError`

## Example

```go
type Backend struct{}

func (b *Backend) NewSession(c *server.Conn) (server.Session, error) {
    return &Session{}, nil
}

type Session struct{}

func (s *Session) Mail(from string, opts *server.MailOptions) error { return nil }
func (s *Session) Rcpt(to string, opts *server.RcptOptions) error   { return nil }
func (s *Session) Data(headers server.MessageHeaders, body io.Reader) error {
    // Replace io.Discard with a queue, MIME walker, or bounded spool.
    _, err := io.Copy(io.Discard, body)
    return err
}
func (s *Session) Reset()        {}
func (s *Session) Logout() error { return nil }

srv := server.NewServer(&Backend{}, server.ServerConfig{
    Domain:         "mx.example.com",
    Addr:           ":2525",
    EnableSMTPUTF8: true, // Opt in to RFC 6531 support.
})

if err := srv.ListenAndServe(ctx); err != nil {
    panic(err)
}
```

`Data` must consume `body` before returning, even when rejecting a message.
`headers` contains the raw header block, including Raven's `Received` field but
not the blank-line separator. To create a complete seekable message for
DKIM/ARC, write `headers`, `"\r\n"`, and `body` to a caller-owned spool.
