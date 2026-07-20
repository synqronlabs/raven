# client

Package `client` provides SMTP client utilities for connecting, probing, authenticating, and sending mail.

## Import

```go
import "github.com/synqronlabs/raven/client"
```

## What It Does

- Connects with plain SMTP, STARTTLS, or implicit TLS.
- Supports AUTH flows (for servers that advertise them).
- Sends structured `mail.Mail` objects.
- Streams raw `.eml` messages from `io.Reader` with caller-supplied envelopes.
- Provides probing helpers to inspect server capabilities.

## Key API

- `NewDialer(host, port)`
- `(*Dialer).Dial()`, `(*Client).Send(mail)`
- `(*Client).SendRaw(envelope, reader)`
- `NewPool(dialer, size)`, `(*Pool).Send(...)`, `(*Pool).SendRaw(...)`
- `Probe(...)`, `ProbeWithSTARTTLS(...)`, `ProbeTLS(...)`

## Example

```go
dialer := client.NewDialer("smtp.example.com", 587)
dialer.StartTLS = true
dialer.Auth = &client.ClientAuth{
    Username: "user",
    Password: "pass",
}

c, err := dialer.Dial()
if err != nil {
    panic(err)
}
defer c.Quit()

for _, msg := range queue {
    result, err := c.Send(msg)
    if err != nil {
        panic(err)
    }
    _ = result.Success
}
```

Dial once for a sequential queue. For concurrent producers, use a bounded
`Pool` and close it during shutdown.

## Streaming Raw Mail

```go
f, err := os.Open("message.eml")
if err != nil {
    panic(err)
}
defer f.Close()

env := mail.Envelope{
    From: mail.Path{Mailbox: mail.MailboxAddress{LocalPart: "sender", Domain: "example.com"}},
    To: []mail.Recipient{
        {Address: mail.Path{Mailbox: mail.MailboxAddress{LocalPart: "rcpt", Domain: "example.net"}}},
    },
}

result, err := c.SendRaw(env, f)
if err != nil {
    panic(err)
}
_ = result.MessageID
```

`SendRaw` does not parse or validate the RFC 5322 stream. It applies SMTP
dot-stuffing for DATA and keeps the envelope separate. Do not reuse a reader
after it has been sent unless you seek it back to the beginning.
