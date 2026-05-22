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
- `(*Client).SendRaw(envelope, reader)`, `(*Client).SendRawMultiple(messages)`
- `(*Dialer).DialAndSendRaw(envelope, reader)`
- `QuickSend(...)`, `QuickSendTLS(...)`, `QuickSendMail(...)`
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

result, err := c.Send(msg)
if err != nil {
    panic(err)
}

_ = result.Success
```

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
    Size: 12345,
}

result, err := c.SendRaw(env, f)
if err != nil {
    panic(err)
}
_ = result.MessageID
```
