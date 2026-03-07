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
- Provides probing helpers to inspect server capabilities.

## Key API

- `NewDialer(host, port)`
- `(*Dialer).Dial()`, `(*Client).Send(mail)`
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
