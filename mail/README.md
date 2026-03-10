# mail

Package `mail` defines Raven's core message model and MIME helpers: envelope, headers, body, trace fields, builder APIs, and parsed MIME trees.

## Import

```go
import "github.com/synqronlabs/raven/mail"
```

## What It Does

- Represents SMTP envelope and RFC 5322 content separately.
- Provides fluent message construction via `MailBuilder`, including multipart content and attachments.
- Parses message content into `MIMEPart` trees and serializes MIME structures back to wire bytes.
- Validates header/body constraints (line endings, required headers, lengths).
- Supports JSON and MessagePack serialization helpers.

## Key API

- `NewMailBuilder()`
- `(*MailBuilder).Build()`
- `(*Content).Validate()`
- `(*Content).ToMIME()`, `(*Content).FromMIME(...)`
- `(*MIMEPart).IsMultipart()`, `(*MIMEPart).ToBytes()`
- `(*Mail).ToJSON()`, `FromJSON(...)`
- `(*Mail).ToMessagePack()`, `FromMessagePack(...)`

## Example

```go
msg, err := mail.NewMailBuilder().
    From("sender@example.com").
    To("recipient@example.com").
    Subject("Hello from Raven").
    TextBody("Body content").
    Build()
if err != nil {
    panic(err)
}

if err := msg.Content.Validate(); err != nil {
    panic(err)
}

part, err := msg.Content.ToMIME()
if err != nil {
    panic(err)
}

if err := msg.Content.FromMIME(part); err != nil {
    panic(err)
}
```
