# mail

Package `mail` defines Raven's core message model: envelope, headers, body, trace fields, and builder APIs.

## Import

```go
import "github.com/synqronlabs/raven/mail"
```

## What It Does

- Represents SMTP envelope and RFC 5322 content separately.
- Provides fluent message construction via `MailBuilder`.
- Validates header/body constraints (line endings, required headers, lengths).
- Supports JSON and MessagePack serialization helpers.

## Key API

- `NewMailBuilder()`
- `(*MailBuilder).Build()`
- `(*Content).Validate()`
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
```
