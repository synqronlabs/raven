# mail

Package `mail` defines Raven's SMTP envelope, RFC 5322 content model, message
builder, and streaming MIME helpers.

## Import

```go
import "github.com/synqronlabs/raven/mail"
```

## What It Does

- Represents SMTP envelope and RFC 5322 content separately.
- Provides fluent message construction via `MailBuilder`, including multipart content and attachments.
- Walks and validates MIME structure without retaining every part body.
- Validates header/body constraints (line endings, required headers, lengths).
- Provides helpers for prepending generated authentication headers to a stream.

## Key API

- `NewMailBuilder()`
- `(*MailBuilder).Build()`
- `(*Content).Validate()`
- `ParseHeaders(...)`, `Headers.Validate()`
- `WalkMIME(...)`, `MIMEWalkPart`
- `ValidateMIMEStream(...)`
- `NewHeaderPrependedReader(...)`, `PrependedSize(...)`

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

err = mail.WalkMIME(
    msg.Content.Headers,
    bytes.NewReader(msg.Content.Body),
    mail.MIMEWalkOptions{MaxDepth: 20, MaxParts: 1_000},
    func(part *mail.MIMEWalkPart) error {
        if !part.IsMultipart() {
            _, err := io.Copy(io.Discard, part.Body)
            return err
        }
        return nil
    },
)
if err != nil {
    panic(err)
}
```

`MIMEWalkPart.Body` is valid during the callback. Raven drains unread leaf data
before visiting the next part, so copy content that must outlive the callback.
For server workloads, keep the SMTP envelope and original message spool
separate instead of using the deprecated eager serialization and MIME-tree
compatibility helpers.
