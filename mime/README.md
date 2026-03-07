# mime

Package `mime` parses MIME content into structured parts.

## Import

```go
import "github.com/synqronlabs/raven/mime"
```

## What It Does

- Parses single-part and multipart message bodies.
- Extracts standard MIME metadata (content type, transfer encoding, charset, filename, content-id).
- Validates encoding constraints for composite media types.

## Key API

- `Parse(headers, body)`
- `ParseSinglePart(...)`
- `ParseMultipart(...)`
- `ValidateCompositeEncoding(...)`

## Example

```go
part, err := mime.Parse(headers, body)
if err != nil {
    panic(err)
}

if part.IsMultipart() {
    for _, child := range part.Parts {
        _ = child.ContentType
    }
}
```
