# io

Package `io` provides strict SMTP line-reading and ASCII helper functions.

## Import

```go
import ravenio "github.com/synqronlabs/raven/io"
```

## What It Does

- Reads CRLF-terminated SMTP lines safely.
- Enforces maximum line length.
- Optionally enforces 7-bit ASCII-only input.
- Detects non-ASCII content in strings.

## Key API

- `ReadLine(reader, max, enforce)`
- `ContainsNonASCII(s)`

## Example

```go
line, err := ravenio.ReadLine(reader, 2000, true)
if err != nil {
    panic(err)
}

_ = line
```
