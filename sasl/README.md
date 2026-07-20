# sasl

Package `sasl` provides SASL mechanism primitives used during SMTP AUTH.

## Import

```go
import "github.com/synqronlabs/raven/sasl"
```

## What It Does

- Implements PLAIN and legacy LOGIN mechanism handlers.
- Provides a ready-made `sasl.Server` verifier for PLAIN.
- Defines client-side and server-side mechanism interfaces.
- Exposes typed errors for cancellation and malformed authentication payloads.

## Key API

- `NewPlain()`, `NewPlainServer()`
- `VerifyFunc`
- `Mechanism` interface
- `Server` interface
- `Credentials` and helper methods

## Example

```go
plain := sasl.NewPlain()
_ = plain

plainServer := sasl.NewPlainServer(func(creds *sasl.Credentials) error {
	_ = creds
	return nil
})
_ = plainServer
```

Prefer PLAIN inside TLS. LOGIN is not a standards-track SASL mechanism and is
provided only for compatibility with older SMTP clients.
