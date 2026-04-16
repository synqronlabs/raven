# sasl

Package `sasl` provides SASL mechanism primitives used during SMTP AUTH.

## Import

```go
import "github.com/synqronlabs/raven/sasl"
```

## What It Does

- Implements LOGIN and PLAIN mechanism handlers.
- Provides ready-made `sasl.Server` verifiers for LOGIN and PLAIN.
- Defines client-side and server-side mechanism interfaces.
- Exposes typed errors for cancellation and malformed authentication payloads.

## Key API

- `NewPlain()`, `NewLogin()`
- `NewPlainServer()`, `NewLoginServer()`
- `VerifyFunc`
- `Mechanism` interface
- `Server` interface
- `Credentials` and helper methods

## Example

```go
plain := sasl.NewPlain()
_ = plain

login := sasl.NewLogin()
_ = login

plainServer := sasl.NewPlainServer(func(creds *sasl.Credentials) error {
	_ = creds
	return nil
})
_ = plainServer
```
