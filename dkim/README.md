# dkim

Package `dkim` implements DomainKeys Identified Mail (RFC 6376).

## Import

```go
import "github.com/synqronlabs/raven/dkim"
```

## What It Does

- Signs RFC 5322 messages with RSA or Ed25519 keys.
- Verifies one or more DKIM signatures on incoming messages.
- Parses DKIM records and signatures into typed structs.

## Key API

- `(*Signer).Sign(message)`
- `Verify(ctx, resolver, message)`
- `SignMail(...)`, `SignMailMultiple(...)`, `QuickSign(...)`

## Example

```go
signer := &dkim.Signer{
    Domain:     "example.com",
    Selector:   "selector1",
    PrivateKey: privateKey,
}

sigHeader, err := signer.Sign(rawMessage)
if err != nil {
    panic(err)
}

_ = sigHeader

results, err := dkim.Verify(ctx, resolver, rawMessage)
if err != nil {
    panic(err)
}

for _, r := range results {
    if r.Status == dkim.StatusPass {
        // Verified signature.
    }
}
```
