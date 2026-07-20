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

- `(*Signer).SignReader(message, size)`
- `SignMultipleReader(message, size, signers)`
- `(*Verifier).VerifyReader(ctx, message)`
- `ParseRecord(...)`, `ParseSignature(...)`

## Example

```go
signer := &dkim.Signer{
    Domain:     "example.com",
    Selector:   "selector1",
    PrivateKey: privateKey,
}

info, err := spool.Stat()
if err != nil {
    panic(err)
}

sigHeader, err := signer.SignReader(spool, info.Size())
if err != nil {
    panic(err)
}

if _, err := spool.Seek(0, io.SeekStart); err != nil {
    panic(err)
}
signedMessage := mail.NewHeaderPrependedReader(sigHeader, spool)
_ = signedMessage // Pass this reader to client.SendRaw.

results, err := (&dkim.Verifier{Resolver: resolver}).VerifyReader(ctx, spool)
if err != nil {
    panic(err)
}

for _, r := range results {
    if r.Status == dkim.StatusPass {
        // Verified signature.
    }
}
```

The reader must contain the complete RFC 5322 message and implement
`io.ReaderAt`; an `*os.File` spool is suitable. Signing returns a complete
`DKIM-Signature` header line. Seek the spool before forwarding because ordinary
reads use its current offset.
