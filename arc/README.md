# arc

Package `arc` implements Authenticated Received Chain (ARC, RFC 8617).

## Import

```go
import "github.com/synqronlabs/raven/arc"
```

## What It Does

- Verifies existing ARC sets on a message.
- Seals a message with a new ARC set at intermediaries.
- Exposes structured verification results for policy decisions.

## Key API

- `Verifier.Verify(ctx, message)`
- `Sealer.Seal(message, authServID, authResults, chainValidation)`
- `SignMail(...)`, `QuickSeal(...)`
- `EvaluateARCForDMARC(...)`

## Example

```go
verifier := &arc.Verifier{Resolver: resolver}
result, err := verifier.Verify(ctx, rawMessage)
if err != nil {
    panic(err)
}

if result.Status == arc.StatusPass {
    // ARC chain validated.
}

sealer := &arc.Sealer{
    Domain:     "example.com",
    Selector:   "arc1",
    PrivateKey: privateKey,
}

sealResult, err := sealer.Seal(
    rawMessage,
    "mx.example.com",
    "dkim=pass header.d=example.com",
    arc.ChainValidationPass,
)
if err != nil {
    panic(err)
}

_ = sealResult.AuthenticationResults
_ = sealResult.MessageSignature
_ = sealResult.Seal
```
