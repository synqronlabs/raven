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

- `(*Verifier).VerifyReader(ctx, message)`
- `(*Sealer).SealReader(message, size, authServID, authResults, chainValidation)`
- `GetARCChainStatus(result)`
- `EvaluateARCForDMARC(...)`

## Example

```go
verifier := arc.Verifier{Resolver: resolver}
result, err := verifier.VerifyReader(ctx, spool)
if err != nil {
    panic(err)
}

if result.Status == arc.StatusPass {
    // ARC chain validated.
}
chainStatus := arc.GetARCChainStatus(result)

info, err := spool.Stat()
if err != nil {
    panic(err)
}

sealer := arc.Sealer{
    Domain:     "example.com",
    Selector:   "arc1",
    PrivateKey: privateKey,
}

sealResult, err := sealer.SealReader(
    spool,
    info.Size(),
    "mx.example.com",
    "dkim=pass header.d=example.com",
    chainStatus,
)
if err != nil {
    panic(err)
}

_ = sealResult.AuthenticationResults
_ = sealResult.MessageSignature
_ = sealResult.Seal

headers := sealResult.Seal + sealResult.MessageSignature + sealResult.AuthenticationResults
if _, err := spool.Seek(0, io.SeekStart); err != nil {
    panic(err)
}
sealedMessage := mail.NewHeaderPrependedReader(headers, spool)
_ = sealedMessage // Pass this reader to client.SendRaw.
```

`spool` is an `*os.File` containing the complete RFC 5322 message (another
`io.ReaderAt` can be used when its size is known). The three returned values are
complete header lines; prepend them in ARC-Seal, ARC-Message-Signature,
ARC-Authentication-Results order when forwarding.
