# dmarc

Package `dmarc` implements DMARC policy lookup and alignment evaluation (RFC 7489).

## Import

```go
import "github.com/synqronlabs/raven/dmarc"
```

## What It Does

- Looks up DMARC records (`_dmarc.<domain>` with org-domain fallback).
- Checks SPF and DKIM alignment against the visible From domain.
- Produces policy decisions (`none`, `quarantine`, `reject`) and status details.

## Key API

- `Lookup(ctx, resolver, domain)`
- `Verify(ctx, resolver, args, applyRandomPercentage)`
- `ExtractFromDomain(fromHeader)`
- `OrganizationalDomain(...)`, `DomainsAligned(...)`

## Example

```go
lookup, err := dmarc.Lookup(ctx, resolver, "example.com")
if err != nil {
    panic(err)
}

_ = lookup.Status
_ = lookup.Domain
_ = lookup.Record
_ = lookup.Authentic

useResult, result := dmarc.Verify(ctx, resolver, dmarc.VerifyArgs{
    FromDomain:  fromDomain,
    SPFResult:   spfResult,
    SPFDomain:   spfDomain,
    DKIMResults: dkimResults,
}, true)

if useResult && result.Reject {
    // Apply DMARC reject policy.
}
```

Parse the visible `From` header once and pass its domain explicitly. SPF must be
evaluated against the SMTP identity before DATA; DKIM results come from the
complete RFC 5322 message. Set `applyRandomPercentage` to `true` in normal mail
processing so the record's `pct` policy is honored.
