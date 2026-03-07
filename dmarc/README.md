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
- `VerifyMail(...)`, `VerifyMailObject(...)`
- `OrganizationalDomain(...)`, `DomainsAligned(...)`

## Example

```go
status, domain, record, _, authentic, err := dmarc.Lookup(ctx, resolver, "example.com")
if err != nil {
    panic(err)
}

_ = status
_ = domain
_ = record
_ = authentic

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
