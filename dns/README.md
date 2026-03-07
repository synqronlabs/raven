# dns

Package `dns` provides DNS lookup utilities used by authentication packages.

## Import

```go
import "github.com/synqronlabs/raven/dns"
```

## What It Does

- Resolves TXT, MX, A/AAAA, and PTR data through a common interface.
- Surfaces DNSSEC authenticity where supported.
- Provides typed error helpers for timeout/not-found/temporary cases.
- Provides domain and SMTP hostname validation helpers.

## Key API

- `NewResolver(config)`
- `NewStdResolver()`
- `Resolver` interface and `Result[T]`
- `IsNotFound(err)`, `IsTimeout(err)`, `IsTemporary(err)`
- `IsValidDomain(domain)`
- `IsValidSMTPHostname(hostname)`

## Example

```go
resolver := dns.NewResolver(dns.ResolverConfig{
    Nameservers: []string{"8.8.8.8:53"},
    DNSSEC:      true,
})

res, err := resolver.LookupTXT(ctx, "_dmarc.example.com")
if err != nil {
    panic(err)
}

_ = res.Records
_ = res.Authentic
```
