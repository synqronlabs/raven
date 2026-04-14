# dns

Package `dns` provides DNS lookup utilities used by authentication packages.

## Import

```go
import "github.com/synqronlabs/raven/dns"
```

## What It Does

- Resolves TXT, CNAME, MX, A/AAAA, and PTR data through a common interface.
- When `DNSSEC` is enabled, trusts AD and RFC 8914 EDE status from a validating recursive resolver such as Unbound.
- Provides typed error helpers for timeout/not-found/temporary cases.
- Provides domain and SMTP hostname validation helpers.

The package does not perform local DNSSEC chain validation. It is intended to be used with a validating upstream resolver, typically on `127.0.0.1:53`.

## Key API

- `NewResolver(config)`
- `NewStdResolver()`
- `Resolver` interface and `Result[T]`
- `LookupTXT`, `LookupCNAME`, `LookupIP`, `LookupMX`, `LookupAddr`
- `IsNotFound(err)`, `IsTimeout(err)`, `IsTemporary(err)`
- `IsValidDomain(domain)`
- `IsValidSMTPHostname(hostname)`

## Example

```go
resolver := dns.NewResolver(dns.ResolverConfig{
    Nameservers: []string{"127.0.0.1:53"},
    DNSSEC:      true,
})

res, err := resolver.LookupTXT(ctx, "_dmarc.example.com")
if err != nil {
    panic(err)
}

_ = res.Records
_ = res.Authentic
```
