# spf

Package `spf` implements Sender Policy Framework parsing and evaluation (RFC 7208).

## Import

```go
import "github.com/synqronlabs/raven/spf"
```

## What It Does

- Parses SPF DNS records and mechanisms.
- Evaluates sender authorization for a client IP and domain identity.
- Returns structured results suitable for policy and header generation.

## Key API

- `Lookup(ctx, resolver, domain)`
- `Verify(ctx, resolver, args)`
- `ParseRecord(...)`
- `Received.Header()`

## Example

```go
resolver := spf.NewResolver(spf.ResolverConfig{DNSSEC: true})

received, checkedDomain, explanation, authentic, err := spf.Verify(ctx, resolver, spf.Args{
    RemoteIP:       remoteIP,
    MailFromDomain: "example.com",
    HelloDomain:    "mail.example.com",
    LocalHostname:  "mx.receiver.net",
})
if err != nil {
    panic(err)
}

_ = received.Result
_ = checkedDomain
_ = explanation
_ = authentic
```
