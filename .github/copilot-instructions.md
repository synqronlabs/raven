# Raven - ESMTP Library for Go

## Architecture Overview

Raven is an RFC-compliant ESMTP server and client library with a **handler-chain architecture** (similar to web middleware frameworks like Gin/Echo).

### Core Components

- **Server** ([server.go](../server.go)) - Fluent builder API for SMTP servers with handler chains
- **Client** ([client.go](../client.go)) - SMTP client with extension negotiation and connection pooling
- **Mail** ([mail.go](../mail.go)) - Core email structures (`Mail`, `Envelope`, `Headers`, `Content`)
- **MailBuilder** ([mail_builder.go](../mail_builder.go)) - Fluent API for constructing emails

### Email Authentication Packages

Each authentication package follows the same pattern with: types, verification, middleware integration
- `dkim/` - DKIM signing/verification (RFC 6376)
- `spf/` - SPF validation (RFC 7208)
- `dmarc/` - DMARC policy evaluation (RFC 7489)
- `arc/` - ARC chain verification/sealing (RFC 8617)
- `dns/` - DNS resolution with DNSSEC support

## Handler Chain Pattern

Handlers are `func(c *raven.Context) *raven.Response`. Return `c.Next()` to pass to next handler:

```go
server := raven.New("mail.example.com").
    OnConnect(recovery, logger, rateLimit).  // Multiple handlers chain
    OnMailFrom(validateSender).
    OnRcptTo(validateRecipient).
    OnMessage(processMessage)

func validateSender(c *raven.Context) *raven.Response {
    if blocked(c.Request.From) {
        return c.PermError("Sender blocked")  // Stop chain, return error
    }
    return c.Next()  // Continue to next handler
}
```

### Context Response Methods

- `c.Next()` - Continue chain
- `c.OK(msg)` / `c.OKf(fmt, args...)` - 250 success
- `c.TempError(msg)` - 451 temporary failure
- `c.PermError(msg)` - 550 permanent failure
- `c.Reject(msg)` - 554 transaction failed
- `c.Error(code, msg)` - Custom SMTP code

### Handler Hooks

`OnConnect`, `OnDisconnect`, `OnHelo`, `OnEhlo`, `OnMailFrom`, `OnRcptTo`, `OnData`, `OnBdat`, `OnMessage`, `OnReset`

## Code Generation

Run after modifying `Mail` or `MIMEPart` structs:
```bash
go generate ./...  # Regenerates MessagePack serialization (msgp)
```

## Testing

```bash
go test ./...                    # All tests
go test -run TestMailBuilder     # Specific test pattern
go test -race ./...              # Race detection
go test -fuzz=Fuzz ./...         # Fuzz tests (server_fuzz_test.go)
```

Test helpers in [server_test.go](../server_test.go): `newTestServer()` creates ephemeral servers for integration tests.

## Conventions

### Error Handling

- Define package-level sentinel errors: `var ErrSomething = errors.New("pkg: description")`
- Prefix errors with package name: `dkim:`, `spf:`, `arc:`, `dmarc:`
- Use `errors.Is()` for checking; wrap with `fmt.Errorf("context: %w", err)`

### SMTP Response Codes

Use constants from [response.go](../response.go): `CodeOK`, `CodeMailboxNotFound`, etc.
Use enhanced codes: `ESCSuccess`, `ESCPermFailure`, `ESCTempLocalError`

### DNS Resolution

Use `dns.Resolver` interface for testability. See [dns/mock.go](../dns/mock.go) for test mocks.

### Middleware Integration

Authentication middleware stores results in context with typed keys:
```go
// In middleware
c.Set(dkim.ContextKeyDKIMResults, results)

// In later handler
if results, ok := c.Get(dkim.ContextKeyDKIMResults); ok { ... }
```

### Middleware Order (Authentication)

**Critical**: Authentication middleware must run in this order in `OnMessage`:
1. **SPF** - Check sender IP authorization
2. **DKIM** - Verify message signatures
3. **DMARC** - Evaluate policy using SPF/DKIM results
4. **ARC** - Verify/seal chain (requires all above results)

ARC sealing reads SPF, DKIM, and DMARC results from context, so it **must** run last.

### Package Documentation

Each package has a `doc.go` with usage examples (see `dkim/`, `spf/`, `arc/`, `dmarc/`).

## Key Patterns

1. **Fluent builders** - Server, Client, MailBuilder all use method chaining returning `*Self`
2. **Status types** - Each auth package defines `Status` type (`StatusPass`, `StatusFail`, `StatusNone`, etc.)
3. **Result structs** - Verification results include: `Status`, parsed record, DNSSEC `Authentic` flag, `Err`
4. **Canonicalization** - DKIM/ARC use `simple` and `relaxed` algorithms ([dkim/canonicalize.go](../dkim/canonicalize.go))
5. **Connection pooling** - `Pool` in [client_dialer.go](../client_dialer.go) manages reusable SMTP connections with health checks via `Noop()`

## Example Reference

See [_examples/msa_server/main.go](../_examples/msa_server/main.go) for a complete Mail Submission Agent with:
- STARTTLS/implicit TLS
- AUTH with rate limiting
- Envelope validation
- Message queueing pattern
