# Motivation

## Why Raven?

Modern email infrastructure relies on a stack of interrelated protocols — SMTP
for transport, SPF/DKIM/DMARC/ARC for authentication, MIME for structured
content — yet most Go libraries focus on only one slice of that stack. Building
a mail transfer agent (MTA), a submission server (MSA), or even a simple
transactional-mail client means gluing together several packages that were never
designed to work together: the DNS lookups don't share the same resolver
abstraction, authentication results can't flow naturally into DMARC evaluation,
and the message model differs between sender and receiver.

Raven addresses this by providing **a single, cohesive toolkit** that covers the
full SMTP transport and authentication pipeline within one module.

## Design Goals

### 1. Unified Message Model

A single `mail.Mail` type threads through every layer:

- **`mail.MailBuilder`** constructs the message (headers, body, MIME parts).
- **`client.Client`** reads the `Mail` envelope to drive `MAIL FROM` / `RCPT TO`
  and serialises the content for `DATA`.
- **`server.Session`** hands the received body back as an `io.Reader` that can be
  parsed into the same `Mail` structure.
- **`dkim.SignMail`**, **`dmarc.VerifyMailObject`**, and **`arc.SignMail`** operate
  directly on `*mail.Mail` objects, so there is no translation layer between
  transport and authentication.

### 2. Backend / Session Pattern

The server package borrows the widely-understood handler/middleware pattern from
HTTP and applies it to SMTP:

```
Backend.NewSession(conn) → Session
Session.Mail(from, opts)
Session.Rcpt(to, opts)
Session.Data(reader)
Session.Reset()
Session.Logout()
```

All protocol mechanics (greeting, capability negotiation, STARTTLS, AUTH, line
reading, timeouts, error codes) are handled by the framework. The implementer
only writes the **business logic**: accept or reject senders, store or relay
messages, look up credentials.

Optional interfaces (`AuthSession`, `ChunkingSession`, `VRFYSession`,
`EXPNSession`) let the backend opt into advanced features without cluttering the
base interface.

### 3. Pluggable DNS with DNSSEC Awareness

All authentication packages share a common `dns.Resolver` interface:

```go
type Resolver interface {
    LookupTXT(ctx, domain)  Result[string]
    LookupIP(ctx, domain)   Result[net.IP]
    LookupMX(ctx, domain)   Result[*net.MX]
    LookupAddr(ctx, ip)     Result[string]
}
```

`Result[T]` carries an `Authentic` flag that propagates DNSSEC validation
status, enabling consumers (SPF, DKIM, DMARC) to enforce stricter policies when
DNS answers are validated. Two implementations ship out of the box:

| Resolver        | DNSSEC | Dependency       |
|-----------------|--------|------------------|
| `DNSResolver`   | Yes    | `miekg/dns`      |
| `StdResolver`   | No     | `net` (stdlib)   |

A `MockResolver` is also provided for deterministic testing.

### 4. Full Authentication Pipeline

Raven implements the complete modern email authentication stack in a way that
lets results flow from one layer to the next:

```
Remote IP ─► SPF Verify   ─► spf.Status
                               │
Raw message ─► DKIM Verify ─►  []dkim.Result
                               │         │
              SPF + DKIM  ─────┴─────────┴─► DMARC Verify ─► dmarc.Result
                                                                    │
              Message + Auth ─────────────────────────────────► ARC Seal
```

Each layer returns typed results that are accepted directly by the next,
eliminating string-formatting hops and manual mapping.

### 5. Correctness and Safety

- Strict RFC compliance: line-length limits, required headers, CRLF
  enforcement, DNS lookup caps (10 mechanisms + 2 void lookups for SPF).
- `OversignHeaders` in DKIM signing prevents header-injection attacks (signs
  each header one more time than it appears, blocking additions).
- `server.SMTPError` with structured enhanced status codes for precise error
  signalling.
- Address validation follows RFC 5321 limits (local-part ≤ 64, domain ≤ 255,
  total ≤ 254 octets) with Punycode (IDNA) conversion.

### 6. No Framework Lock-in

Raven is a **library**, not a framework. You import the packages you need and
combine them in your own `main()`. There is no global state, no mandatory
configuration file, and no process manager. The examples in the `_examples`
directory show how to compose Raven packages into real-world architectures.
