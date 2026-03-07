# Architecture

This document describes the package layout of Raven and how the packages relate
to each other.

## Package Map

```
github.com/synqronlabs/raven
│
├── mail/      Core message model (Mail, Envelope, Content, Headers, MailBuilder)
├── mime/      MIME parsing (multipart, encodings, content types)
├── io/        SMTP-oriented I/O helpers (line reading, ASCII checks)
├── crypto/    Crypto utilities (ULID generation for Message-ID)
│
├── dns/       DNS resolver abstraction with DNSSEC support
│
├── sasl/      SASL mechanisms (PLAIN, LOGIN) for SMTP AUTH
│
├── client/    SMTP client: Dialer → Client → Send
├── server/    SMTP server: Backend/Session pattern
│
├── spf/       SPF record parsing and verification (RFC 7208)
├── dkim/      DKIM signing and verification (RFC 6376)
├── dmarc/     DMARC policy evaluation (RFC 7489)
└── arc/       ARC chain verification and sealing (RFC 8617)
```

## Dependency Graph

Arrows point from consumer → dependency. Only intra-module dependencies are
shown; external deps (`miekg/dns`, `oklog/ulid`, `tinylib/msgp`, `x/net`) are
omitted.

```
                    ┌──────────┐
                    │   mail   │  ◄── foundation: no raven deps
                    └──┬───┬───┘
                       │   │
             ┌─────────┘   └──────────┐
             ▼                        ▼
        ┌────────┐              ┌──────────┐
        │  mime  │              │  crypto  │
        └────────┘              └──────────┘

        ┌────────┐              ┌──────────┐
        │   io   │   ◄── no deps│   dns    │  ◄── no raven deps
        └────┬───┘              └────┬─────┘
             │                       │
     ┌───────┴───────┐       ┌───────┴──┬─────────┬─────────┐
     ▼               ▼       ▼          ▼         ▼         ▼
┌────────┐    ┌──────────┐ ┌──────┐ ┌───────┐ ┌───────┐  ┌─────┐
│ client │    │  server  │ │ dkim │ │  spf  │ │ dmarc │  │ arc │
└────────┘    └──────────┘ └──┬───┘ └───┬───┘ └───┬───┘  └──┬──┘
     │             │          │         │         │         │
     └──┬──────────┘          └─────────┴─────────┴─────────┘
        ▼                         (auth packages share dns)
   ┌────────┐
   │  sasl  │
   └────────┘
```

### Layer Summary

| Layer              | Packages                        | Role                                     |
|--------------------|---------------------------------|------------------------------------------|
| **Foundation**     | `mail`, `io`, `crypto`          | Data model, low-level I/O, ID generation |
| **Content**        | `mime`                          | MIME structure parsing                   |
| **Infrastructure** | `dns`, `sasl`                   | Shared DNS + auth mechanism primitives   |
| **Transport**      | `client`, `server`              | SMTP send and receive                    |
| **Authentication** | `spf`, `dkim`, `dmarc`, `arc`   | Email authentication protocols           |

## Package Details

### mail — Message Model

The `mail` package defines the canonical representation of an email. Every other
package that touches a message depends on types from `mail`.

**Key types:**

| Type              | Purpose                                          |
|-------------------|-------------------------------------------------|
| `Mail`            | Top-level object: Envelope + Content             |
| `Envelope`        | SMTP envelope (sender, recipients, extensions)   |
| `Content`         | RFC 5322 message (headers + body)                |
| `Headers` / `Header` | Ordered header collection with accessors     |
| `MailboxAddress`  | Parsed email address (local + domain)            |
| `MailBuilder`     | Fluent API for building `Mail` objects           |

`Content.Validate()` enforces RFC 5322 rules (required headers, line lengths,
CRLF endings). `Content.ToRaw()` serialises back to wire format.

### io — Line Reading

Provides `ReadLine()` with strict CRLF enforcement and configurable length
limits — essential for SMTP protocol parsing. Also provides
`ContainsNonASCII()` for 7-bit checks.

### crypto — Identifiers

Provides `GenerateID()` for ULID-based unique identifiers used as Message‑IDs.

### dns — Resolver Abstraction

A common resolver interface shared by all authentication packages:

```go
type Resolver interface {
    LookupTXT(ctx context.Context, domain string) (Result[string], error)
    LookupIP(ctx context.Context, domain string) (Result[net.IP], error)
    LookupMX(ctx context.Context, domain string) (Result[*net.MX], error)
    LookupAddr(ctx context.Context, ip string) (Result[string], error)
}
```

`Result[T]` wraps `[]T` records + an `Authentic` boolean for DNSSEC.

Implementations:

- **`DNSResolver`** — DNSSEC-aware, uses `miekg/dns`.
- **`StdResolver`** — Standard library `net.Resolver`, no DNSSEC.
- **`MockResolver`** — Deterministic testing (set records in maps, configure
  failures, authentic/inauthentic lists).

Helper functions: `IsValidDomain()`, `IsValidSMTPHostname()`,
`IsNotFound()`, `IsTimeout()`, `IsTemporary()`, `IsServFail()`.

### sasl — SMTP AUTH Mechanisms

Client- and server-side SASL:

- `Mechanism` interface — client side (`Start`, `Next`, `Credentials`).
- `Server` interface — server side (`Next` returns challenge/done).
- `NewPlain()` / `NewLogin()` — the two mechanisms SMTP commonly uses.
- `Credentials` — result of successful authentication (AuthorizationID,
  AuthenticationID, Password).

### client — SMTP Client

Two-level API:

1. **`Dialer`** — high-level, configures connection once:
   - `Dial()` → `*Client` (handles EHLO, STARTTLS, AUTH automatically).
   - `DialAndSend(mail)` — one-shot: connect, send, quit.
   - `DialAndSendMultiple(mails)` — batch reuse.

2. **`Client`** — low-level, protocol commands:
   - `Hello()`, `StartTLS()`, `Auth()`, `Send()`, `Quit()`.
   - `HasExtension()` for capability probing.
   - `Verify()`, `Expand()` for VRFY/EXPN.

`SendResult` contains per-recipient acceptance and the server-assigned message
ID. `ServerCapabilities` gives EHLO extension information.

### server — SMTP Server

**Backend / Session pattern:**

```go
type Backend interface {
    NewSession(c *Conn) (Session, error)
}

type Session interface {
    Mail(from string, opts *MailOptions) error
    Rcpt(to string, opts *RcptOptions) error
    Data(r io.Reader) error
    Reset()
    Logout() error
}
```

The `Server` handles all protocol details: greeting, EHLO, STARTTLS, AUTH, DATA,
BDAT, RSET, QUIT, NOOP, timeouts, connection tracking, and graceful shutdown
via context cancellation.

Optional interfaces extend the base:

| Interface          | Enables          | Trigger      |
|--------------------|------------------|--------------|
| `AuthSession`      | SMTP AUTH        | AUTH command  |
| `ChunkingSession`  | BDAT (RFC 3030)  | BDAT command  |
| `VRFYSession`      | VRFY             | VRFY command  |
| `EXPNSession`      | EXPN             | EXPN command  |

`ServerConfig` controls the domain, listen address, TLS, timeouts, size limits,
and extension flags (SMTPUTF8, DSN, REQUIRETLS, CHUNKING, BINARYMIME).

### spf — Sender Policy Framework

`Verify(ctx, resolver, args)` is the main entry point. It:

1. Looks up the SPF TXT record for the `MailFromDomain`.
2. Parses mechanisms (`include`, `a`, `mx`, `ip4`, `ip6`, `ptr`, `exists`,
   `redirect`, `exp`).
3. Evaluates mechanisms against `RemoteIP` with DNS lookup caps (10 mechanisms,
   2 void lookups).
4. Returns `Status` (pass, fail, softfail, neutral, temperror, permerror, none).

SPF has its own `Resolver` interface (slightly different from `dns.Resolver`)
and ships `NewResolver()` / `NewResolverWithDefaults()`.

### dkim — DomainKeys Identified Mail

**Signing** (`Signer.Sign` / `SignMail` / `QuickSign`):

- Configure domain, selector, private key (RSA or Ed25519).
- Supports relaxed / simple canonicalization for headers and body.
- `OversignHeaders` prevents header-injection attacks.
- Returns a `DKIM-Signature` header string.

**Verification** (`Verifier.Verify` / `VerifyMailContext`):

- Extracts `DKIM-Signature` headers from the message.
- Looks up the selector record via DNS.
- Validates key size, hash algorithm, service flags.
- Returns `[]Result` with `Status` per signature (Pass, Fail, Policy, Neutral,
  Temperror, Permerror).

### dmarc — Domain-based Message Authentication

`Verify(ctx, resolver, args, applyPct)` evaluates:

1. Extracts the `From` domain.
2. `Lookup()` queries `_dmarc.<domain>` (with organizational domain fallback via
   the public suffix list).
3. Checks **SPF alignment** (MailFrom domain ↔ From domain).
4. Checks **DKIM alignment** (at least one passing signature domain ↔ From
   domain).
5. Returns `Result` with `Reject` boolean and alignment details.

Alignment can be **strict** (exact match) or **relaxed** (organizational domain
match). `OrganizationalDomain()` maps subdomains to their registered domain
using the public suffix list.

### arc — Authenticated Received Chain

**Verification** (`Verifier.Verify` / `VerifyMailContext`):

- Parses ARC header sets (AAR + AMS + Seal per instance).
- Validates sequential numbering (1 … n, max 50).
- Verifies each ARC-Message-Signature (DKIM-like) and ARC-Seal.
- Returns `Status` (None, Pass, Fail) with `OldestPass` instance.

**Sealing** (`Sealer.Seal` / `SignMail` / `QuickSeal`):

- Creates a new ARC instance with AAR, AMS, and Seal headers.
- Accepts `ChainValidationStatus` from a prior `Verify()` round.
- `EvaluateARCForDMARC()` enables DMARC policy overrides when a trusted ARC
  chain exists.

## Typical Data Flow

### Outbound (MSA / Transactional Sender)

```
MailBuilder  →  mail.Mail
                  │
            dkim.SignMail(mail, signer)
                  │
            client.Dialer.DialAndSend(mail)
                  │
            SMTP session ──► remote MX
```

### Inbound (MX Receiver)

```
server.ListenAndServe
    │
    ├── NewSession(conn)
    │       │
    │   conn.RemoteAddr() ──► spf.Verify()
    │       │
    │   Session.Data(reader)
    │       │   parse message
    │       │   dkim.Verify()
    │       │   dmarc.Verify()
    │       │   arc.Verify() (optional)
    │       │
    │       └── accept / reject / quarantine
    │
    └── Session.Logout()
```
