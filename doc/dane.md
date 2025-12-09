# DANE Support

This document explains DANE (DNS-Based Authentication of Named Entities) support in Raven and how to configure your SMTP server for DANE compatibility.

## What is DANE?

DANE (RFC 7672) is a protocol that uses DNSSEC and TLSA DNS records to authenticate SMTP servers. It provides:

- **Downgrade resistance**: Prevents MITM attacks from disabling TLS
- **CA independence**: Server authentication without relying on certificate authorities
- **Secure server identity**: Cryptographic binding of certificates to DNS names

## DANE Architecture

DANE is primarily a **client-side protocol**. When an MTA sends email:

1. The sending MTA looks up MX records for the destination domain
2. For each MX host, it queries for TLSA records via DNSSEC
3. If valid TLSA records exist, the MTA requires TLS and verifies the server certificate against the TLSA data
4. If verification fails, delivery is delayed (not downgraded to cleartext)

```
┌─────────────────┐                      ┌─────────────────┐
│  Sending MTA    │                      │  Receiving MTA  │
│  (DANE Client)  │                      │  (Your Server)  │
└────────┬────────┘                      └────────┬────────┘
         │                                        │
         │  1. DNS: MX lookup                     │
         │────────────────────────────►           │
         │                                        │
         │  2. DNS: TLSA lookup (DNSSEC)          │
         │────────────────────────────►           │
         │                                        │
         │  3. Connect with TLS                   │
         │───────────────────────────────────────►│
         │                                        │
         │  4. Verify certificate against TLSA   │
         │◄ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┤
         │                                        │
```

## Server-Side Requirements

For your Raven SMTP server to be DANE-compatible, you need:

### 1. TLS Configuration

Configure TLS in your server:

```go
cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
if err != nil {
    log.Fatal(err)
}

config := raven.DefaultServerConfig()
config.Hostname = "mail.example.com"
config.TLSConfig = &tls.Config{
    Certificates: []tls.Certificate{cert},
    MinVersion:   tls.VersionTLS12,
}
```

### 2. DNSSEC-Signed Zone

Your domain's DNS zone must be signed with DNSSEC. This is typically configured at your DNS provider or registrar.

### 3. TLSA Records

Publish TLSA records in DNS that match your server's certificate. TLSA records are published at:

```
_25._tcp.mail.example.com. IN TLSA <usage> <selector> <matching-type> <certificate-data>
```

## TLSA Record Types

### Certificate Usage Values

| Value | Name | Description |
|-------|------|-------------|
| 0 | PKIX-TA | CA constraint (requires valid CA chain) |
| 1 | PKIX-EE | End entity constraint (requires valid CA chain) |
| 2 | DANE-TA | Trust anchor assertion (CA cert, no PKI validation) |
| 3 | DANE-EE | End entity assertion (leaf cert, no PKI validation) |

**Recommended**: Use `DANE-EE (3)` for simplicity—it authenticates the server certificate directly without requiring a CA chain.

### Selector Values

| Value | Name | Description |
|-------|------|-------------|
| 0 | Full | Match full certificate |
| 1 | SPKI | Match SubjectPublicKeyInfo (public key only) |

**Recommended**: Use `SPKI (1)` so you can renew certificates without updating TLSA records (as long as you keep the same key).

### Matching Type Values

| Value | Name | Description |
|-------|------|-------------|
| 0 | Full | No hash, use full data |
| 1 | SHA-256 | SHA-256 hash |
| 2 | SHA-512 | SHA-512 hash |

**Recommended**: Use `SHA-256 (1)` for good security and compatibility.

## Generating TLSA Records

### Using OpenSSL

Generate a DANE-EE TLSA record (usage=3, selector=1, matching=1):

```bash
# Extract the SPKI and compute SHA-256 hash
openssl x509 -in server.crt -noout -pubkey | \
    openssl pkey -pubin -outform DER | \
    openssl dgst -sha256 -binary | \
    xxd -p -c 256

# Output example: 8d02536c887482bc...
```

Then create the DNS record:

```
_25._tcp.mail.example.com. 3600 IN TLSA 3 1 1 8d02536c887482bc...
```

### Using `tlsa` Command (from hash-slinger)

```bash
tlsa --create --certificate server.crt --selector 1 --mtype 1 mail.example.com
```

### Using Online Tools

Tools like [https://www.huque.com/bin/gen_tlsa](https://www.huque.com/bin/gen_tlsa) can generate TLSA records from your certificate.

## Complete DANE Setup Example

### Step 1: Generate Keys and Certificate

```bash
# Generate private key
openssl genrsa -out server.key 2048

# Generate CSR
openssl req -new -key server.key -out server.csr \
    -subj "/CN=mail.example.com"

# Generate self-signed certificate (or use a CA)
openssl x509 -req -days 365 -in server.csr \
    -signkey server.key -out server.crt
```

### Step 2: Configure Raven Server

```go
package main

import (
    "crypto/tls"
    "log"

    "github.com/synqronlabs/raven"
)

func main() {
    cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
    if err != nil {
        log.Fatal(err)
    }

    config := raven.DefaultServerConfig()
    config.Hostname = "mail.example.com"
    config.Addr = ":25"
    config.TLSConfig = &tls.Config{
        Certificates: []tls.Certificate{cert},
        MinVersion:   tls.VersionTLS12,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        },
    }

    server, err := raven.NewServer(config)
    if err != nil {
        log.Fatal(err)
    }

    // Set up signal handling for graceful shutdown
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

    // Run server in a goroutine
    go func() {
        log.Println("SMTP server listening on :25")
        if err := server.ListenAndServe(); err != raven.ErrServerClosed {
            log.Fatal(err)
        }
    }()

    // Wait for shutdown signal
    <-sigChan
    log.Println("Shutting down...")

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    server.Shutdown(ctx)
}
```

### Step 3: Generate TLSA Record

```bash
# Generate TLSA record data
TLSA_DATA=$(openssl x509 -in server.crt -noout -pubkey | \
    openssl pkey -pubin -outform DER | \
    openssl dgst -sha256 -binary | \
    xxd -p -c 256)

echo "_25._tcp.mail.example.com. 3600 IN TLSA 3 1 1 $TLSA_DATA"
```

### Step 4: Configure DNS

Add to your DNS zone (example for BIND):

```
; Enable DNSSEC for your zone first!

; MX record
example.com.                3600 IN MX 10 mail.example.com.

; A record for mail server  
mail.example.com.           3600 IN A 192.0.2.1

; TLSA record for DANE
_25._tcp.mail.example.com.  3600 IN TLSA 3 1 1 8d02536c887482bc34ff54a973d...
```

### Step 5: Sign Your Zone

Enable DNSSEC signing for your zone through your DNS provider.

## Verifying DANE Configuration

### Using `dig`

```bash
# Check TLSA record exists
dig +short TLSA _25._tcp.mail.example.com

# Check DNSSEC validation
dig +dnssec TLSA _25._tcp.mail.example.com
```

### Using Online Validators

- [DANE SMTP Validator](https://dane.sys4.de/)
- [Internet.nl](https://internet.nl/)
- [Hardenize](https://www.hardenize.com/)

### Using `openssl s_client`

```bash
# Connect and check certificate
openssl s_client -starttls smtp -connect mail.example.com:25 \
    -dane_tlsa_domain mail.example.com \
    -dane_tlsa_rrdata "3 1 1 8d02536c887482bc..."
```

## Certificate Renewal with DANE

When renewing certificates:

### If Using Selector 1 (SPKI) - Recommended

If you keep the same private key, no TLSA update is needed:

```bash
# Renew with same key
openssl x509 -req -days 365 -in server.csr \
    -signkey server.key -out server.crt
```

### If Changing Keys

1. Publish new TLSA record first (pre-publish)
2. Wait for DNS propagation (> TTL)
3. Deploy new certificate
4. Remove old TLSA record after old certificate expires

```bash
# Pre-publish timeline:
# Day 0: Add new TLSA record alongside existing
# Day 1: Wait for DNS propagation (TTL + buffer)
# Day 2: Deploy new certificate
# Day 3: Remove old TLSA record
```

## Monitoring DANE

Monitor your DANE setup to ensure continued deliverability:

1. **TLSA record presence**: Ensure records exist and are valid
2. **DNSSEC chain**: Verify the full DNSSEC chain is valid
3. **Certificate expiry**: Alert before certificate expires
4. **Certificate/TLSA match**: Verify certificate matches TLSA record

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| TLSA lookup fails | DNSSEC not configured | Enable DNSSEC for zone |
| Certificate mismatch | TLSA record outdated | Regenerate TLSA record |
| Connection refused | TLS not configured | Enable TLS in server |
| Insecure TLSA | Parent zone not signed | Sign parent zone or use different registrar |

### Debug Checklist

1. ✅ TLS configured in server
2. ✅ STARTTLS offered in EHLO response
3. ✅ Zone signed with DNSSEC
4. ✅ TLSA record published
5. ✅ TLSA matches certificate
6. ✅ Full DNSSEC chain validates

## DANE for Submission (Port 587)

For submission servers, publish TLSA records for port 587:

```
_587._tcp.mail.example.com. 3600 IN TLSA 3 1 1 8d02536c887482bc...
```

## DANE for Implicit TLS (Port 465)

For SMTPS servers, publish TLSA records for port 465:

```
_465._tcp.mail.example.com. 3600 IN TLSA 3 1 1 8d02536c887482bc...
```

## References

- [RFC 7672](https://tools.ietf.org/html/rfc7672) - SMTP Security via Opportunistic DANE TLS
- [RFC 6698](https://tools.ietf.org/html/rfc6698) - The DNS-Based Authentication of Named Entities (DANE)
- [RFC 7671](https://tools.ietf.org/html/rfc7671) - The DNS-Based Authentication of Named Entities (DANE) Protocol: Updates and Operational Guidance

## See Also

- [TLS & Authentication](tls-and-auth.md) - TLS configuration guide
- [Configuration](configuration.md) - Server configuration reference
