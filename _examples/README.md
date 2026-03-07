# Examples

Runnable example programs demonstrating common Raven usage patterns.

Each directory contains a standalone `main.go` that can be run with `go run .`.

| Example                          | Role                  | Description                                                                                     |
|----------------------------------|-----------------------|-------------------------------------------------------------------------------------------------|
| [`mua/`](mua/)                   | Mail User Agent       | Compose a message with `MailBuilder` and submit via port 587 with STARTTLS + AUTH               |
| [`msa/`](msa/)                   | Mail Submission Agent | Accept authenticated submissions, DKIM-sign, and relay to downstream MX                        |
| [`mx/`](mx/)                     | MX / Mail Delivery    | Receive inbound mail on port 25, run SPF → DKIM → DMARC → ARC pipeline, accept or reject       |
| [`dkimsign/`](dkimsign/)         | DKIM Tool             | Standalone DKIM signing and verification of raw messages (stdin)                                |

## How the examples relate

```
┌─────────────┐    port 587     ┌─────────────┐    port 25      ┌─────────────┐
│  MUA client │ ──────────────► │  MSA server │ ──────────────► │  MX server  │
│  (mua/)     │   STARTTLS+AUTH │  (msa/)     │   DKIM-signed   │  (mx/)      │
└─────────────┘                 └─────────────┘                 └─────────────┘
                                  DKIM signs ↑                   SPF + DKIM +
                                  the message                    DMARC + ARC ↑
```

## Running locally

Start the MX server in one terminal:

```bash
cd mx && go run . -addr :2525
```

Start the MSA in another terminal:

```bash
cd msa && go run . -addr :5870 -relay localhost -relay-port 2525
```

Send a message with the MUA:

```bash
cd mua && go run . -host localhost -port 5870 \
    -from alice@example.com -to bob@example.com \
    -subject "Hello" -body "Test message"
```

Watch the MSA and MX logs for the authentication pipeline output.

## DKIM signing/verification tool

Sign a raw `.eml` file:

```bash
cd dkimsign && go run . sign -domain example.com -selector sel1 -key /path/to/private.pem < message.eml > signed.eml
```

Verify the signed output:

```bash
cd dkimsign && go run . verify < signed.eml
```
