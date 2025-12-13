// Raven is a high-performance, RFC-compliant ESMTP library for Go.
//
// # Server
//
// Create an SMTP server using the fluent builder API:
//
//	server, err := raven.New("mail.example.com").
//	    Addr(":587").
//	    TLS(tlsConfig).
//	    Auth([]string{"PLAIN"}, authHandler).
//	    MaxMessageSize(25 * 1024 * 1024).
//	    Use(raven.SecureDefaults(logger)...).
//	    OnMessage(func(ctx *raven.Context) error {
//	        log.Printf("Received mail from %s", ctx.Mail.Envelope.From.String())
//	        return nil
//	    }).
//	    Build()
//
//	if err := server.ListenAndServe(); err != raven.ErrServerClosed {
//	    log.Fatal(err)
//	}
//
// The server handles graceful shutdown automatically on SIGINT/SIGTERM.
// Use GracefulShutdown(false) to disable this behavior.
//
// # Middleware
//
// Built-in middleware for common functionality:
//
//	server := raven.New("mail.example.com").
//	    Use(
//	        raven.Recovery(logger),           // Panic recovery
//	        raven.Logger(logger),             // Request logging
//	        raven.RateLimit(rateLimiter),     // Rate limiting
//	        raven.IPFilterMiddleware(filter), // IP filtering
//	    ).
//	    Build()
//
// # Client
//
// Send emails using the client with automatic extension negotiation:
//
//	client := raven.NewClient(&raven.ClientConfig{
//	    LocalName: "client.example.com",
//	    Auth: &raven.ClientAuth{Username: "user", Password: "pass"},
//	})
//	client.Dial("smtp.example.com:587")
//	client.Hello()
//	if client.Capabilities().TLS {
//	    client.StartTLS()
//	    client.Hello()
//	}
//	client.Auth()
//	result, err := client.Send(mail)
//	client.Quit()
//
// For simple use cases:
//
//	err := raven.QuickSend(
//	    "smtp.example.com:587",
//	    &raven.ClientAuth{Username: "user", Password: "pass"},
//	    "sender@example.com",
//	    []string{"recipient@example.com"},
//	    "Subject",
//	    "Message body",
//	)
//
// # Mail Builder
//
// Build emails:
//
//	mail, err := raven.NewMailBuilder().
//	    From("Sender <sender@example.com>").
//	    To("recipient@example.com").
//	    Subject("Hello").
//	    TextBody("Message content").
//	    Build()
//
// # Serialization
//
// JSON Serialization:
//
//	jsonData, err := mail.ToJSON()
//
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// JSON Deserialization:
//
//	mail, err := raven.FromJSON(jsonData)
//
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// MessagePack Serialization:
//
//	msgpackData, err := mail.ToMessagePack()
//
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// MessagePack Deserialization:
//
//	mail, err := raven.FromMessagePack(msgpackData)
//
//	if err != nil {
//	    log.Fatal(err)
//	}
//
// # Connection Pooling
//
// Use connection pooling for efficient bulk sending:
//
//	dialer := raven.NewDialer("smtp.example.com", 587)
//	dialer.Auth = &raven.ClientAuth{Username: "user", Password: "pass"}
//	dialer.StartTLS = true
//
//	pool := raven.NewPool(dialer, 5)
//	defer pool.Close()
//
//	for _, mail := range mails {
//	    result, err := pool.Send(mail)
//	}
//
// # SPF Validation
//
// Enable SPF (Sender Policy Framework, RFC 7208) validation for incoming mail:
//
//	server := raven.New("mail.example.com").
//	    SPF(raven.SPFActionReject, raven.SPFActionAccept).
//	    Build()
//
// Or with detailed options:
//
//	server := raven.New("mail.example.com").
//	    SPFWithOptions(&raven.SPFVerifyOptions{
//	        Enabled:        true,
//	        FailAction:     raven.SPFActionReject,
//	        SoftfailAction: raven.SPFActionAccept,
//	    }).
//	    Build()
//
// The SPF result is available in ctx.Mail.Envelope.SPFResult and a
// Received-SPF header is automatically added to the message.
//
// # DKIM Signing and Verification
//
// Sign outbound messages with DKIM (RFC 6376):
//
//	mail.SignDKIM(&raven.DKIMSignOptions{
//	    Domain:     "example.com",
//	    Selector:   "default",
//	    PrivateKey: privateKey, // *rsa.PrivateKey
//	})
//
// Verify DKIM signatures on inbound messages:
//
//	results := mail.VerifyDKIM(raven.DefaultDKIMVerifyOptions())
//	for _, result := range results {
//	    if result.Status == raven.DKIMStatusPass {
//	        // Valid signature from result.Domain
//	    }
//	}
//
// # DMARC Validation
//
// Enable DMARC (Domain-based Message Authentication, Reporting, and
// Conformance, RFC 7489) validation for incoming mail. DMARC builds on
// SPF and DKIM to provide domain-level authentication:
//
//	server := raven.New("mail.example.com").
//	    SPF(raven.SPFActionMark, raven.SPFActionAccept).
//	    DMARCWithOptions(&raven.DMARCVerifyOptions{
//	        Enabled:       true,
//	        RejectAction:  raven.DMARCActionReject,
//	        QuarantineAction: raven.DMARCActionMark,
//	    }).
//	    Build()
//
// DMARC verifies that the From header domain aligns with authenticated
// SPF and/or DKIM domains. The result is available in ctx.Mail.Envelope.DMARCResult
// and an Authentication-Results header is automatically added.
//
// # Server Capability Probing
//
// Discover what a server supports without sending mail:
//
//	caps, err := raven.Probe("smtp.example.com:25")
//	caps, err := raven.ProbeWithSTARTTLS("smtp.example.com:587")
//
// # Extensions
//
// Raven supports these SMTP extensions:
//
// Intrinsic (always enabled):
//   - ENHANCEDSTATUSCODES (RFC 2034)
//   - 8BITMIME (RFC 6152)
//   - SMTPUTF8 (RFC 6531)
//   - PIPELINING (RFC 2920)
//   - REQUIRETLS (RFC 8689) - advertised after STARTTLS
//
// Opt-in (configure to enable):
//   - STARTTLS (RFC 3207) - use .TLS(tlsConfig)
//   - AUTH (RFC 4954) - use .Auth(mechanisms, handler)
//   - SIZE (RFC 1870) - use .MaxMessageSize(size)
//   - DSN (RFC 3461) - use .Extension(raven.DSN())
//   - CHUNKING (RFC 3030) - use .Extension(raven.Chunking())
//   - SPF (RFC 7208) - use .SPF() or .SPFWithOptions()
//   - DKIM (RFC 6376) - use mail.SignDKIM() or mail.VerifyDKIM()
//   - DMARC (RFC 7489) - use .DMARCWithOptions()
package raven
