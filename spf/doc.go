// Package spf implements Sender Policy Framework (SPF) verification according to RFC 7208.
//
// SPF allows domain owners to publish a policy as a DNS TXT record describing which IP
// addresses are authorized to send email with the domain in the MAIL FROM command,
// and how to handle messages from unauthorized IPs.
//
// This package provides:
//   - Full SPF record parsing with all mechanisms and modifiers
//   - SPF evaluation with proper DNS lookup limits
//   - Macro expansion support
//   - Received-SPF header generation
//   - Middleware integration for Raven SMTP server
//
// Basic Usage:
//
//	resolver := spf.NewResolver(spf.ResolverConfig{
//	    Nameservers: []string{"8.8.8.8:53"},
//	    DNSSEC:      true,
//	})
//
//	args := spf.Args{
//	    RemoteIP:       net.ParseIP("192.0.2.1"),
//	    MailFromDomain: "example.com",
//	    MailFromLocal:  "user",
//	    HelloDomain:    "mail.example.com",
//	    LocalHostname:  "mx.example.org",
//	}
//
//	result, err := spf.Verify(ctx, resolver, args)
//	if err != nil {
//	    // Handle error
//	}
//
//	switch result.Status {
//	case spf.StatusPass:
//	    // Accept the message
//	case spf.StatusFail:
//	    // Reject the message
//	case spf.StatusSoftfail:
//	    // Mark as suspicious
//	}
//
// Middleware Usage:
//
//	server := raven.New("mx.example.com").
//	    Use(spf.Middleware(spf.MiddlewareConfig{
//	        Resolver: resolver,
//	        Policy:   spf.PolicyMark, // Add header but don't reject
//	    }))
//
// References:
//   - RFC 7208: Sender Policy Framework (SPF)
//   - RFC 4408: Sender Policy Framework (obsoleted by 7208)
package spf
