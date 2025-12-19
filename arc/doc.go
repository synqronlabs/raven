// Package arc implements Authenticated Received Chain (ARC) per RFC 8617.
//
// ARC provides a way to preserve email authentication results across
// intermediaries that may modify messages (such as mailing lists). When
// a message passes through an intermediary, ARC creates a chain of custody
// that allows receivers to validate that the message was authenticated
// when received by each intermediary.
//
// ARC consists of three header types:
//   - ARC-Authentication-Results: Contains authentication results from the intermediary
//   - ARC-Message-Signature: A DKIM-like signature over the message
//   - ARC-Seal: A signature that seals the entire ARC chain
//
// # Basic Usage
//
// Verifying an ARC chain:
//
//	verifier := arc.Verifier{
//	    Resolver: resolver,
//	}
//	result, err := verifier.Verify(ctx, message)
//	if result.Status == arc.StatusPass {
//	    // ARC chain is valid
//	}
//
// Sealing a message (as an intermediary):
//
//	sealer := arc.Sealer{
//	    Domain:     "example.com",
//	    Selector:   "arc1",
//	    PrivateKey: privateKey,
//	}
//	headers, err := sealer.Seal(message, authResults, arc.ChainValidationPass)
//
// # Chain Validation States
//
// RFC 8617 defines the following chain validation states:
//   - none: No ARC headers present
//   - pass: All ARC sets validated successfully
//   - fail: ARC validation failed
//
// # Integration with DMARC
//
// ARC results can be used by DMARC to override authentication failures
// when a trusted ARC chain indicates the message was originally authenticated.
// This is particularly useful for mailing lists that modify messages.
//
// # References
//
//   - RFC 8617: The Authenticated Received Chain (ARC) Protocol
//   - RFC 6376: DomainKeys Identified Mail (DKIM) Signatures
//   - RFC 8601: Message Header Field for Indicating Message Authentication Status
package arc
