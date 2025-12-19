package arc

import (
	"context"
	"crypto"

	"github.com/synqronlabs/raven"
	ravendns "github.com/synqronlabs/raven/dns"
)

// SignMail adds ARC headers to a mail message (sealing it).
// This is a convenience function for sealing mail objects.
//
// Parameters:
//   - mail: The mail message to seal
//   - sealer: The sealer configuration
//   - authServID: The authentication service identifier (your domain)
//   - authResults: The authentication results string (from SPF, DKIM, DMARC)
//   - chainValidation: The status of any existing ARC chain
//
// The function will prepend the three ARC headers to the message:
// ARC-Seal, ARC-Message-Signature, and ARC-Authentication-Results.
func SignMail(mail *raven.Mail, sealer *Sealer, authServID, authResults string, chainValidation ChainValidationStatus) error {
	// Build raw message
	rawMessage := mail.Content.ToRaw()

	// Seal the message
	result, err := sealer.Seal(rawMessage, authServID, authResults, chainValidation)
	if err != nil {
		return err
	}

	// Add the ARC headers at the top (in correct order)
	// Order: ARC-Seal, ARC-Message-Signature, ARC-Authentication-Results
	newHeaders := raven.Headers{
		{
			Name:  "ARC-Seal",
			Value: extractValue(result.Seal),
		},
		{
			Name:  "ARC-Message-Signature",
			Value: extractValue(result.MessageSignature),
		},
		{
			Name:  "ARC-Authentication-Results",
			Value: extractValue(result.AuthenticationResults),
		},
	}

	mail.Content.Headers = append(newHeaders, mail.Content.Headers...)

	return nil
}

// QuickSeal is a simplified sealing function for common use cases.
func QuickSeal(mail *raven.Mail, domain, selector string, privateKey crypto.Signer, authServID, authResults string, chainValidation ChainValidationStatus) error {
	sealer := &Sealer{
		Domain:                 domain,
		Selector:               selector,
		PrivateKey:             privateKey,
		Headers:                DefaultSignedHeaders,
		HeaderCanonicalization: CanonRelaxed,
		BodyCanonicalization:   CanonRelaxed,
	}
	return SignMail(mail, sealer, authServID, authResults, chainValidation)
}

// VerifyMailContext verifies ARC chain in a mail message.
// Returns the verification result.
func VerifyMailContext(ctx context.Context, mail *raven.Mail, resolver ravendns.Resolver) (*Result, error) {
	rawMessage := mail.Content.ToRaw()
	verifier := &Verifier{Resolver: resolver}
	return verifier.Verify(ctx, rawMessage)
}

// extractValue extracts the header value (after "HeaderName: ").
func extractValue(header string) string {
	// Find the first colon
	for i := 0; i < len(header); i++ {
		if header[i] == ':' {
			// Return everything after ": "
			value := header[i+1:]
			if len(value) > 0 && value[0] == ' ' {
				value = value[1:]
			}
			return value
		}
	}
	return header
}

// GetARCChainStatus determines the validation status for sealing based on verification results.
// This is useful when an intermediary needs to add its own ARC set.
//
// Usage:
//
//	result, err := VerifyMailContext(ctx, mail, resolver)
//	chainStatus := GetARCChainStatus(result)
//	err = SignMail(mail, sealer, authServID, authResults, chainStatus)
func GetARCChainStatus(result *Result) ChainValidationStatus {
	if result == nil || result.Status == StatusNone {
		return ChainValidationNone
	}
	if result.Status == StatusPass {
		return ChainValidationPass
	}
	return ChainValidationFail
}

// EvaluateARCForDMARC helps DMARC evaluation by providing ARC chain information.
// This can be used to override DMARC failures when a trusted ARC chain exists.
//
// Parameters:
//   - result: The ARC verification result
//   - trustedDomains: List of domains whose ARC seals are trusted
//
// Returns:
//   - trusted: Whether the ARC chain was sealed by a trusted domain
//   - oldestTrustedPass: The oldest instance where a trusted domain passed ARC
func EvaluateARCForDMARC(result *Result, trustedDomains []string) (trusted bool, oldestTrustedPass int) {
	if result == nil || result.Status != StatusPass {
		return false, 0
	}

	trustedMap := make(map[string]bool)
	for _, d := range trustedDomains {
		trustedMap[d] = true
	}

	for _, set := range result.Sets {
		if set.Seal != nil && trustedMap[set.Seal.Domain] {
			if oldestTrustedPass == 0 {
				oldestTrustedPass = set.Instance
			}
			trusted = true
		}
	}

	return trusted, oldestTrustedPass
}
