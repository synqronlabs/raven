package dkim

import (
	"context"
	"crypto"
	"fmt"

	ravendns "github.com/synqronlabs/raven/dns"
	ravenmail "github.com/synqronlabs/raven/mail"
)

// SignMail signs a mail message and adds the DKIM-Signature header.
// This is a convenience function for signing mail objects.
func SignMail(mail *ravenmail.Mail, signer *Signer) error {
	// Build raw message
	rawMessage := mail.Content.ToRaw()

	// Sign the message
	sigHeader, err := signer.Sign(rawMessage)
	if err != nil {
		return fmt.Errorf("signing mail with DKIM: %w", err)
	}

	// Add the signature header at the top
	mail.Content.Headers = append(ravenmail.Headers{{
		Name:  "DKIM-Signature",
		Value: sigHeader[len("DKIM-Signature: ") : len(sigHeader)-2], // Remove header name and trailing CRLF
	}}, mail.Content.Headers...)

	return nil
}

// SignMailMultiple signs a mail message with multiple signers.
func SignMailMultiple(mail *ravenmail.Mail, signers []Signer) error {
	for i := range signers {
		if err := SignMail(mail, &signers[i]); err != nil {
			return fmt.Errorf("signing mail with DKIM signer %d: %w", i, err)
		}
	}
	return nil
}

// QuickSign is a simplified signing function for common use cases.
func QuickSign(mail *ravenmail.Mail, domain, selector string, privateKey crypto.Signer) error {
	signer := &Signer{
		Domain:                 domain,
		Selector:               selector,
		PrivateKey:             privateKey,
		Headers:                DefaultSignedHeaders,
		HeaderCanonicalization: CanonRelaxed,
		BodyCanonicalization:   CanonRelaxed,
		OversignHeaders:        true,
	}
	if err := SignMail(mail, signer); err != nil {
		return fmt.Errorf("quick DKIM signing: %w", err)
	}
	return nil
}

// VerifyMailContext verifies DKIM signatures in a mail message.
// Returns verification results for each signature found.
func VerifyMailContext(ctx context.Context, mail *ravenmail.Mail, resolver ravendns.Resolver) ([]Result, error) {
	rawMessage := mail.Content.ToRaw()
	verifier := &Verifier{Resolver: resolver}
	results, err := verifier.Verify(ctx, rawMessage)
	if err != nil {
		return nil, fmt.Errorf("verifying DKIM signatures for mail: %w", err)
	}
	return results, nil
}
