package dkim

import (
	"context"
	"crypto"

	"github.com/synqronlabs/raven"
	ravendns "github.com/synqronlabs/raven/dns"
)

// SignMail signs a mail message and adds the DKIM-Signature header.
// This is a convenience function for signing mail objects.
func SignMail(mail *raven.Mail, signer *Signer) error {
	// Build raw message
	rawMessage := mail.Content.ToRaw()

	// Sign the message
	sigHeader, err := signer.Sign(rawMessage)
	if err != nil {
		return err
	}

	// Add the signature header at the top
	mail.Content.Headers = append(raven.Headers{{
		Name:  "DKIM-Signature",
		Value: sigHeader[len("DKIM-Signature: ") : len(sigHeader)-2], // Remove header name and trailing CRLF
	}}, mail.Content.Headers...)

	return nil
}

// SignMailMultiple signs a mail message with multiple signers.
func SignMailMultiple(mail *raven.Mail, signers []Signer) error {
	for i := range signers {
		if err := SignMail(mail, &signers[i]); err != nil {
			return err
		}
	}
	return nil
}

// QuickSign is a simplified signing function for common use cases.
func QuickSign(mail *raven.Mail, domain, selector string, privateKey crypto.Signer) error {
	signer := &Signer{
		Domain:                 domain,
		Selector:               selector,
		PrivateKey:             privateKey,
		Headers:                DefaultSignedHeaders,
		HeaderCanonicalization: CanonRelaxed,
		BodyCanonicalization:   CanonRelaxed,
		OversignHeaders:        true,
	}
	return SignMail(mail, signer)
}

// VerifyMailContext verifies DKIM signatures in a mail message.
// Returns verification results for each signature found.
func VerifyMailContext(ctx context.Context, mail *raven.Mail, resolver ravendns.Resolver) ([]Result, error) {
	rawMessage := mail.Content.ToRaw()
	verifier := &Verifier{Resolver: resolver}
	return verifier.Verify(ctx, rawMessage)
}
