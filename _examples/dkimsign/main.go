// Command dkimsign demonstrates standalone DKIM signing and verification
// of messages read from stdin or a file.
//
// This is useful for testing DKIM key setups and verifying signed messages
// without a full SMTP pipeline.
//
// Usage:
//
//	# Sign a message:
//	go run . sign -domain example.com -selector sel1 -key private.pem < message.eml
//
//	# Verify a message:
//	go run . verify < signed-message.eml
package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/synqronlabs/raven/dkim"
	"github.com/synqronlabs/raven/dns"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	switch os.Args[1] {
	case "sign":
		signCmd(os.Args[2:])
	case "verify":
		verifyCmd(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: dkimsign <sign|verify> [flags]")
	fmt.Fprintln(os.Stderr, "  sign   - DKIM-sign a message from stdin")
	fmt.Fprintln(os.Stderr, "  verify - verify DKIM signatures on a message from stdin")
	os.Exit(1)
}

func signCmd(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	domain := fs.String("domain", "", "Signing domain (d= tag)")
	selector := fs.String("selector", "", "Selector (s= tag)")
	keyPath := fs.String("key", "", "Path to PEM private key (RSA or Ed25519)")
	canon := fs.String("canon", "relaxed/relaxed",
		"Canonicalization (simple/simple, relaxed/relaxed, etc.)")
	oversign := fs.Bool("oversign", true, "Oversign headers to prevent injection")
	fs.Parse(args)

	if *domain == "" || *selector == "" || *keyPath == "" {
		fmt.Fprintln(os.Stderr, "sign: -domain, -selector, and -key are required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	privKey, err := loadPrivateKey(*keyPath)
	if err != nil {
		log.Fatalf("loading key: %v", err)
	}

	message, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("reading message: %v", err)
	}

	headerCanon, bodyCanon := parseCanonicalization(*canon)

	signer := &dkim.Signer{
		Domain:                 *domain,
		Selector:               *selector,
		PrivateKey:             privKey,
		Headers:                dkim.DefaultSignedHeaders,
		HeaderCanonicalization: headerCanon,
		BodyCanonicalization:   bodyCanon,
		OversignHeaders:        *oversign,
	}

	sigHeader, err := signer.Sign(message)
	if err != nil {
		log.Fatalf("signing: %v", err)
	}

	// Output: signature header followed by original message.
	fmt.Print(sigHeader)
	os.Stdout.Write(message)
}

func verifyCmd(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	dnssec := fs.Bool("dnssec", true, "Use DNSSEC-aware resolver")
	fs.Parse(args)

	message, err := io.ReadAll(os.Stdin)
	if err != nil {
		log.Fatalf("reading message: %v", err)
	}

	resolver := dns.NewResolver(dns.ResolverConfig{
		DNSSEC:  *dnssec,
		Timeout: 5 * time.Second,
		Retries: 2,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	verifier := &dkim.Verifier{Resolver: resolver}
	results, err := verifier.Verify(ctx, message)
	if err != nil {
		log.Fatalf("verification error: %v", err)
	}

	if len(results) == 0 {
		fmt.Println("No DKIM signatures found.")
		return
	}

	for i, r := range results {
		fmt.Printf("Signature %d:\n", i+1)
		fmt.Printf("  Status: %s\n", r.Status)
		if r.Signature != nil {
			fmt.Printf("  Domain (d=): %s\n", r.Signature.Domain)
			fmt.Printf("  Selector (s=): %s\n", r.Signature.Selector)
			fmt.Printf("  Algorithm: %s\n", r.Signature.Algorithm)
		}
		if r.Record != nil {
			fmt.Printf("  Key type: %s\n", r.Record.Key)
			if r.Record.IsTesting() {
				fmt.Printf("  Warning: testing mode (t=y)\n")
			}
		}
		if r.Err != nil {
			fmt.Printf("  Error: %v\n", r.Err)
		}
	}
}

func parseCanonicalization(s string) (dkim.Canonicalization, dkim.Canonicalization) {
	header, body := dkim.CanonRelaxed, dkim.CanonRelaxed
	switch s {
	case "simple/simple":
		header, body = dkim.CanonSimple, dkim.CanonSimple
	case "relaxed/simple":
		header, body = dkim.CanonRelaxed, dkim.CanonSimple
	case "simple/relaxed":
		header, body = dkim.CanonSimple, dkim.CanonRelaxed
	}
	return header, body
}

func loadPrivateKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unsupported key type in %s", path)
}
