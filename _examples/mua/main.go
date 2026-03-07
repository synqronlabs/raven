// Command mua demonstrates a Mail User Agent (MUA) that composes a message and
// submits it to a Mail Submission Agent (MSA) over port 587 with STARTTLS and
// authentication.
//
// This is the most common pattern for transactional or end-user mail sending.
//
// Usage:
//
//	go run . -host smtp.example.com -user alice@example.com -pass secret \
//	         -from alice@example.com -to bob@example.net -subject "Hello"
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/synqronlabs/raven/client"
	"github.com/synqronlabs/raven/mail"
)

func main() {
	host := flag.String("host", "localhost", "SMTP submission host")
	port := flag.Int("port", 587, "SMTP submission port")
	user := flag.String("user", "", "AUTH username")
	pass := flag.String("pass", "", "AUTH password")
	from := flag.String("from", "", "Sender address")
	to := flag.String("to", "", "Recipient address")
	subject := flag.String("subject", "Test from Raven MUA", "Subject line")
	body := flag.String("body", "Hello! This message was sent using the Raven MUA example.", "Message body")
	flag.Parse()

	if *from == "" || *to == "" {
		fmt.Fprintln(os.Stderr, "usage: mua -from sender@example.com -to recipient@example.net")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// 1. Build the message with the fluent MailBuilder API.
	msg, err := mail.NewMailBuilder().
		From(*from).
		To(*to).
		Subject(*subject).
		TextBody(*body).
		Build()
	if err != nil {
		log.Fatalf("building message: %v", err)
	}

	// 2. Configure the Dialer for submission (port 587 + STARTTLS).
	dialer := client.NewDialer(*host, *port)
	dialer.StartTLS = true

	if *user != "" {
		dialer.Auth = &client.ClientAuth{
			Username: *user,
			Password: *pass,
		}
	}

	// 3. DialAndSend connects, negotiates TLS, authenticates, sends, and quits.
	result, err := dialer.DialAndSend(msg)
	if err != nil {
		log.Fatalf("sending message: %v", err)
	}

	fmt.Printf("Message sent successfully: %v\n", result.Success)
	if result.MessageID != "" {
		fmt.Printf("Server message ID: %s\n", result.MessageID)
	}

	for _, r := range result.RecipientResults {
		status := "accepted"
		if !r.Accepted {
			status = fmt.Sprintf("rejected: %v", r.Error)
		}
		fmt.Printf("  %s → %s\n", r.Address, status)
	}
}
