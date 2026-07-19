package client

import (
	"bytes"
	"io"
	"testing"

	ravenmail "github.com/synqronlabs/raven/mail"
)

func BenchmarkNewMailContentReader1MiB(b *testing.B) {
	content := ravenmail.Content{
		Headers: ravenmail.Headers{
			{Name: "From", Value: "sender@example.com"},
			{Name: "To", Value: "recipient@example.com"},
			{Name: "Subject", Value: "large message"},
		},
		Body: bytes.Repeat([]byte("x"), 1<<20),
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(content.Body)))
	for b.Loop() {
		reader, _ := newMailContentReader(&content)
		if _, err := io.Copy(io.Discard, reader); err != nil {
			b.Fatal(err)
		}
	}
}
