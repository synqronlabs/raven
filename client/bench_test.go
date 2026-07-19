package client

import (
	"bufio"
	"bytes"
	"io"
	"testing"

	ravenmail "github.com/synqronlabs/raven/mail"
)

type benchmarkResponseReader struct{}

func (benchmarkResponseReader) Read(p []byte) (int, error) {
	return copy(p, "250 2.0.0 OK\r\n"), nil
}

func benchmarkTransferData(size int) []byte {
	pattern := []byte("line content for SMTP transfer\r\n.dot-prefixed content\r\n")
	data := make([]byte, 0, size)
	for len(data)+len(pattern) <= size {
		data = append(data, pattern...)
	}
	data = append(data, bytes.Repeat([]byte{'x'}, size-len(data))...)
	return data
}

func benchmarkDisplaySMTPDATASend(b *testing.B, size int) {
	data := benchmarkTransferData(size)
	reader := bytes.NewReader(data)
	client := &Client{writer: bufio.NewWriter(io.Discard)}

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for b.Loop() {
		reader.Reset(data)
		if err := client.streamWithDotStuffing(reader); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDisplaySMTPDATASend1MiB(b *testing.B) {
	benchmarkDisplaySMTPDATASend(b, 1<<20)
}

func BenchmarkDisplaySMTPDATASend16MiB(b *testing.B) {
	benchmarkDisplaySMTPDATASend(b, 16<<20)
}

func BenchmarkScaleSMTPDATASend1MiB(b *testing.B) {
	data := benchmarkTransferData(1 << 20)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		reader := bytes.NewReader(data)
		client := &Client{writer: bufio.NewWriter(io.Discard)}
		for pb.Next() {
			reader.Reset(data)
			if err := client.streamWithDotStuffing(reader); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func benchmarkDisplaySMTPBDATSend(b *testing.B, size int) {
	data := benchmarkTransferData(size)
	reader := bytes.NewReader(data)
	client := &Client{
		config: &ClientConfig{},
		reader: bufio.NewReader(benchmarkResponseReader{}),
		writer: bufio.NewWriter(io.Discard),
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for b.Loop() {
		reader.Reset(data)
		if err := client.sendStreamWithBDAT(reader, 64*1024); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDisplaySMTPBDATSend1MiB(b *testing.B) {
	benchmarkDisplaySMTPBDATSend(b, 1<<20)
}

func BenchmarkDisplaySMTPBDATSend16MiB(b *testing.B) {
	benchmarkDisplaySMTPBDATSend(b, 16<<20)
}

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
