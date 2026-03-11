package io

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

var (
	benchReadLineFastInput = []byte("MAIL FROM:<user@example.com>\r\n")
	benchReadLineSlowInput = []byte(strings.Repeat("A", 128) + "\r\n")
	benchReadLineLongInput = []byte(strings.Repeat("B", 256) + "\r\nNEXT\r\n")
	benchReadLine8BitInput = []byte("EHLO ex\xc3\xa4mple.com\r\n")
	benchASCIIBytes        = []byte("RCPT TO:<recipient@example.com>\r\n")
	benchUTF8Bytes         = []byte("RCPT TO:<récipient@example.com>\r\n")
	benchASCIIString       = "MAIL FROM:<sender@example.com>"
	benchUTF8String        = "MAIL FROM:<séndér@example.com>"
)

func BenchmarkReadLineFastPath(b *testing.B) {
	b.SetBytes(int64(len(benchReadLineFastInput)))

	for b.Loop() {
		reader := bufio.NewReaderSize(bytes.NewReader(benchReadLineFastInput), 256)
		line, err := ReadLine(reader, 512, false)
		if err != nil {
			b.Fatalf("ReadLine: %v", err)
		}
		if line == "" {
			b.Fatal("ReadLine returned empty line")
		}
	}
}

func BenchmarkReadLineSlowPath(b *testing.B) {
	b.SetBytes(int64(len(benchReadLineSlowInput)))

	for b.Loop() {
		reader := bufio.NewReaderSize(bytes.NewReader(benchReadLineSlowInput), 16)
		line, err := ReadLine(reader, 512, false)
		if err != nil {
			b.Fatalf("ReadLine: %v", err)
		}
		if len(line) != len(benchReadLineSlowInput)-2 {
			b.Fatalf("ReadLine returned %d bytes, want %d", len(line), len(benchReadLineSlowInput)-2)
		}
	}
}

func BenchmarkReadLineTooLongDrain(b *testing.B) {
	b.SetBytes(int64(len(benchReadLineLongInput)))

	for b.Loop() {
		reader := bufio.NewReaderSize(bytes.NewReader(benchReadLineLongInput), 16)
		_, err := ReadLine(reader, 64, false)
		if err != ErrLineTooLong {
			b.Fatalf("ReadLine error = %v, want %v", err, ErrLineTooLong)
		}
		line, err := ReadLine(reader, 512, false)
		if err != nil {
			b.Fatalf("ReadLine after drain: %v", err)
		}
		if line != "NEXT" {
			b.Fatalf("ReadLine after drain = %q, want %q", line, "NEXT")
		}
	}
}

func BenchmarkReadLineEnforceASCIIReject(b *testing.B) {
	b.SetBytes(int64(len(benchReadLine8BitInput)))

	for b.Loop() {
		reader := bufio.NewReaderSize(bytes.NewReader(benchReadLine8BitInput), 256)
		_, err := ReadLine(reader, 512, true)
		if err != Err8BitIn7BitMode {
			b.Fatalf("ReadLine error = %v, want %v", err, Err8BitIn7BitMode)
		}
	}
}

func BenchmarkValidateAndConvert(b *testing.B) {
	b.SetBytes(int64(len(benchReadLineFastInput)))

	for b.Loop() {
		line, err := validateAndConvert(benchReadLineFastInput, 512)
		if err != nil {
			b.Fatalf("validateAndConvert: %v", err)
		}
		if line == "" {
			b.Fatal("validateAndConvert returned empty line")
		}
	}
}

func BenchmarkIsASCIIASCII(b *testing.B) {
	b.SetBytes(int64(len(benchASCIIBytes)))

	for b.Loop() {
		if !isASCII(benchASCIIBytes) {
			b.Fatal("isASCII returned false for ASCII input")
		}
	}
}

func BenchmarkIsASCIIUTF8(b *testing.B) {
	b.SetBytes(int64(len(benchUTF8Bytes)))

	for b.Loop() {
		if isASCII(benchUTF8Bytes) {
			b.Fatal("isASCII returned true for UTF-8 input")
		}
	}
}

func BenchmarkContainsNonASCIIASCII(b *testing.B) {
	b.SetBytes(int64(len(benchASCIIString)))

	for b.Loop() {
		if ContainsNonASCII(benchASCIIString) {
			b.Fatal("ContainsNonASCII returned true for ASCII input")
		}
	}
}

func BenchmarkContainsNonASCIIUTF8(b *testing.B) {
	b.SetBytes(int64(len(benchUTF8String)))

	for b.Loop() {
		if !ContainsNonASCII(benchUTF8String) {
			b.Fatal("ContainsNonASCII returned false for UTF-8 input")
		}
	}
}
