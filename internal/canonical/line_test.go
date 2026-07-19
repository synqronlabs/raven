package canonical

import (
	"bufio"
	"io"
	"strings"
	"testing"
)

func TestLineReader(t *testing.T) {
	input := strings.Repeat("a", 80) + "\r\nlast"
	reader := NewLineReader(bufio.NewReaderSize(strings.NewReader(input), 16))

	line, err := reader.ReadLine()
	if err != nil {
		t.Fatalf("ReadLine(first) error = %v", err)
	}
	if got, want := string(line), strings.Repeat("a", 80)+"\r\n"; got != want {
		t.Fatalf("ReadLine(first) = %q, want %q", got, want)
	}

	line, err = reader.ReadLine()
	if err != io.EOF {
		t.Fatalf("ReadLine(last) error = %v, want EOF", err)
	}
	if got, want := string(line), "last"; got != want {
		t.Fatalf("ReadLine(last) = %q, want %q", got, want)
	}
}

func TestCompressWhitespaceInPlace(t *testing.T) {
	line := []byte("  one\t\t two \t")
	result := CompressWhitespace(line)
	if got, want := string(result), " one two "; got != want {
		t.Fatalf("CompressWhitespace() = %q, want %q", got, want)
	}
	if &result[0] != &line[0] {
		t.Fatal("CompressWhitespace allocated a new backing array")
	}
}
