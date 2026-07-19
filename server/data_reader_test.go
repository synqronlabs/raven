package server

import (
	"bufio"
	"bytes"
	"io"
	"testing"
)

func TestDataReaderSmallBuffers(t *testing.T) {
	input := []byte("Subject: fragmented line test\r\n\r\n..dot-stuffed\r\nbody\r\n.\r\nNEXT\r\n")
	buffered := bufio.NewReaderSize(bytes.NewReader(input), 16)
	reader := newDataReader(buffered, false, 0)

	var got bytes.Buffer
	buf := make([]byte, 3)
	for {
		n, err := reader.Read(buf)
		got.Write(buf[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
	}

	want := "Subject: fragmented line test\r\n\r\n.dot-stuffed\r\nbody\r\n"
	if got.String() != want {
		t.Fatalf("message = %q, want %q", got.String(), want)
	}

	next, err := buffered.ReadString('\n')
	if err != nil {
		t.Fatalf("reading command after DATA: %v", err)
	}
	if next != "NEXT\r\n" {
		t.Fatalf("next command = %q, want %q", next, "NEXT\r\n")
	}
}
