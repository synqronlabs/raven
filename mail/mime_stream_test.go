package mail

import (
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestValidateMIMEStream_NestedMultipart(t *testing.T) {
	headers := Headers{{Name: "Content-Type", Value: `multipart/mixed; boundary="outer"`}}
	body := strings.NewReader("--outer\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"hello\r\n" +
		"--outer\r\n" +
		"Content-Type: multipart/alternative; boundary=inner\r\n\r\n" +
		"--inner\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"plain\r\n" +
		"--inner\r\n" +
		"Content-Type: text/html\r\n\r\n" +
		"<b>html</b>\r\n" +
		"--inner--\r\n" +
		"--outer--\r\n")

	if err := ValidateMIMEStream(headers, body, MIMEWalkOptions{}); err != nil {
		t.Fatalf("ValidateMIMEStream: %v", err)
	}
}

func TestWalkMIME_DepthFirstAndDrainsLeafBodies(t *testing.T) {
	headers := Headers{{Name: "Content-Type", Value: `multipart/mixed; boundary="outer"`}}
	body := strings.NewReader("--outer\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"hello\r\n" +
		"--outer\r\n" +
		"Content-Type: multipart/alternative; boundary=inner\r\n\r\n" +
		"--inner\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"plain\r\n" +
		"--inner\r\n" +
		"Content-Type: text/html\r\n\r\n" +
		"<b>html</b>\r\n" +
		"--inner--\r\n" +
		"--outer--\r\n")

	type visitRecord struct {
		depth       int
		contentType string
		multipart   bool
		preview     string
	}

	var visits []visitRecord
	err := WalkMIME(headers, body, MIMEWalkOptions{}, func(part *MIMEWalkPart) error {
		record := visitRecord{
			depth:       part.Depth,
			contentType: part.ContentType,
			multipart:   part.IsMultipart(),
		}
		if !part.IsMultipart() {
			buf := make([]byte, 1)
			n, err := part.Body.Read(buf)
			if err != nil && err != io.EOF {
				return err
			}
			record.preview = string(buf[:n])
		}
		visits = append(visits, record)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkMIME: %v", err)
	}

	want := []visitRecord{
		{depth: 0, contentType: "multipart/mixed", multipart: true},
		{depth: 1, contentType: "text/plain", preview: "h"},
		{depth: 1, contentType: "multipart/alternative", multipart: true},
		{depth: 2, contentType: "text/plain", preview: "p"},
		{depth: 2, contentType: "text/html", preview: "<"},
	}
	if !reflect.DeepEqual(visits, want) {
		t.Fatalf("visits = %#v, want %#v", visits, want)
	}
}

func TestValidateMIMEStream_MissingBoundary(t *testing.T) {
	headers := Headers{{Name: "Content-Type", Value: "multipart/mixed"}}
	err := ValidateMIMEStream(headers, strings.NewReader("body"), MIMEWalkOptions{})
	if err == nil || !strings.Contains(err.Error(), "boundary") {
		t.Fatalf("expected boundary error, got %v", err)
	}
}

func TestValidateMIMEStream_InvalidMultipartTransferEncoding(t *testing.T) {
	headers := Headers{
		{Name: "Content-Type", Value: `multipart/mixed; boundary="b"`},
		{Name: "Content-Transfer-Encoding", Value: "base64"},
	}
	body := strings.NewReader("--b\r\nContent-Type: text/plain\r\n\r\nhello\r\n--b--\r\n")

	err := ValidateMIMEStream(headers, body, MIMEWalkOptions{})
	if err == nil || !strings.Contains(err.Error(), "Content-Transfer-Encoding") {
		t.Fatalf("expected multipart transfer encoding error, got %v", err)
	}
}

func TestValidateMIMEStream_InvalidNestedPartContentType(t *testing.T) {
	headers := Headers{{Name: "Content-Type", Value: `multipart/mixed; boundary="b"`}}
	body := strings.NewReader("--b\r\nContent-Type: !!!bad!!!\r\n\r\nbody\r\n--b--\r\n")

	err := ValidateMIMEStream(headers, body, MIMEWalkOptions{})
	if err == nil || !strings.Contains(err.Error(), "Content-Type") {
		t.Fatalf("expected invalid nested Content-Type error, got %v", err)
	}
	if !strings.Contains(err.Error(), "Content-Type") {
		t.Fatalf("expected Content-Type context, got %v", err)
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("expected invalid content-type error, got %v", err)
	}
	if !strings.Contains(err.Error(), "media type") {
		t.Fatalf("expected media type context, got %v", err)
	}
}

func TestWalkMIME_DefaultsMissingContentType(t *testing.T) {
	var got MIMEWalkPart
	err := WalkMIME(nil, strings.NewReader("hello"), MIMEWalkOptions{}, func(part *MIMEWalkPart) error {
		got = *part
		data, err := io.ReadAll(part.Body)
		if err != nil {
			return err
		}
		if string(data) != "hello" {
			t.Fatalf("body = %q, want hello", data)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkMIME: %v", err)
	}
	if got.ContentType != "text/plain" {
		t.Fatalf("ContentType = %q, want text/plain", got.ContentType)
	}
	if got.Charset != "us-ascii" {
		t.Fatalf("Charset = %q, want us-ascii", got.Charset)
	}
	if got.Depth != 0 {
		t.Fatalf("Depth = %d, want 0", got.Depth)
	}
	if got.IsMultipart() {
		t.Fatal("missing Content-Type should not be multipart")
	}
}

func TestValidateMIMEStream_MaxDepth(t *testing.T) {
	headers := Headers{{Name: "Content-Type", Value: `multipart/mixed; boundary="outer"`}}
	body := strings.NewReader("--outer\r\n" +
		"Content-Type: multipart/alternative; boundary=inner\r\n\r\n" +
		"--inner\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"plain\r\n" +
		"--inner--\r\n" +
		"--outer--\r\n")

	err := ValidateMIMEStream(headers, body, MIMEWalkOptions{MaxDepth: 2})
	if err == nil || !strings.Contains(err.Error(), "max depth exceeded") {
		t.Fatalf("expected max depth error, got %v", err)
	}
	if !strings.Contains(err.Error(), "limit 2") {
		t.Fatalf("expected limit context, got %v", err)
	}
}

func TestWalkMIME_MaxParts(t *testing.T) {
	headers := Headers{{Name: "Content-Type", Value: `multipart/mixed; boundary="outer"`}}
	body := strings.NewReader("--outer\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"hello\r\n" +
		"--outer\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"world\r\n" +
		"--outer--\r\n")

	var visited []string
	err := WalkMIME(headers, body, MIMEWalkOptions{MaxParts: 2}, func(part *MIMEWalkPart) error {
		visited = append(visited, part.ContentType)
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "max part count exceeded") {
		t.Fatalf("expected max part count error, got %v", err)
	}
	if !reflect.DeepEqual(visited, []string{"multipart/mixed", "text/plain"}) {
		t.Fatalf("visited = %#v, want root and first child only", visited)
	}
	if !strings.Contains(err.Error(), "limit 2") {
		t.Fatalf("expected limit context, got %v", err)
	}
}
