package mail

import (
	"bytes"
	"testing"
	"time"
)

var (
	benchMailAttachmentData = bytes.Repeat([]byte("attachment-bytes-"), 128)
	benchMailInlineData     = bytes.Repeat([]byte("inline-image-"), 64)
	benchMailLongSubject    = "This is a long benchmark subject line that should exercise RFC 5322 folding behavior across multiple whitespace boundaries for realistic mail generation"
	benchMailTextBody       = "Hello there,\r\nThis is a realistic benchmark body.\r\nIt spans multiple lines to exercise serialization.\r\n"
	benchMailMultipartBody  = []byte("--outer-boundary\r\n" +
		"Content-Type: multipart/alternative; boundary=inner-boundary\r\n\r\n" +
		"--inner-boundary\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nplain body\r\n" +
		"--inner-boundary\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<b>html body</b>\r\n" +
		"--inner-boundary--\r\n" +
		"--outer-boundary\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=report.bin\r\nContent-Transfer-Encoding: base64\r\n\r\nQUJDREVGRw==\r\n" +
		"--outer-boundary--\r\n")
)

func benchmarkMailBuilderText() *MailBuilder {
	return NewMailBuilder().
		From("sender@example.com").
		To("recipient@example.com").
		Subject("Benchmark Subject").
		Date(time.Unix(1734607200, 0)).
		MessageID("mail-bench@example.com").
		TextBody(benchMailTextBody)
}

func benchmarkMailBuilderAttachments() *MailBuilder {
	return NewMailBuilder().
		From("sender@example.com").
		To("recipient@example.com").
		Subject("Benchmark Multipart Message").
		Date(time.Unix(1734607200, 0)).
		MessageID("mail-bench-attachments@example.com").
		HTMLBody("<html><body><h1>Benchmark</h1><p>Hello world.</p></body></html>").
		AttachFile("report.pdf", benchMailAttachmentData, "application/pdf").
		AttachInline("image.png", "cid-bench", benchMailInlineData, "image/png")
}

func benchmarkMultipartContent() Content {
	return Content{
		Headers: Headers{{Name: "Content-Type", Value: `multipart/mixed; boundary="outer-boundary"`}},
		Body:    benchMailMultipartBody,
	}
}

func benchmarkRawContent(b *testing.B) []byte {
	b.Helper()
	mail, err := benchmarkMailBuilderAttachments().Build()
	if err != nil {
		b.Fatalf("Build: %v", err)
	}
	return mail.Content.ToRaw()
}

func BenchmarkMailBuilderBuildText(b *testing.B) {
	for b.Loop() {
		mail, err := benchmarkMailBuilderText().Build()
		if err != nil {
			b.Fatalf("Build: %v", err)
		}
		if len(mail.Content.Body) == 0 {
			b.Fatal("empty body")
		}
	}
}

func BenchmarkMailBuilderBuildAttachments(b *testing.B) {
	for b.Loop() {
		mail, err := benchmarkMailBuilderAttachments().Build()
		if err != nil {
			b.Fatalf("Build: %v", err)
		}
		if mail.Content.Headers.Get("Content-Type") == "" {
			b.Fatal("missing Content-Type")
		}
	}
}

func BenchmarkContentToMIME_Multipart(b *testing.B) {
	content := benchmarkMultipartContent()
	b.SetBytes(int64(len(content.Body)))

	b.ResetTimer()
	for b.Loop() {
		part, err := content.ToMIME()
		if err != nil {
			b.Fatalf("ToMIME: %v", err)
		}
		if !part.IsMultipart() {
			b.Fatal("expected multipart MIME part")
		}
	}
}

func BenchmarkMIMEPartToBytes_Multipart(b *testing.B) {
	content := benchmarkMultipartContent()
	part, err := content.ToMIME()
	if err != nil {
		b.Fatalf("ToMIME setup: %v", err)
	}
	b.SetBytes(int64(len(content.Body)))

	b.ResetTimer()
	for b.Loop() {
		serialized, err := part.ToBytes()
		if err != nil {
			b.Fatalf("ToBytes: %v", err)
		}
		if len(serialized) == 0 {
			b.Fatal("empty serialized MIME body")
		}
	}
}

func BenchmarkContentFromMIME_Multipart(b *testing.B) {
	content := benchmarkMultipartContent()
	part, err := content.ToMIME()
	if err != nil {
		b.Fatalf("ToMIME setup: %v", err)
	}
	b.SetBytes(int64(len(content.Body)))

	b.ResetTimer()
	for b.Loop() {
		var dst Content
		if err := dst.FromMIME(part); err != nil {
			b.Fatalf("FromMIME: %v", err)
		}
		if len(dst.Body) == 0 {
			b.Fatal("empty body after FromMIME")
		}
	}
}

func BenchmarkContentToRaw(b *testing.B) {
	raw := benchmarkRawContent(b)
	content := Content{}
	content.FromRaw(raw)
	b.SetBytes(int64(len(raw)))

	b.ResetTimer()
	for b.Loop() {
		serialized := content.ToRaw()
		if len(serialized) == 0 {
			b.Fatal("empty raw content")
		}
	}
}

func BenchmarkContentFromRaw(b *testing.B) {
	raw := benchmarkRawContent(b)
	b.SetBytes(int64(len(raw)))

	b.ResetTimer()
	for b.Loop() {
		var content Content
		content.FromRaw(raw)
		if len(content.Headers) == 0 {
			b.Fatal("missing parsed headers")
		}
	}
}

func BenchmarkFoldHeaderLong(b *testing.B) {
	b.SetBytes(int64(len(benchMailLongSubject)))

	for b.Loop() {
		folded := FoldHeader("Subject", benchMailLongSubject)
		if len(folded) == 0 {
			b.Fatal("empty folded header")
		}
	}
}

func benchmarkStreamingMIME(size int) (Headers, []byte) {
	const boundary = "raven-benchmark-boundary"
	headers := Headers{{Name: "Content-Type", Value: `multipart/mixed; boundary="` + boundary + `"`}}
	prefix := []byte("--" + boundary + "\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nbenchmark body\r\n--" + boundary + "\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n")
	suffix := []byte("\r\n--" + boundary + "--\r\n")
	encodedLine := []byte("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0123456789QUJDREVGR0hJSktMTU5PUFFSU1RV\r\n")
	body := make([]byte, 0, size+len(encodedLine))
	body = append(body, prefix...)
	for len(body)+len(encodedLine)+len(suffix) <= size {
		body = append(body, encodedLine...)
	}
	body = append(body, suffix...)
	return headers, body
}

func benchmarkDisplayMIMEWalk(b *testing.B, size int) {
	headers, body := benchmarkStreamingMIME(size)
	reader := bytes.NewReader(body)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for b.Loop() {
		reader.Reset(body)
		if err := WalkMIME(headers, reader, MIMEWalkOptions{}, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDisplayMIMEWalk1MiB(b *testing.B) {
	benchmarkDisplayMIMEWalk(b, 1<<20)
}

func BenchmarkDisplayMIMEWalk16MiB(b *testing.B) {
	benchmarkDisplayMIMEWalk(b, 16<<20)
}

func BenchmarkScaleMIMEWalk1MiB(b *testing.B) {
	headers, body := benchmarkStreamingMIME(1 << 20)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		reader := bytes.NewReader(body)
		for pb.Next() {
			reader.Reset(body)
			if err := WalkMIME(headers, reader, MIMEWalkOptions{}, nil); err != nil {
				b.Error(err)
				return
			}
		}
	})
}
