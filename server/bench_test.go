package server

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/synqronlabs/raven/sasl"
)

type benchAddr string

func (benchAddr) Network() string  { return "tcp" }
func (a benchAddr) String() string { return string(a) }

type benchConn struct {
	bytes.Buffer
}

func (*benchConn) Read(_ []byte) (int, error)         { return 0, io.EOF }
func (*benchConn) Close() error                       { return nil }
func (*benchConn) LocalAddr() net.Addr                { return benchAddr("127.0.0.1:25") }
func (*benchConn) RemoteAddr() net.Addr               { return benchAddr("127.0.0.1:54321") }
func (*benchConn) SetDeadline(_ time.Time) error      { return nil }
func (*benchConn) SetReadDeadline(_ time.Time) error  { return nil }
func (*benchConn) SetWriteDeadline(_ time.Time) error { return nil }

type benchSession struct{}

func (*benchSession) Mail(string, *MailOptions) error { return nil }
func (*benchSession) Rcpt(string, *RcptOptions) error { return nil }
func (*benchSession) Data(io.Reader) error            { return nil }
func (*benchSession) Reset()                          {}
func (*benchSession) Logout() error                   { return nil }

type benchAuthSession struct{ benchSession }

func (*benchAuthSession) AuthMechanisms() []string { return []string{"PLAIN", "LOGIN"} }
func (*benchAuthSession) Auth(string) (sasl.Server, error) {
	return nil, nil
}

var (
	benchServerAddressASCII = "user.name+tag@example.com"
	benchServerAddressUTF8  = "müller@例え.jp"
	benchServerPath         = "<user@example.com> BODY=8BITMIME SIZE=4096 SMTPUTF8"
	benchServerMailParams   = "BODY=8BITMIME SIZE=4096 SMTPUTF8 REQUIRETLS RET=FULL ENVID=queue-123 AUTH=sender@example.com"
	benchServerRcptParams   = "NOTIFY=SUCCESS,FAILURE,DELAY ORCPT=rfc822;recipient@example.net"
	benchServerData         = []byte("Received: from mx1.example.net by mx2.example.net\r\n" +
		"Subject: Benchmark DATA\r\n" +
		"\r\n" +
		"Hello world\r\n" +
		"..dot-stuffed line\r\n" +
		"Another line\r\n" +
		".\r\n")
)

func newBenchmarkConn(session Session) *Conn {
	server := NewServer(nil, ServerConfig{
		Domain:            "mx.example.com",
		MaxMessageBytes:   1 << 20,
		MaxRecipients:     100,
		MaxLineLength:     2000,
		EnableSMTPUTF8:    true,
		EnableDSN:         true,
		EnableREQUIRETLS:  true,
		EnableCHUNKING:    true,
		EnableBINARYMIME:  true,
		AllowInsecureAuth: true,
		TLSConfig:         &tls.Config{},
	})
	netConn := &benchConn{}
	conn := &Conn{
		server:  server,
		conn:    netConn,
		reader:  bufio.NewReader(bytes.NewReader(nil)),
		writer:  bufio.NewWriter(netConn),
		state:   StateGreeted,
		session: session,
	}
	conn.tlsState = &tls.ConnectionState{}
	return conn
}

func BenchmarkParseCommand(b *testing.B) {
	const line = "MAIL FROM:<sender@example.com> BODY=8BITMIME SIZE=12345"
	b.SetBytes(int64(len(line)))

	for b.Loop() {
		verb, args := parseCommand(line)
		if verb != "MAIL" || args == "" {
			b.Fatalf("parseCommand = %q %q", verb, args)
		}
	}
}

func BenchmarkParseAddressASCII(b *testing.B) {
	b.SetBytes(int64(len(benchServerAddressASCII)))

	for b.Loop() {
		parsed, err := parseAddress(benchServerAddressASCII, false)
		if err != nil {
			b.Fatalf("parseAddress: %v", err)
		}
		if parsed.Domain != "example.com" {
			b.Fatalf("Domain = %q", parsed.Domain)
		}
	}
}

func BenchmarkParseAddressSMTPUTF8(b *testing.B) {
	b.SetBytes(int64(len(benchServerAddressUTF8)))

	for b.Loop() {
		parsed, err := parseAddress(benchServerAddressUTF8, true)
		if err != nil {
			b.Fatalf("parseAddress: %v", err)
		}
		if parsed.Domain == "" {
			b.Fatal("empty normalized domain")
		}
	}
}

func BenchmarkParsePath(b *testing.B) {
	b.SetBytes(int64(len(benchServerPath)))

	for b.Loop() {
		parsed, params, err := parsePath(benchServerPath, true)
		if err != nil {
			b.Fatalf("parsePath: %v", err)
		}
		if parsed.String() != "user@example.com" || params == "" {
			b.Fatalf("parsePath = %q %q", parsed.String(), params)
		}
	}
}

func BenchmarkParseMailOptions(b *testing.B) {
	conn := newBenchmarkConn(&benchSession{})

	b.SetBytes(int64(len(benchServerMailParams)))
	b.ResetTimer()
	for b.Loop() {
		opts, err := conn.parseMailOptions(benchServerMailParams)
		if err != nil {
			b.Fatalf("parseMailOptions: %v", err)
		}
		if !opts.UTF8 || !opts.RequireTLS || opts.Size != 4096 {
			b.Fatalf("unexpected opts: %+v", opts)
		}
	}
}

func BenchmarkParseRcptOptions(b *testing.B) {
	conn := newBenchmarkConn(&benchSession{})

	b.SetBytes(int64(len(benchServerRcptParams)))
	b.ResetTimer()
	for b.Loop() {
		opts, err := conn.parseRcptOptions(benchServerRcptParams)
		if err != nil {
			b.Fatalf("parseRcptOptions: %v", err)
		}
		if len(opts.Notify) != 3 || opts.OriginalRecipient == "" {
			b.Fatalf("unexpected opts: %+v", opts)
		}
	}
}

func BenchmarkBuildExtensions(b *testing.B) {
	conn := newBenchmarkConn(&benchAuthSession{})

	b.ResetTimer()
	for b.Loop() {
		exts := conn.buildExtensions()
		if len(exts) < 6 {
			b.Fatalf("unexpected extension count: %d", len(exts))
		}
	}
}

func BenchmarkDataReaderRead(b *testing.B) {
	b.SetBytes(int64(len(benchServerData)))

	for b.Loop() {
		reader := newDataReader(bufio.NewReader(bytes.NewReader(benchServerData)), false, 1<<20)
		if _, err := io.Copy(io.Discard, reader); err != nil {
			b.Fatalf("io.Copy: %v", err)
		}
	}
}

func BenchmarkHandleMAIL(b *testing.B) {
	const args = "FROM:<sender@example.com> BODY=8BITMIME SIZE=128"
	b.SetBytes(int64(len(args)))

	for b.Loop() {
		conn := newBenchmarkConn(&benchSession{})
		if err := conn.handleMAIL(args); err != nil {
			b.Fatalf("handleMAIL: %v", err)
		}
		if conn.state != StateMail {
			b.Fatalf("state = %v, want %v", conn.state, StateMail)
		}
	}
}

func BenchmarkHandleRCPT(b *testing.B) {
	const args = "TO:<recipient@example.net> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;recipient@example.net"
	b.SetBytes(int64(len(args)))

	for b.Loop() {
		conn := newBenchmarkConn(&benchSession{})
		conn.state = StateMail
		if err := conn.handleRCPT(args); err != nil {
			b.Fatalf("handleRCPT: %v", err)
		}
		if conn.state != StateRcpt {
			b.Fatalf("state = %v, want %v", conn.state, StateRcpt)
		}
	}
}
