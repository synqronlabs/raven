package dns

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

func startTestDNSServer(t *testing.T, handler mdns.HandlerFunc) string {
	t.Helper()

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}

	started := make(chan struct{})
	serveErr := make(chan error, 1)
	server := &mdns.Server{
		PacketConn:        packetConn,
		Handler:           handler,
		NotifyStartedFunc: func() { close(started) },
	}

	go func() {
		serveErr <- server.ActivateAndServe()
	}()

	select {
	case <-started:
	case err := <-serveErr:
		_ = packetConn.Close()
		t.Fatalf("ActivateAndServe() error = %v", err)
	case <-time.After(time.Second):
		_ = packetConn.Close()
		t.Fatal("timed out starting test DNS server")
	}

	t.Cleanup(func() {
		if err := server.Shutdown(); err != nil {
			t.Errorf("Shutdown() error = %v", err)
		}
		if err := packetConn.Close(); err != nil && !strings.Contains(err.Error(), "closed") {
			t.Errorf("Close() error = %v", err)
		}
		select {
		case err := <-serveErr:
			if err != nil && !strings.Contains(err.Error(), "closed") {
				t.Errorf("ActivateAndServe() exit error = %v", err)
			}
		case <-time.After(time.Second):
			t.Errorf("timed out waiting for test DNS server shutdown")
		}
	})

	return packetConn.LocalAddr().String()
}

func newTestResolver(addr string, dnssec bool) *DNSResolver {
	resolver := NewResolver(ResolverConfig{
		Nameservers: []string{addr},
		DNSSEC:      dnssec,
		Timeout:     100 * time.Millisecond,
	})
	resolver.config.Retries = 0
	return resolver
}

func newTestStdResolver(addr string) *StdResolver {
	return NewStdResolverWithDialer(func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "udp", addr)
	})
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestDNSResolverQueryWithoutNameservers(t *testing.T) {
	resolver := &DNSResolver{
		config: ResolverConfig{Retries: 0},
		client: &mdns.Client{Timeout: 10 * time.Millisecond},
	}

	_, _, err := resolver.query(context.Background(), "example.com", mdns.TypeTXT)
	if !errors.Is(err, ErrDNSNoNameservers) {
		t.Fatalf("query() error = %v, want ErrDNSNoNameservers", err)
	}
}

func TestDNSResolverLookupTXTJoinsSegmentsAndMarksAuthentic(t *testing.T) {
	addr := startTestDNSServer(t, mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		resp.AuthenticatedData = true
		resp.Answer = []mdns.RR{
			&mdns.TXT{
				Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 300},
				Txt: []string{"v=spf1 ", "include:_spf.example.net"},
			},
		}
		if err := w.WriteMsg(resp); err != nil {
			_ = err
		}
	}))

	result, err := newTestResolver(addr, true).LookupTXT(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("LookupTXT() error = %v", err)
	}
	if len(result.Records) != 1 || result.Records[0] != "v=spf1 include:_spf.example.net" {
		t.Fatalf("LookupTXT() records = %#v, want joined TXT record", result.Records)
	}
	if !result.Authentic {
		t.Fatal("LookupTXT() Authentic = false, want true")
	}
}

func TestDNSResolverLookupIPNotFoundIsNeverAuthenticWithoutDNSSEC(t *testing.T) {
	addr := startTestDNSServer(t, mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		resp.Rcode = mdns.RcodeNameError
		if err := w.WriteMsg(resp); err != nil {
			_ = err
		}
	}))

	result, err := newTestResolver(addr, false).LookupIP(context.Background(), "missing.example")
	if !errors.Is(err, ErrDNSNotFound) {
		t.Fatalf("LookupIP() error = %v, want ErrDNSNotFound", err)
	}
	if result.Authentic {
		t.Fatal("LookupIP() Authentic = true, want false when DNSSEC is disabled")
	}
}

func TestDNSResolverLookupMXSortsByPreference(t *testing.T) {
	addr := startTestDNSServer(t, mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		resp.Answer = []mdns.RR{
			&mdns.MX{Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeMX, Class: mdns.ClassINET, Ttl: 300}, Preference: 30, Mx: "mx3.example.com."},
			&mdns.MX{Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeMX, Class: mdns.ClassINET, Ttl: 300}, Preference: 10, Mx: "mx1.example.com."},
			&mdns.MX{Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeMX, Class: mdns.ClassINET, Ttl: 300}, Preference: 20, Mx: "mx2.example.com."},
		}
		if err := w.WriteMsg(resp); err != nil {
			_ = err
		}
	}))

	result, err := newTestResolver(addr, false).LookupMX(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("LookupMX() error = %v", err)
	}

	got := []uint16{result.Records[0].Pref, result.Records[1].Pref, result.Records[2].Pref}
	want := []uint16{10, 20, 30}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("LookupMX() preferences = %v, want %v", got, want)
		}
	}
}

func TestDNSResolverLookupTXTClassifiesDeadlineExceededAsTimeout(t *testing.T) {
	addr := startTestDNSServer(t, mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		time.Sleep(100 * time.Millisecond)
		resp := new(mdns.Msg)
		resp.SetReply(req)
		if err := w.WriteMsg(resp); err != nil {
			_ = err
		}
	}))

	resolver := newTestResolver(addr, false)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := resolver.LookupTXT(ctx, "slow.example")
	if !errors.Is(err, ErrDNSTimeout) {
		t.Fatalf("LookupTXT() error = %v, want ErrDNSTimeout", err)
	}
	if !IsTimeout(err) {
		t.Fatalf("IsTimeout(%v) = false, want true", err)
	}
}

func TestDNSResolverQueryMapsServfailToBogusWithDNSSEC(t *testing.T) {
	addr := startTestDNSServer(t, mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		resp.Rcode = mdns.RcodeServerFailure
		if err := w.WriteMsg(resp); err != nil {
			_ = err
		}
	}))

	_, err := newTestResolver(addr, true).LookupTXT(context.Background(), "bogus.example")
	if !errors.Is(err, ErrDNSBogus) {
		t.Fatalf("LookupTXT() error = %v, want ErrDNSBogus", err)
	}
}

func TestDNSResolverQueryMapsRefused(t *testing.T) {
	addr := startTestDNSServer(t, mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		resp.Rcode = mdns.RcodeRefused
		if err := w.WriteMsg(resp); err != nil {
			_ = err
		}
	}))

	_, err := newTestResolver(addr, false).LookupTXT(context.Background(), "refused.example")
	if !errors.Is(err, ErrDNSRefused) {
		t.Fatalf("LookupTXT() error = %v, want ErrDNSRefused", err)
	}
}

func TestDNSResolverLookupTXTNotFoundWithoutTXTAnswers(t *testing.T) {
	addr := startTestDNSServer(t, mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		resp.Answer = []mdns.RR{
			&mdns.CNAME{Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: 300}, Target: "other.example.com."},
		}
		if err := w.WriteMsg(resp); err != nil {
			_ = err
		}
	}))

	_, err := newTestResolver(addr, false).LookupTXT(context.Background(), "example.com")
	if !errors.Is(err, ErrDNSNotFound) {
		t.Fatalf("LookupTXT() error = %v, want ErrDNSNotFound", err)
	}
}

func TestDNSResolverLookupIPCombinesAAndAAAA(t *testing.T) {
	addr := startTestDNSServer(t, mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		resp.AuthenticatedData = true

		switch req.Question[0].Qtype {
		case mdns.TypeA:
			resp.Answer = []mdns.RR{
				&mdns.A{Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.10").To4()},
			}
		case mdns.TypeAAAA:
			resp.Answer = []mdns.RR{
				&mdns.AAAA{Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeAAAA, Class: mdns.ClassINET, Ttl: 300}, AAAA: net.ParseIP("2001:db8::10")},
			}
		}

		if err := w.WriteMsg(resp); err != nil {
			_ = err
		}
	}))

	result, err := newTestResolver(addr, true).LookupIP(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("LookupIP() error = %v", err)
	}
	if len(result.Records) != 2 {
		t.Fatalf("LookupIP() returned %d records, want 2", len(result.Records))
	}
	if !result.Authentic {
		t.Fatal("LookupIP() Authentic = false, want true")
	}
}

func TestDNSResolverLookupAddrReturnsPTRAndConfig(t *testing.T) {
	ip := net.ParseIP("192.0.2.44")
	arpa, err := mdns.ReverseAddr(ip.String())
	if err != nil {
		t.Fatalf("ReverseAddr() error = %v", err)
	}

	addr := startTestDNSServer(t, mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		resp.AuthenticatedData = true
		if req.Question[0].Name == arpa && req.Question[0].Qtype == mdns.TypePTR {
			resp.Answer = []mdns.RR{
				&mdns.PTR{Hdr: mdns.RR_Header{Name: arpa, Rrtype: mdns.TypePTR, Class: mdns.ClassINET, Ttl: 300}, Ptr: "mail.example.com."},
			}
		}
		if err := w.WriteMsg(resp); err != nil {
			_ = err
		}
	}))

	resolver := newTestResolver(addr, true)
	result, err := resolver.LookupAddr(context.Background(), ip)
	if err != nil {
		t.Fatalf("LookupAddr() error = %v", err)
	}
	if len(result.Records) != 1 || result.Records[0] != "mail.example.com." {
		t.Fatalf("LookupAddr() records = %#v, want PTR result", result.Records)
	}
	if !result.Authentic {
		t.Fatal("LookupAddr() Authentic = false, want true")
	}

	config := resolver.Config()
	if len(config.Nameservers) != 1 || config.Nameservers[0] != addr {
		t.Fatalf("Config().Nameservers = %#v, want [%q]", config.Nameservers, addr)
	}
}

func TestDNSResolverLookupAddrRejectsInvalidIP(t *testing.T) {
	resolver := &DNSResolver{}
	_, err := resolver.LookupAddr(context.Background(), net.IP{1, 2, 3})
	if err == nil {
		t.Fatal("LookupAddr() error = nil, want non-nil")
	}
}

func TestClassifyQueryError(t *testing.T) {
	otherErr := errors.New("boom")

	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "nil", err: nil, want: nil},
		{name: "deadline exceeded", err: context.DeadlineExceeded, want: ErrDNSTimeout},
		{name: "net timeout", err: timeoutError{}, want: ErrDNSTimeout},
		{name: "other", err: otherErr, want: otherErr},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyQueryError(tt.err)
			if tt.want == nil {
				if got != nil {
					t.Fatalf("classifyQueryError() = %v, want nil", got)
				}
				return
			}
			if !errors.Is(got, tt.want) {
				t.Fatalf("classifyQueryError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConvertErrorClassifiesNetDNSErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{
			name: "not found",
			err:  &net.DNSError{Name: "missing.example", Err: "no such host", IsNotFound: true},
			want: ErrDNSNotFound,
		},
		{
			name: "timeout",
			err:  &net.DNSError{Name: "slow.example", Err: "i/o timeout", IsTimeout: true},
			want: ErrDNSTimeout,
		},
		{
			name: "temporary",
			err:  &net.DNSError{Name: "temp.example", Err: "temporary failure", IsTemporary: true},
			want: ErrDNSServFail,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertError(tt.err)
			if !errors.Is(got, tt.want) {
				t.Fatalf("convertError() = %v, want %v", got, tt.want)
			}
			if !errors.Is(got, tt.err) {
				t.Fatalf("convertError() = %v, want wrapped original error", got)
			}
		})
	}
}

func TestConvertErrorWrapsNonDNSErrors(t *testing.T) {
	baseErr := errors.New("boom")
	got := convertError(baseErr)
	if !errors.Is(got, baseErr) {
		t.Fatalf("convertError() = %v, want wrapped original error", got)
	}
}

func TestStdResolverWithDialerLookupMethods(t *testing.T) {
	ip4 := net.ParseIP("192.0.2.25").To4()
	ip6 := net.ParseIP("2001:db8::25")

	addr := startTestDNSServer(t, mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
		resp := new(mdns.Msg)
		resp.SetReply(req)

		switch req.Question[0].Qtype {
		case mdns.TypeTXT:
			resp.Answer = []mdns.RR{
				&mdns.TXT{Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 300}, Txt: []string{"hello", "world"}},
			}
		case mdns.TypeA:
			resp.Answer = []mdns.RR{
				&mdns.A{Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300}, A: ip4},
			}
		case mdns.TypeAAAA:
			resp.Answer = []mdns.RR{
				&mdns.AAAA{Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeAAAA, Class: mdns.ClassINET, Ttl: 300}, AAAA: ip6},
			}
		case mdns.TypeMX:
			resp.Answer = []mdns.RR{
				&mdns.MX{Hdr: mdns.RR_Header{Name: req.Question[0].Name, Rrtype: mdns.TypeMX, Class: mdns.ClassINET, Ttl: 300}, Preference: 10, Mx: "mx.example.com."},
			}
		}

		if err := w.WriteMsg(resp); err != nil {
			_ = err
		}
	}))

	resolver := newTestStdResolver(addr)

	txtResult, err := resolver.LookupTXT(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("LookupTXT() error = %v", err)
	}
	if len(txtResult.Records) != 1 || txtResult.Records[0] != "helloworld" {
		t.Fatalf("LookupTXT() records = %#v, want concatenated TXT record", txtResult.Records)
	}

	ipResult, err := resolver.LookupIP(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("LookupIP() error = %v", err)
	}
	if len(ipResult.Records) != 2 {
		t.Fatalf("LookupIP() returned %d records, want 2", len(ipResult.Records))
	}

	mxResult, err := resolver.LookupMX(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("LookupMX() error = %v", err)
	}
	if len(mxResult.Records) != 1 || mxResult.Records[0].Host != "mx.example.com." {
		t.Fatalf("LookupMX() records = %#v, want MX result", mxResult.Records)
	}
}

func TestStdResolverLookupAddrDialFailure(t *testing.T) {
	dialErr := errors.New("forced dial failure")
	resolver := NewStdResolverWithDialer(func(_ context.Context, _, _ string) (net.Conn, error) {
		return nil, dialErr
	})

	_, err := resolver.LookupAddr(context.Background(), net.ParseIP("192.0.2.25"))
	if err == nil {
		t.Fatal("LookupAddr() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), dialErr.Error()) {
		t.Fatalf("LookupAddr() error = %v, want error containing %q", err, dialErr.Error())
	}
}

func TestStdResolverLookupAddrRejectsNilIP(t *testing.T) {
	_, err := newTestStdResolver("127.0.0.1:53").LookupAddr(context.Background(), nil)
	if err == nil {
		t.Fatal("LookupAddr() error = nil, want non-nil")
	}
}

func TestMockResolverHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	resolver := MockResolver{
		TXT: map[string][]string{"example.com.": {"v=spf1 -all"}},
		A:   map[string][]string{"example.com.": {"192.0.2.1"}},
		MX:  map[string][]*net.MX{"example.com.": {{Host: "mx.example.com.", Pref: 10}}},
		PTR: map[string][]string{"192.0.2.1": {"mx.example.com."}},
	}

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "txt",
			call: func() error {
				_, err := resolver.LookupTXT(ctx, "example.com")
				return err
			},
		},
		{
			name: "ip",
			call: func() error {
				_, err := resolver.LookupIP(ctx, "example.com")
				return err
			},
		},
		{
			name: "mx",
			call: func() error {
				_, err := resolver.LookupMX(ctx, "example.com")
				return err
			},
		},
		{
			name: "ptr",
			call: func() error {
				_, err := resolver.LookupAddr(ctx, net.ParseIP("192.0.2.1"))
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("call error = %v, want context.Canceled", err)
			}
		})
	}
}

func TestMockResolverLookupAddrRejectsNilIP(t *testing.T) {
	_, err := (MockResolver{}).LookupAddr(context.Background(), nil)
	if err == nil {
		t.Fatal("LookupAddr() error = nil, want non-nil")
	}
}

func TestMockResolverAuthenticityAndFailures(t *testing.T) {
	resolver := MockResolver{
		TXT:          map[string][]string{"example.com.": {"v=spf1 -all"}},
		A:            map[string][]string{"example.com.": {"192.0.2.1"}},
		AAAA:         map[string][]string{"example.com.": {"2001:db8::1"}},
		MX:           map[string][]*net.MX{"example.com.": {{Host: "mx.example.com.", Pref: 10}}},
		PTR:          map[string][]string{"192.0.2.1": {"mail.example.com."}},
		AllAuthentic: true,
		Inauthentic:  []string{"aaaa example.com."},
		Fail:         []string{"mx fail.example.com."},
	}

	txtResult, err := resolver.LookupTXT(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("LookupTXT() error = %v", err)
	}
	if !txtResult.Authentic {
		t.Fatal("LookupTXT() Authentic = false, want true")
	}

	ipResult, err := resolver.LookupIP(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("LookupIP() error = %v", err)
	}
	if ipResult.Authentic {
		t.Fatal("LookupIP() Authentic = true, want false after inauthentic AAAA override")
	}

	ptrResult, err := resolver.LookupAddr(context.Background(), net.ParseIP("192.0.2.1"))
	if err != nil {
		t.Fatalf("LookupAddr() error = %v", err)
	}
	if len(ptrResult.Records) != 1 || ptrResult.Records[0] != "mail.example.com." {
		t.Fatalf("LookupAddr() records = %#v, want PTR result", ptrResult.Records)
	}

	_, err = resolver.LookupMX(context.Background(), "fail.example.com")
	if !errors.Is(err, ErrDNSServFail) {
		t.Fatalf("LookupMX() error = %v, want ErrDNSServFail", err)
	}
}
