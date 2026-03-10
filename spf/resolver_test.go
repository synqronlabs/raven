package spf

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	rdns "github.com/synqronlabs/raven/dns"
)

func startTestDNSServer(t *testing.T) (string, func()) {
	t.Helper()

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}

	server := &mdns.Server{
		PacketConn: packetConn,
		Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, req *mdns.Msg) {
			resp := new(mdns.Msg)
			resp.SetReply(req)
			resp.Authoritative = true

			if len(req.Question) == 0 {
				resp.Rcode = mdns.RcodeFormatError
				_ = w.WriteMsg(resp)
				return
			}

			q := req.Question[0]
			switch {
			case q.Qtype == mdns.TypeTXT && q.Name == "example.com.":
				resp.Answer = append(resp.Answer, &mdns.TXT{
					Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 60},
					Txt: []string{"v=spf1 ", "-all"},
				})
			case q.Qtype == mdns.TypeA && q.Name == "example.com.":
				resp.Answer = append(resp.Answer, &mdns.A{
					Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
					A:   net.ParseIP("192.0.2.1").To4(),
				})
			case q.Qtype == mdns.TypeAAAA && q.Name == "example.com.":
				resp.Answer = append(resp.Answer, &mdns.AAAA{
					Hdr:  mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeAAAA, Class: mdns.ClassINET, Ttl: 60},
					AAAA: net.ParseIP("2001:db8::1"),
				})
			case q.Qtype == mdns.TypeA && q.Name == "v4only.example.com.":
				resp.Answer = append(resp.Answer, &mdns.A{
					Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
					A:   net.ParseIP("192.0.2.10").To4(),
				})
			case q.Qtype == mdns.TypeAAAA && q.Name == "v6only.example.com.":
				resp.Answer = append(resp.Answer, &mdns.AAAA{
					Hdr:  mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeAAAA, Class: mdns.ClassINET, Ttl: 60},
					AAAA: net.ParseIP("2001:db8::10"),
				})
			case q.Qtype == mdns.TypeMX && q.Name == "example.com.":
				resp.Answer = append(resp.Answer, &mdns.MX{
					Hdr:        mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeMX, Class: mdns.ClassINET, Ttl: 60},
					Mx:         "mail.example.com.",
					Preference: 10,
				})
			case q.Qtype == mdns.TypePTR && q.Name == "1.2.0.192.in-addr.arpa.":
				resp.Answer = append(resp.Answer, &mdns.PTR{
					Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypePTR, Class: mdns.ClassINET, Ttl: 60},
					Ptr: "example.com.",
				})
			default:
				resp.Rcode = mdns.RcodeNameError
			}

			_ = w.WriteMsg(resp)
		}),
	}

	go func() {
		_ = server.ActivateAndServe()
	}()

	shutdown := func() {
		_ = server.Shutdown()
		_ = packetConn.Close()
	}

	return packetConn.LocalAddr().String(), shutdown
}

func TestDNSResolverWrappers(t *testing.T) {
	addr, shutdown := startTestDNSServer(t)
	defer shutdown()

	if NewResolverWithDefaults() == nil {
		t.Fatal("NewResolverWithDefaults() returned nil")
	}

	resolver := NewResolver(ResolverConfig{
		Nameservers: []string{addr},
		Timeout:     time.Second,
		Retries:     1,
	})
	if resolver == nil {
		t.Fatal("NewResolver() returned nil")
	}

	ctx := context.Background()

	txts, result, err := resolver.LookupTXT(ctx, "example.com")
	if err != nil || len(txts) != 1 || txts[0] != "v=spf1 -all" || result.Authentic {
		t.Fatalf("LookupTXT() = (%v, authentic=%v, err=%v), want ([v=spf1 -all], false, nil)", txts, result.Authentic, err)
	}
	if _, _, err := resolver.LookupTXT(ctx, "missing.example.com"); !errors.Is(err, ErrDNSNotFound) {
		t.Fatalf("LookupTXT() missing error = %v, want ErrDNSNotFound", err)
	}

	ips, _, err := resolver.LookupIP(ctx, "ip", "example.com")
	if err != nil || len(ips) != 2 {
		t.Fatalf("LookupIP(ip) = (%v, err=%v), want 2 records and nil error", ips, err)
	}
	ips, _, err = resolver.LookupIP(ctx, "ip4", "v4only.example.com")
	if err != nil || len(ips) != 1 || ips[0].To4() == nil {
		t.Fatalf("LookupIP(ip4) = (%v, err=%v), want one IPv4 record", ips, err)
	}
	ips, _, err = resolver.LookupIP(ctx, "ip6", "v6only.example.com")
	if err != nil || len(ips) != 1 || ips[0].To4() != nil {
		t.Fatalf("LookupIP(ip6) = (%v, err=%v), want one IPv6 record", ips, err)
	}
	if _, _, err := resolver.LookupIP(ctx, "ip6", "v4only.example.com"); !errors.Is(err, ErrDNSNotFound) {
		t.Fatalf("LookupIP(ip6 on v4-only host) error = %v, want ErrDNSNotFound", err)
	}
	if _, _, err := resolver.LookupIP(ctx, "ip4", "missing.example.com"); !errors.Is(err, ErrDNSNotFound) {
		t.Fatalf("LookupIP() missing error = %v, want ErrDNSNotFound", err)
	}

	mxs, _, err := resolver.LookupMX(ctx, "example.com")
	if err != nil || len(mxs) != 1 || mxs[0].Host != "mail.example.com." {
		t.Fatalf("LookupMX() = (%v, err=%v), want one MX record", mxs, err)
	}
	if _, _, err := resolver.LookupMX(ctx, "missing.example.com"); !errors.Is(err, ErrDNSNotFound) {
		t.Fatalf("LookupMX() missing error = %v, want ErrDNSNotFound", err)
	}

	ptrs, _, err := resolver.LookupAddr(ctx, "192.0.2.1")
	if err != nil || len(ptrs) != 1 || ptrs[0] != "example.com." {
		t.Fatalf("LookupAddr() = (%v, err=%v), want one PTR record", ptrs, err)
	}
	if _, _, err := resolver.LookupAddr(ctx, "not-an-ip"); err == nil {
		t.Fatal("LookupAddr() expected error for invalid IP string")
	}
	if _, _, err := resolver.LookupAddr(ctx, "192.0.2.99"); !errors.Is(err, ErrDNSNotFound) {
		t.Fatalf("LookupAddr() missing error = %v, want ErrDNSNotFound", err)
	}
}

func TestStdResolverWrappers(t *testing.T) {
	addr, shutdown := startTestDNSServer(t)
	defer shutdown()

	if NewStdResolver() == nil {
		t.Fatal("NewStdResolver() returned nil")
	}

	resolver := &StdResolver{r: rdns.NewStdResolverWithDialer(func(ctx context.Context, network, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, addr)
	})}

	ctx := context.Background()

	txts, result, err := resolver.LookupTXT(ctx, "example.com.")
	if err != nil || len(txts) != 1 || txts[0] != "v=spf1 -all" || result.Authentic {
		t.Fatalf("Std LookupTXT() = (%v, authentic=%v, err=%v), want ([v=spf1 -all], false, nil)", txts, result.Authentic, err)
	}
	if _, _, err := resolver.LookupTXT(ctx, "missing.example.com."); !errors.Is(err, ErrDNSNotFound) {
		t.Fatalf("Std LookupTXT() missing error = %v, want ErrDNSNotFound", err)
	}

	ips, _, err := resolver.LookupIP(ctx, "ip", "example.com.")
	if err != nil || len(ips) != 2 {
		t.Fatalf("Std LookupIP(ip) = (%v, err=%v), want 2 records and nil error", ips, err)
	}
	ips, _, err = resolver.LookupIP(ctx, "ip4", "v4only.example.com.")
	if err != nil || len(ips) != 1 || ips[0].To4() == nil {
		t.Fatalf("Std LookupIP(ip4) = (%v, err=%v), want one IPv4 record", ips, err)
	}
	ips, _, err = resolver.LookupIP(ctx, "ip6", "v6only.example.com.")
	if err != nil || len(ips) != 1 || ips[0].To4() != nil {
		t.Fatalf("Std LookupIP(ip6) = (%v, err=%v), want one IPv6 record", ips, err)
	}
	if _, _, err := resolver.LookupIP(ctx, "ip6", "v4only.example.com."); !errors.Is(err, ErrDNSNotFound) {
		t.Fatalf("Std LookupIP(ip6 on v4-only host) error = %v, want ErrDNSNotFound", err)
	}
	if _, _, err := resolver.LookupIP(ctx, "ip4", "missing.example.com."); !errors.Is(err, ErrDNSNotFound) {
		t.Fatalf("Std LookupIP() missing error = %v, want ErrDNSNotFound", err)
	}

	mxs, _, err := resolver.LookupMX(ctx, "example.com.")
	if err != nil || len(mxs) != 1 || mxs[0].Host != "mail.example.com." {
		t.Fatalf("Std LookupMX() = (%v, err=%v), want one MX record", mxs, err)
	}
	if _, _, err := resolver.LookupMX(ctx, "missing.example.com."); !errors.Is(err, ErrDNSNotFound) {
		t.Fatalf("Std LookupMX() missing error = %v, want ErrDNSNotFound", err)
	}

	ptrs, _, err := resolver.LookupAddr(ctx, "192.0.2.1")
	if err != nil || len(ptrs) != 1 || ptrs[0] != "example.com." {
		t.Fatalf("Std LookupAddr() = (%v, err=%v), want one PTR record", ptrs, err)
	}
	if _, _, err := resolver.LookupAddr(ctx, "not-an-ip"); err == nil {
		t.Fatal("Std LookupAddr() expected error for invalid IP string")
	}
	if _, _, err := resolver.LookupAddr(ctx, "192.0.2.99"); !errors.Is(err, ErrDNSNotFound) {
		t.Fatalf("Std LookupAddr() missing error = %v, want ErrDNSNotFound", err)
	}
}
