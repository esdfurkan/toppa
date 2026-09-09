package relay

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestSanitizeRequestHeadRewritesUserAgent(t *testing.T) {
	head := "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nAccept: */*\r\n\r\n"
	out, changed := SanitizeRequestHead([]byte(head), SanitizeConfig{Enabled: true})
	if !changed {
		t.Fatal("head with a Windows UA must be rewritten")
	}
	s := string(out)
	if strings.Contains(s, "Windows NT") {
		t.Fatalf("Windows UA leaked: %s", s)
	}
	if !strings.Contains(s, DefaultAndroidUA) {
		t.Fatalf("Android UA missing: %s", s)
	}
	if !strings.Contains(s, "Host: example.com") || !strings.Contains(s, "Accept: */*") {
		t.Fatalf("unrelated headers damaged: %s", s)
	}
}

func TestSanitizeRequestHeadStripsForwarded(t *testing.T) {
	head := "POST /a HTTP/1.1\r\nX-Forwarded-For: 10.0.0.1\r\nVia: toppa\r\nHost: h\r\n\r\n"
	out, changed := SanitizeRequestHead([]byte(head), SanitizeConfig{Enabled: true, StripForwarded: true})
	if !changed {
		t.Fatal("expected changes")
	}
	if strings.Contains(string(out), "Forwarded") || strings.Contains(string(out), "Via:") {
		t.Fatalf("forwarded headers survived: %s", out)
	}
}

func TestSanitizeRequestHeadPassesThroughNonHTTP(t *testing.T) {
	payload := "SSH-2.0-OpenSSH_9\r\n"
	out, changed := SanitizeRequestHead([]byte(payload), SanitizeConfig{Enabled: true})
	if changed || string(out) != payload {
		t.Fatal("non-HTTP payload must pass through unchanged")
	}
}

func TestSanitizedConnHoldsUntilHeadComplete(t *testing.T) {
	client, server := net.Pipe()
	sanitized := NewSanitizedConn(client, SanitizeConfig{Enabled: true})

	// Partial head: nothing may reach the wire yet.
	if _, err := sanitized.Write([]byte("GET / HTTP/1.1\r\nUser-A")); err != nil {
		t.Fatal(err)
	}
	if probeHasData(server) {
		t.Fatal("partial head was written through")
	}

	go func() {
		_, _ = sanitized.Write([]byte("gent: x\r\n\r\nBODY"))
	}()

	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("read sanitized head: %v", err)
	}
	head := string(buf[:n])
	if !strings.Contains(head, DefaultAndroidUA) {
		t.Fatalf("sanitized UA missing: %q", head)
	}
	if !strings.Contains(head, "\r\n\r\n") {
		t.Fatalf("head terminator missing: %q", head)
	}
}

// probeHasData reports whether anything is readable within a short window.
func probeHasData(c net.Conn) bool {
	_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	one := make([]byte, 1)
	_, err := c.Read(one)
	return err == nil
}
