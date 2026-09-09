// Package relay hosts the PC-side relay plumbing (roadmap Steps 3–4): the
// dialer that turns netstack flows into TLMP streams toward the phone, the
// plain-HTTP HeaderSanitizer, and the pacing gate.
package relay

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/esdfurkan/toppa/desktop/internal/mux"
)

// StreamConn adapts a mux Stream to net.Conn so gVisor's forwarding
// goroutines can pump it like any socket. Deadlines are accepted and
// ignored: the mux provides no per-stream timer (the keepalive governs
// liveness); callers that rely on deadlines for correctness — not just
// hang-avoidance — must not.
type StreamConn struct {
	Stream *mux.Stream
}

func (c *StreamConn) Read(b []byte) (int, error) {
	n, err := c.Stream.Read(b)
	if err != nil {
		return n, mapErr(err)
	}
	return n, nil
}

func (c *StreamConn) Write(b []byte) (int, error) {
	n, err := c.Stream.Write(b)
	if err != nil {
		return n, mapErr(err)
	}
	return n, nil
}

func (c *StreamConn) Close() error                      { return c.Stream.Close() }
func (c *StreamConn) LocalAddr() net.Addr               { return muxAddr{"tlmp-local"} }
func (c *StreamConn) RemoteAddr() net.Addr              { return muxAddr{c.Stream.Target.String()} }
func (c *StreamConn) SetDeadline(t time.Time) error     { return nil }
func (c *StreamConn) SetReadDeadline(t time.Time) error { return nil }
func (c *StreamConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type muxAddr struct{ s string }

func (a muxAddr) Network() string { return "tlmp" }
func (a muxAddr) String() string  { return a.s }

func mapErr(err error) error {
	switch err {
	case mux.ErrStreamReset:
		return net.ErrClosed
	case mux.ErrSessionClosed:
		return net.ErrClosed
	default:
		return err
	}
}

// Dialer opens outbound flows through the active tunnel session.
type Dialer interface {
	DialTCP(addr *net.TCPAddr) (net.Conn, error)
}

// TunnelDialer implements Dialer over the mux session factory (re-created on
// every reconnect by the daemon).
type TunnelDialer struct {
	mu        sync.RWMutex
	session   *mux.Session
	sanitizer *SanitizeConfig
	pacer     *Pacer
}

func NewTunnelDialer(session *mux.Session, sanitize *SanitizeConfig, pacer *Pacer) *TunnelDialer {
	return &TunnelDialer{session: session, sanitizer: sanitize, pacer: pacer}
}

func (d *TunnelDialer) SetSession(s *mux.Session) {
	d.mu.Lock()
	d.session = s
	d.mu.Unlock()
}

func (d *TunnelDialer) active() *mux.Session {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.session
}

// DialTCP re-originates a TCP flow: the phone opens a real socket, so the
// carrier sees an Android-native flow (TTL 64, Android TCP options).
func (d *TunnelDialer) DialTCP(addr *net.TCPAddr) (net.Conn, error) {
	session := d.active()
	if session == nil {
		return nil, fmt.Errorf("relay: no active tunnel session")
	}
	if d.pacer != nil {
		if err := d.pacer.acquire(); err != nil {
			return nil, err
		}
		defer d.pacer.release()
	}

	target := mux.Target{Network: mux.NetTCP, Port: uint16(addr.Port)}
	switch {
	case addr.IP.To4() != nil:
		target.ATYP = mux.ATYPIPv4
		target.Address = addr.IP.To4()
	case addr.IP.To16() != nil:
		target.ATYP = mux.ATYPIPv6
		target.Address = addr.IP.To16()
	default:
		return nil, fmt.Errorf("relay: bad dial address %s", addr)
	}

	stream, err := session.Open(target)
	if err != nil {
		return nil, fmt.Errorf("relay: open stream: %w", err)
	}
	var conn net.Conn = &StreamConn{Stream: stream}
	if d.sanitizer != nil && d.sanitizer.Enabled {
		conn = NewSanitizedConn(conn, *d.sanitizer)
	}
	return conn, nil
}

// SanitizeConfig controls the plain-HTTP HeaderSanitizer. HTTPS traffic is
// e2e-encrypted, so the carrier never sees its User-Agent; this rewriter
// exists because *plaintext* HTTP payloads DO cross the phone's sockets even
// in the L5 architecture.
type SanitizeConfig struct {
	Enabled        bool
	UserAgent      string // empty → DefaultAndroidUA
	StripForwarded bool
}

// DefaultAndroidUA is the replacement UA for sanitized plaintext requests.
const DefaultAndroidUA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"

var httpMethods = []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH "}

// SanitizeRequestHead rewrites a plain-HTTP request head (bytes up to and
// including the blank line): the User-Agent becomes the Android UA and
// optional Forwarded/X-Forwarded-* headers are stripped. Non-HTTP payloads
// pass through unchanged. Exported for unit tests.
func SanitizeRequestHead(head []byte, cfg SanitizeConfig) ([]byte, bool) {
	startsHTTP := false
	for _, m := range httpMethods {
		if len(head) >= len(m) && string(head[:len(m)]) == m {
			startsHTTP = true
			break
		}
	}
	if !startsHTTP {
		return head, false
	}
	var out bytes.Buffer
	changed := false
	for _, line := range strings.Split(string(head), "\r\n") {
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "user-agent:"):
			out.WriteString("User-Agent: " + cfg.userAgent() + "\r\n")
			changed = true
		case cfg.StripForwarded && (strings.HasPrefix(lower, "forwarded:") ||
			strings.HasPrefix(lower, "x-forwarded-for:") ||
			strings.HasPrefix(lower, "x-forwarded-host:") ||
			strings.HasPrefix(lower, "via:")):
			changed = true
			continue
		default:
			out.WriteString(line + "\r\n")
		}
	}
	return out.Bytes(), changed
}

func (c SanitizeConfig) userAgent() string {
	if c.UserAgent == "" {
		return DefaultAndroidUA
	}
	return c.UserAgent
}

// SanitizedConn rewrites the first HTTP request head written on the
// connection and passes everything else through untouched.
type SanitizedConn struct {
	net.Conn
	cfg     SanitizeConfig
	buf     bytes.Buffer // bytes held back until the head is complete
	done    bool
}

func NewSanitizedConn(c net.Conn, cfg SanitizeConfig) *SanitizedConn {
	return &SanitizedConn{Conn: c, cfg: cfg}
}

const maxHeadHold = 16 * 1024

func (c *SanitizedConn) Write(b []byte) (int, error) {
	if c.done {
		return c.Conn.Write(b)
	}
	c.buf.Write(b)
	data := c.buf.Bytes()
	headEnd := bytes.Index(data, []byte("\r\n\r\n"))
	complete := headEnd >= 0
	if !complete && len(data) < maxHeadHold {
		return len(b), nil // keep holding; nothing written yet
	}
	if !complete {
		// Head unreasonably large: give up sanitizing, flush raw.
		c.done = true
		return c.Conn.Write(data)
	}
	head := data[:headEnd+4]
	rest := data[headEnd+4:]
	sanitized, _ := SanitizeRequestHead(head, c.cfg)
	if _, err := c.Conn.Write(sanitized); err != nil {
		return 0, err
	}
	c.done = true
	if len(rest) > 0 {
		if _, err := c.Conn.Write(rest); err != nil {
			return len(b), err
		}
	}
	return len(b), nil
}
