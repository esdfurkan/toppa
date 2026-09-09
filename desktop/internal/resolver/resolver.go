// Package resolver implements the PC-local DNS strategy (roadmap Step 4,
// docs/ARCHITECTURE.md §1.5): a UDP listener on the tunnel IP answers every
// query with the truncation flag, forcing Windows to retry over TCP/53,
// which the netstack intercepts; queries are then answered via DoH through
// the tunnel (dns.mode=pc_doh). Zero plaintext DNS crosses the carrier.
package resolver

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
)

const (
	typeA    = 1
	typeAAAA = 28
	flagQR   = 0x8000
	flagTC   = 0x0200
)

// Upstream answers a raw DNS query message with a raw response message.
type Upstream interface {
	QueryWire(query []byte) ([]byte, error)
}

// DohUpstream forwards raw wire queries verbatim to a DoH server
// (application/dns-message POST). Pinned-IP server URLs come from config
// (dns.servers + dns.bootstrap_ips).
type DohUpstream struct {
	ServerURLs []string
	// Dial connects to the DoH server (pinned IP:443); TLS rides on top.
	Dial func(network, addr string) (net.Conn, error)
}

func (d *DohUpstream) QueryWire(query []byte) ([]byte, error) {
	var lastErr error
	for _, server := range d.ServerURLs {
		resp, err := dohPost(server, query, d.Dial)
		if err != nil {
			lastErr = err
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("resolver: all DoH servers failed: %w", lastErr)
}

// dohPost performs one RFC 8484 POST against a pinned-IP https URL using
// net/http over the provided dial function (the tunnel).
func dohPost(serverURL string, query []byte, dial func(network, addr string) (net.Conn, error)) ([]byte, error) {
	// net/http handles TLS + HTTP/2 for us; dial is overridden so the
	// connection egresses through the tunnel.
	httpClient := newHTTPClient(dial)
	resp, err := httpClient.Post(serverURL, "application/dns-message", bytesReader(query))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("resolver: doh http %d", resp.StatusCode)
	}
	body := make([]byte, 0, 512)
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		body = append(body, buf[:n]...)
		if n == 0 || err != nil {
			break
		}
		if len(body) > 64*1024 {
			return nil, fmt.Errorf("resolver: doh response too large")
		}
	}
	if len(body) < 12 {
		return nil, fmt.Errorf("resolver: doh response truncated")
	}
	return body, nil
}

// LocalDNS is the UDP truncation responder bound to the tunnel IP:53.
type LocalDNS struct {
	addr     net.IP
	upstream Upstream
	conn     *net.UDPConn
	closed   atomic.Bool
}

func NewLocalDNS(addr net.IP, upstream Upstream) *LocalDNS {
	return &LocalDNS{addr: addr, upstream: upstream}
}

// ServeUDP binds addr:53 and answers queries with TC-set responses until
// Close. Windows (and every major stub resolver) retries over TCP, which the
// netstack intercepts and routes to HandleTCP.
func (l *LocalDNS) ServeUDP() error {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: l.addr, Port: 53})
	if err != nil {
		return fmt.Errorf("resolver: bind udp :53: %w", err)
	}
	l.conn = conn
	buf := make([]byte, 4096)
	for {
		if l.closed.Load() {
			return nil
		}
		n, client, err := conn.ReadFromUDP(buf)
		if err != nil {
			if l.closed.Load() {
				return nil
			}
			continue
		}
		if n < 12 {
			continue
		}
		tc := truncatedResponse(buf[:n])
		if _, err := conn.WriteToUDP(tc, client); err != nil {
			continue
		}
	}
}

// QueryWireUpstream forwards a raw DNS query to the upstream (DoH through
// the tunnel). Used by the netstack's UDP/53 datagram path.
func (l *LocalDNS) QueryWireUpstream(query []byte) ([]byte, error) {
	return l.upstream.QueryWire(query)
}

// HandleTCP serves one DNS-over-TCP connection (2-byte length-prefixed
// messages): reads one query, forwards it upstream, writes one response.
func (l *LocalDNS) HandleTCP(conn net.Conn) error {	defer conn.Close()
	var lenBuf [2]byte
	if _, err := readFull(conn, lenBuf[:]); err != nil {
		return err
	}
	size := int(binary.BigEndian.Uint16(lenBuf[:]))
	if size < 12 || size > 4096 {
		return fmt.Errorf("resolver: bad tcp dns message size %d", size)
	}
	query := make([]byte, size)
	if _, err := readFull(conn, query); err != nil {
		return err
	}
	response, err := l.upstream.QueryWire(query)
	if err != nil {
		return err
	}
	if len(response) > 0xFFFF {
		response = response[:0xFFFF]
	}
	out := make([]byte, 2+len(response))
	binary.BigEndian.PutUint16(out[:2], uint16(len(response)))
	copy(out[2:], response)
	_, err = conn.Write(out)
	return err
}

func (l *LocalDNS) Close() {
	l.closed.Store(true)
	if l.conn != nil {
		l.conn.Close()
	}
}

// truncatedResponse flips a raw query into a TC=1 response so the stub
// resolver falls back to TCP (where the netstack can intercept it).
func truncatedResponse(query []byte) []byte {
	resp := make([]byte, 12)
	copy(resp, query[:4])
	qFlags := binary.BigEndian.Uint16(query[2:4])
	// Preserve opcode + RD, set QR + TC, clear AA/RA/RCODE.
	h := (qFlags & 0x7900) | flagQR | flagTC
	binary.BigEndian.PutUint16(resp[2:4], h)
	// QDCOUNT preserved from query; ANCOUNT/NSCOUNT/ARCOUNT zeroed.
	binary.BigEndian.PutUint16(resp[4:6], binary.BigEndian.Uint16(query[4:6]))
	for i := 6; i < 12; i++ {
		resp[i] = 0
	}
	return resp
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
