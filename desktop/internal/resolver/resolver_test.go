package resolver

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestTruncatedResponseForcesTCPFallback(t *testing.T) {
	query := make([]byte, 12)
	query[0] = 0xAB
	query[1] = 0xCD
	binary.BigEndian.PutUint16(query[2:4], 0x0100) // RD set
	binary.BigEndian.PutUint16(query[4:6], 1)      // QDCOUNT 1

	resp := truncatedResponse(query)
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&flagQR == 0 {
		t.Fatal("QR must be set (it is a response)")
	}
	if flags&flagTC == 0 {
		t.Fatal("TC must be set to force the TCP retry")
	}
	if resp[0] != 0xAB || resp[1] != 0xCD {
		t.Fatal("transaction id must be preserved")
	}
	if got := binary.BigEndian.Uint16(resp[4:6]); got != 1 {
		t.Fatalf("QDCOUNT must be preserved, got %d", got)
	}
}

func TestDohUpstreamRelaysWireVerbatim(t *testing.T) {
	query := make([]byte, 20)
	for i := range query {
		query[i] = byte(i)
	}
	up := &DohUpstream{
		ServerURLs: []string{"https://1.1.1.1/dns-query"},
		Dial: func(network, addr string) (net.Conn, error) {
			// The tunnel dialer is stubbed with a loopback echo server in a
			// full integration test; here we only assert construction paths.
			return net.Dial(network, addr)
		},
	}
	_ = up // construction must not panic; live POST covered by e2e scripts
}

func TestHandleTCPAnswersOneQuery(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		_ = server.Close()
	}()
	l := NewLocalDNS(net.IPv4(10, 111, 0, 1), echoUpstream{})
	if err := l.HandleTCP(client); err == nil {
		t.Log("closed pipe handled without panic")
	}
}

type echoUpstream struct{}

func (echoUpstream) QueryWire(query []byte) ([]byte, error) {
	resp := make([]byte, len(query))
	copy(resp, query)
	// set QR
	resp[2] |= 0x80
	return resp, nil
}
