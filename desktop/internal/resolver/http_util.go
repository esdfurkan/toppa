package resolver

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"time"
)

// newHTTPClient builds an http.Client whose TCP connections come from dial —
// for DoH-through-tunnel this is the relay dialer, so the DoH connection
// egresses the tunnel (pinned IP:443, real TLS on top).
func newHTTPClient(dial func(network, addr string) (net.Conn, error)) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dial(network, addr)
			},
			TLSHandshakeTimeout: 5 * time.Second,
			DisableKeepAlives:   true,
		},
	}
}

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }
