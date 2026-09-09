package mux

import (
	"io"
	"net"
	"testing"
)

// BenchmarkStreamRoundTrip measures full TLMP stream throughput through the
// multiplexer over an in-memory pipe (echo workload, 64 KiB per operation).
// Wire format + flow control are exercised; crypto is not (see
// internal/tunnel benchmarks for the record layer).
func BenchmarkStreamRoundTrip(b *testing.B) {
	c1, c2 := net.Pipe()
	client := New(c1, Config{IsInitiator: true, MaxFramePayload: 16 * 1024, InitialWindow: 1024 * 1024})
	server := New(c2, Config{IsInitiator: false, MaxFramePayload: 16 * 1024, InitialWindow: 1024 * 1024})
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	go func() {
		for {
			st, err := server.Accept()
			if err != nil {
				return
			}
			go func(st *Stream) {
				_, _ = io.Copy(st, st)
				_ = st.Close()
			}(st)
		}
	}()

	st, err := client.Open(TCPv4([4]byte{127, 0, 0, 1}, 443))
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	payload := make([]byte, 64*1024)
	echo := make([]byte, len(payload))
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := st.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(st, echo); err != nil {
			b.Fatal(err)
		}
	}
}
