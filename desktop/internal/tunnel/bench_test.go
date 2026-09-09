package tunnel

import (
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"net"
	"testing"
)

// BenchmarkHandshake measures a full Noise_XX exchange (both roles) over an
// in-memory pipe — the cost of every new connection.
func BenchmarkHandshake(b *testing.B) {
	for i := 0; i < b.N; i++ {
		c1, c2 := net.Pipe()
		iniKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		respKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = Handshake(c2, HandshakeConfig{Role: RoleResponder, StaticPrivate: respKey.Bytes()})
		}()
		if _, err := Handshake(c1, HandshakeConfig{Role: RoleInitiator, StaticPrivate: iniKey.Bytes()}); err != nil {
			b.Fatal(err)
		}
		<-done
		_ = c1.Close()
		_ = c2.Close()
	}
}

// BenchmarkSecureThroughput measures AEAD record-layer throughput (64 KiB
// writes) after one handshake, over an in-memory pipe. This isolates the
// ChaCha20-Poly1305 + framing cost that sits on top of any transport.
func BenchmarkSecureThroughput(b *testing.B) {
	c1, c2 := net.Pipe()
	iniKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	respKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := Handshake(c2, HandshakeConfig{Role: RoleResponder, StaticPrivate: respKey.Bytes()})
		if err != nil {
			b.Error(err)
			return
		}
	}()
	iniRes, err := Handshake(c1, HandshakeConfig{Role: RoleInitiator, StaticPrivate: iniKey.Bytes()})
	if err != nil {
		b.Fatal(err)
	}
	<-done

	go func() {
		_, _ = io.Copy(io.Discard, c2)
	}()

	payload := make([]byte, 64*1024)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := iniRes.Conn.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	_ = c1.Close()
	<-done
}
