package tunnel

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/esdfurkan/toppa/desktop/internal/mux"
)

// handshakePair runs a full Noise_XX exchange over net.Pipe and returns both
// secured ends plus their SAS strings.
func handshakePair(t *testing.T) (ini, resp *SecureConn, sasI, sasR string) {
	t.Helper()

	iniKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	respKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	c1, c2 := net.Pipe()
	type result struct {
		r   *HandshakeResult
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		r, err := Handshake(c2, HandshakeConfig{
			Role:          RoleResponder,
			StaticPrivate: respKey.Bytes(),
		})
		resCh <- result{r, err}
	}()

	resI, err := Handshake(c1, HandshakeConfig{
		Role:          RoleInitiator,
		StaticPrivate: iniKey.Bytes(),
	})
	if err != nil {
		t.Fatalf("initiator handshake: %v", err)
	}
	out := <-resCh
	if out.err != nil {
		t.Fatalf("responder handshake: %v", out.err)
	}

	if resI.SAS != out.r.SAS {
		t.Fatalf("SAS mismatch: initiator %s vs responder %s", resI.SAS, out.r.SAS)
	}
	if len(resI.SAS) != 6 {
		t.Fatalf("SAS must be 6 digits, got %q", resI.SAS)
	}
	if !bytes.Equal(resI.PeerStatic, respKey.PublicKey().Bytes()) {
		t.Fatal("initiator did not learn the responder static key")
	}
	if !bytes.Equal(out.r.PeerStatic, iniKey.PublicKey().Bytes()) {
		t.Fatal("responder did not learn the initiator static key")
	}
	return resI.Conn, out.r.Conn, resI.SAS, out.r.SAS
}

func TestHandshakeSASAndKeyExchange(t *testing.T) {
	_, _, sasI, sasR := handshakePair(t)
	if sasI != sasR {
		t.Fatalf("SAS differs across ends: %s vs %s", sasI, sasR)
	}
}

func TestRecordRoundTrip(t *testing.T) {
	ini, resp, _, _ := handshakePair(t)

	payload := make([]byte, 512*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	go func() {
		_, _ = ini.Write(payload)
	}()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(resp, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("record layer corrupted the payload")
	}
}

// tamperConn flips a bit in the Nth write passing through it. Handshake
// writes are counted too: the initiator emits exactly two handshake writes
// (msg1, msg3) before the record layer starts (header, ciphertext, header,
// ciphertext, …), so index 4 is the first record's ciphertext.
type tamperConn struct {
	net.Conn
	writes int
}

const tamperWriteIndex = 4

func (t *tamperConn) Write(b []byte) (int, error) {
	t.writes++
	if t.writes == tamperWriteIndex {
		b = append([]byte(nil), b...)
		b[0] ^= 0x01
	}
	return t.Conn.Write(b)
}

func TestRecordAuthRejectsTampering(t *testing.T) {
	c1, c2 := net.Pipe()
	iniKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	respKey, _ := ecdh.X25519().GenerateKey(rand.Reader)

	type result struct {
		r   *HandshakeResult
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		r, err := Handshake(c2, HandshakeConfig{Role: RoleResponder, StaticPrivate: respKey.Bytes()})
		resCh <- result{r, err}
	}()

	wrapped := &tamperConn{Conn: c1}
	iniRes, err := Handshake(wrapped, HandshakeConfig{Role: RoleInitiator, StaticPrivate: iniKey.Bytes()})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	out := <-resCh
	if out.err != nil {
		t.Fatalf("responder handshake: %v", out.err)
	}

	// Bound the read so a regression (record accepted) fails fast instead of
	// hanging on a pipe with no further traffic.
	if err := out.r.Conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := iniRes.Conn.Write([]byte("attack at dawn")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 64)
	if _, err := out.r.Conn.Read(buf); err == nil {
		t.Fatal("tampered record was accepted")
	}
}

func TestPinningRejectsWrongPeer(t *testing.T) {
	iniKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	respKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	wrongPin, _ := ecdh.X25519().GenerateKey(rand.Reader)

	c1, c2 := net.Pipe()
	resCh := make(chan error, 1)
	go func() {
		_, err := Handshake(c2, HandshakeConfig{Role: RoleResponder, StaticPrivate: respKey.Bytes()})
		resCh <- err
	}()

	_, err := Handshake(c1, HandshakeConfig{
		Role:          RoleInitiator,
		StaticPrivate: iniKey.Bytes(),
		PinnedPeer:    wrongPin.PublicKey().Bytes(),
	})
	if !errors.Is(err, ErrPeerMismatch) {
		t.Fatalf("expected ErrPeerMismatch, got %v", err)
	}
	<-resCh // responder side finishes or errors; either is fine here
}

func TestPinningAcceptsCorrectPeer(t *testing.T) {
	iniKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	respKey, _ := ecdh.X25519().GenerateKey(rand.Reader)

	c1, c2 := net.Pipe()
	resCh := make(chan error, 1)
	go func() {
		_, err := Handshake(c2, HandshakeConfig{Role: RoleResponder, StaticPrivate: respKey.Bytes()})
		resCh <- err
	}()

	_, err := Handshake(c1, HandshakeConfig{
		Role:          RoleInitiator,
		StaticPrivate: iniKey.Bytes(),
		PinnedPeer:    respKey.PublicKey().Bytes(),
	})
	if err != nil {
		t.Fatalf("pinned handshake with the correct key failed: %v", err)
	}
	<-resCh
}

// TestMuxOverTunnel is the Step-1 integration test: Noise_XX + AEAD records +
// TLMP streams, end to end over an in-memory transport.
func TestMuxOverTunnel(t *testing.T) {
	ini, resp, _, _ := handshakePair(t)

	server := mux.New(resp, mux.Config{IsInitiator: false, MaxFramePayload: 16 * 1024, InitialWindow: 64 * 1024})
	client := mux.New(ini, mux.Config{IsInitiator: true, MaxFramePayload: 16 * 1024, InitialWindow: 64 * 1024})
	defer server.Close()
	defer client.Close()

	go func() {
		for {
			st, err := server.Accept()
			if err != nil {
				return
			}
			go func(st *mux.Stream) {
				_, _ = io.Copy(st, st)
				_ = st.Close()
			}(st)
		}
	}()

	target, err := mux.TCPFQDN("e2e.toppa.test", 443)
	if err != nil {
		t.Fatal(err)
	}
	st, err := client.Open(target)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	payload := make([]byte, 256*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() {
		_, err := st.Write(payload)
		if err == nil {
			err = st.Close()
		}
		errCh <- err
	}()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(st, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("end-to-end payload mismatch through tunnel + mux")
	}
	if err := <-errCh; err != nil {
		t.Fatalf("write/close: %v", err)
	}
}
