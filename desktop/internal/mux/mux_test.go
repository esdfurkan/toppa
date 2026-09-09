package mux

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// newTestPair builds a connected client/server session pair over net.Pipe.
func newTestPair(t *testing.T, tune func(*Config)) (*Session, *Session) {
	t.Helper()
	c1, c2 := net.Pipe()
	ccfg := Config{IsInitiator: true, MaxFramePayload: 4096, InitialWindow: 64 * 1024}
	scfg := Config{IsInitiator: false, MaxFramePayload: 4096, InitialWindow: 64 * 1024}
	if tune != nil {
		tune(&ccfg)
		tune(&scfg)
	}
	client := New(c1, ccfg)
	server := New(c2, scfg)
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

// echoServer accepts streams forever and echoes them until the session dies.
func echoServer(t *testing.T, s *Session) {
	t.Helper()
	for {
		st, err := s.Accept()
		if err != nil {
			return
		}
		go func(st *Stream) {
			_, _ = io.Copy(st, st)
			_ = st.Close()
		}(st)
	}
}

func pattern(seed byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed + byte(i*31)
	}
	return b
}

func TestFrameRoundTrip(t *testing.T) {
	f := &Frame{Version: ProtocolVersion, Flags: FlagDATA, StreamID: 7, Payload: []byte("hello tlmp")}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, f, 1024); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := ReadFrame(&buf, 1024)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if got.Version != f.Version || got.Flags != f.Flags || got.StreamID != f.StreamID || !bytes.Equal(got.Payload, f.Payload) {
		t.Fatalf("round trip mismatch: %+v vs %+v", got, f)
	}
}

func TestFrameRejectsBadFrames(t *testing.T) {
	cases := []struct {
		name string
		f    *Frame
	}{
		{"oversize", &Frame{Version: ProtocolVersion, Flags: FlagDATA, StreamID: 1, Payload: make([]byte, 100)}},
		{"bad version", &Frame{Version: 2, Flags: FlagDATA, StreamID: 1}},
		{"control with stream id", &Frame{Version: ProtocolVersion, Flags: FlagPING, StreamID: 4}},
		{"win wrong payload", &Frame{Version: ProtocolVersion, Flags: FlagWIN, StreamID: 1, Payload: []byte{1, 2}}},
		{"rst wrong payload", &Frame{Version: ProtocolVersion, Flags: FlagRST, StreamID: 1, Payload: []byte{1, 2}}},
		{"unknown flag bits", &Frame{Version: ProtocolVersion, Flags: 0x80 | 0x01, StreamID: 1, Payload: []byte{0, 0, 0, 0, 0}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var encoded []byte
			if tc.f.Version != ProtocolVersion {
				// AppendFrame validates the version, so unsupported-version
				// frames are hand-encoded: [v=2][flags][id=1][len=0].
				encoded = []byte{2, tc.f.Flags, 0, 0, 0, 1, 0, 0, 0, 0}
			} else {
				var err error
				encoded, err = AppendFrame(nil, tc.f, 1<<20)
				if err != nil {
					t.Fatalf("AppendFrame: %v", err)
				}
			}
			if _, err := ReadFrame(bytes.NewReader(encoded), 50); err == nil {
				t.Fatal("ReadFrame accepted a malformed frame")
			}
		})
	}
}

func TestTargetRoundTrip(t *testing.T) {
	cases := []Target{
		{Network: NetTCP, ATYP: ATYPIPv4, Address: []byte{127, 0, 0, 1}, Port: 443},
		{Network: NetTCP, ATYP: ATYPFQDN, Address: []byte("example.com"), Port: 80},
		{Network: NetUDP, ATYP: ATYPIPv6, Address: make([]byte, 16), Port: 53},
	}
	for _, tc := range cases {
		got, err := ParseTarget(AppendTarget(nil, tc))
		if err != nil {
			t.Fatalf("ParseTarget(%v): %v", tc, err)
		}
		if got.Network != tc.Network || got.ATYP != tc.ATYP || got.Port != tc.Port || !bytes.Equal(got.Address, tc.Address) {
			t.Fatalf("target mismatch: %+v vs %+v", got, tc)
		}
	}
}

func TestTargetRejectsGarbage(t *testing.T) {
	cases := [][]byte{
		{NetTCP},                         // truncated
		{9, ATYPIPv4, 0, 0, 0, 0},        // bad network
		{NetTCP, 7, 0, 0, 0, 0},          // bad atyp
		{NetTCP, ATYPFQDN, 0, 0},         // empty fqdn
		{NetTCP, ATYPFQDN, 5, 'a', 0, 0}, // length lies
		{NetTCP, ATYPIPv4, 1, 2, 3},      // short ipv4
	}
	for i, b := range cases {
		if _, err := ParseTarget(b); err == nil {
			t.Fatalf("case %d: ParseTarget accepted garbage", i)
		}
	}
}

func TestEchoStream(t *testing.T) {
	client, server := newTestPair(t, nil)
	go echoServer(t, server)

	st, err := client.Open(mustFQDN(t, "echo.toppa.test", 443))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	payload := pattern(1, 256*1024)
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
		t.Fatal("echo payload mismatch")
	}
	if err := <-errCh; err != nil {
		t.Fatalf("write/close: %v", err)
	}
}

func TestConcurrentStreams(t *testing.T) {
	client, server := newTestPair(t, nil)
	go echoServer(t, server)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(seed byte) {
			defer wg.Done()
			st, err := client.Open(mustFQDN(t, "fan.toppa.test", uint16(seed)))
			if err != nil {
				t.Errorf("open: %v", err)
				return
			}
			defer st.Close()
			payload := pattern(seed, 32*1024)
			done := make(chan error, 1)
			go func() {
				_, err := st.Write(payload)
				done <- err
			}()
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(st, got); err != nil {
				t.Errorf("read: %v", err)
				return
			}
			if err := <-done; err != nil {
				t.Errorf("write: %v", err)
				return
			}
			if !bytes.Equal(got, payload) {
				t.Errorf("stream seed %d: payload mismatch", seed)
			}
		}(byte(i + 1))
	}
	wg.Wait()
}

func TestWindowFlowControl(t *testing.T) {
	// A tiny window forces many WIN round trips; this exercises blocking
	// writers and credit accounting end to end.
	client, server := newTestPair(t, func(c *Config) {
		c.InitialWindow = 16 * 1024
		c.MaxFramePayload = 4096
	})
	go echoServer(t, server)

	st, err := client.Open(mustFQDN(t, "bulk.toppa.test", 9))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	payload := pattern(9, 1024*1024)
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
		t.Fatal("bulk payload mismatch")
	}
	if err := <-errCh; err != nil {
		t.Fatalf("write/close: %v", err)
	}
}

func TestSessionCloseWakesReaders(t *testing.T) {
	client, server := newTestPair(t, nil)
	st, err := client.Open(mustFQDN(t, "hang.toppa.test", 1))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = server.Close()
	}()

	errCh := make(chan error, 1)
	go func() {
		_, err := st.Read(make([]byte, 16))
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if err != ErrSessionClosed {
			t.Fatalf("expected ErrSessionClosed, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stream read was not woken by session close")
	}
}

func TestHalfCloseEOF(t *testing.T) {
	client, server := newTestPair(t, nil)
	go func() {
		st, err := server.Accept()
		if err != nil {
			return
		}
		if _, err := st.Write([]byte("x")); err != nil {
			t.Errorf("server write: %v", err)
		}
		_ = st.Close() // FIN: server will send nothing more
	}()

	st, err := client.Open(mustFQDN(t, "fin.toppa.test", 7))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := st.Read(buf); err != nil {
		t.Fatalf("read data: %v", err)
	}
	if _, err := st.Read(buf); err != io.EOF {
		t.Fatalf("expected io.EOF after FIN, got %v", err)
	}
}

func mustFQDN(t *testing.T, host string, port uint16) Target {
	t.Helper()
	tgt, err := TCPFQDN(host, port)
	if err != nil {
		t.Fatalf("TCPFQDN: %v", err)
	}
	return tgt
}
