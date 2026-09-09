package mux

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// Errors returned by Session and Stream operations.
var (
	ErrSessionClosed     = errors.New("mux: session closed")
	ErrStreamReset       = errors.New("mux: stream reset by remote")
	ErrStreamWriteClosed = errors.New("mux: stream write side is closed")
	ErrProtocol          = errors.New("mux: protocol violation")
)

// Config tunes a Session. Zero values select package defaults; product-level
// defaults come from internal/config, never from here.
type Config struct {
	// MaxFramePayload caps a single frame payload on both send and receive.
	MaxFramePayload uint32
	// InitialWindow is the per-stream receive window granted implicitly at
	// stream creation.
	InitialWindow uint32
	// KeepAlive is the PING interval; 0 disables keepalives.
	KeepAlive time.Duration
	// PingTimeout tears the session down when no inbound frame arrives for
	// this long while keepalives are enabled.
	PingTimeout time.Duration
	// IsInitiator selects the odd/even stream-id space. Ends must disagree.
	IsInitiator bool
	// AcceptQueueDepth bounds pending inbound streams; overflow is refused
	// with RST(ReasonBusy).
	AcceptQueueDepth int
}

func (c *Config) withDefaults() {
	if c.MaxFramePayload == 0 {
		c.MaxFramePayload = 64 * 1024
	}
	if c.InitialWindow == 0 {
		c.InitialWindow = 256 * 1024
	}
	if c.PingTimeout == 0 {
		c.PingTimeout = 45 * time.Second
	}
	if c.AcceptQueueDepth == 0 {
		c.AcceptQueueDepth = 64
	}
}

// Session multiplexes Streams over one ordered, reliable connection (typically
// the AEAD record layer from internal/tunnel).
type Session struct {
	conn io.ReadWriteCloser
	cfg  Config

	writeMu sync.Mutex

	mu      sync.Mutex
	streams map[uint32]*Stream
	nextID  uint32

	acceptCh chan *Stream

	closed    atomic.Bool
	lastRecv  atomic.Int64
	closeOnce sync.Once
	done      chan struct{}
}

// New wraps conn in a multiplexed session and starts its receive loop. Ends
// must be created with mirrored IsInitiator values.
func New(conn io.ReadWriteCloser, cfg Config) *Session {
	cfg.withDefaults()
	s := &Session{
		conn:     conn,
		cfg:      cfg,
		streams:  make(map[uint32]*Stream),
		acceptCh: make(chan *Stream, cfg.AcceptQueueDepth),
		done:     make(chan struct{}),
	}
	if cfg.IsInitiator {
		s.nextID = 1
	} else {
		s.nextID = 2
	}
	s.lastRecv.Store(time.Now().UnixNano())
	go s.readLoop()
	if cfg.KeepAlive > 0 {
		go s.keepAliveLoop()
	}
	return s
}

// Open creates a stream toward target and sends its SYN frame. Data may be
// written immediately; the peer queues the stream via Accept.
func (s *Session) Open(target Target) (*Stream, error) {
	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		return nil, ErrSessionClosed
	}
	id := s.nextID
	s.nextID += 2
	st := newStream(s, id, target, int64(s.cfg.InitialWindow))
	s.streams[id] = st
	s.mu.Unlock()

	err := s.writeFrame(&Frame{Version: ProtocolVersion, Flags: FlagSYN, StreamID: id, Payload: AppendTarget(nil, target)})
	if err != nil {
		s.mu.Lock()
		delete(s.streams, id)
		s.mu.Unlock()
		return nil, err
	}
	return st, nil
}

// PingPayload sends a session-level PING carrying an arbitrary payload.
// Keepalives use small nonces; the obfuscation layer uses it for padding
// profiles (spec §6 — padding must not alter frame semantics).
func (s *Session) PingPayload(payload []byte) error {
	return s.writeFrame(&Frame{Version: ProtocolVersion, Flags: FlagPING, Payload: payload})
}

// Accept returns the next inbound stream. It fails once the session closes.
func (s *Session) Accept() (*Stream, error) {
	select {
	case st := <-s.acceptCh:
		return st, nil
	case <-s.done:
		return nil, ErrSessionClosed
	}
}

// Close tears the session down: GOAWAY (best effort), transport close, and
// all streams woken with ErrSessionClosed.
func (s *Session) Close() error {
	s.closeWithError(nil)
	return nil
}

func (s *Session) closeWithError(cause error) {
	s.closeOnce.Do(func() {
		goaway := &Frame{Version: ProtocolVersion, Flags: FlagGOAWAY, Payload: []byte{ReasonNormal}}
		if cause != nil {
			goaway.Payload[0] = ReasonProtocol
		}
		_ = s.writeFrame(goaway)
		s.closed.Store(true)
		close(s.done)
		_ = s.conn.Close()
		s.mu.Lock()
		for _, st := range s.streams {
			st.sessionClosed()
		}
		s.streams = make(map[uint32]*Stream)
		s.mu.Unlock()
	})
}

func (s *Session) writeFrame(f *Frame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.closed.Load() {
		return ErrSessionClosed
	}
	return WriteFrame(s.conn, f, s.cfg.MaxFramePayload)
}

func (s *Session) stream(id uint32) *Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[id]
}

// removeStream silently retires a fully-closed stream.
func (s *Session) removeStream(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

// resetStream retires a stream and wakes its users with ErrStreamReset.
func (s *Session) resetStream(id uint32) {
	s.mu.Lock()
	st := s.streams[id]
	delete(s.streams, id)
	s.mu.Unlock()
	if st != nil {
		st.remoteReset()
	}
}

func (s *Session) readLoop() {
	defer s.closeWithError(io.EOF)
	for {
		f, err := ReadFrame(s.conn, s.cfg.MaxFramePayload)
		if err != nil {
			return
		}
		s.lastRecv.Store(time.Now().UnixNano())
		if err := s.handleFrame(f); err != nil {
			s.closeWithError(err)
			return
		}
	}
}

func (s *Session) handleFrame(f *Frame) error {
	switch {
	case f.Flags&FlagSYN != 0:
		return s.handleSYN(f)
	case f.Flags&FlagDATA != 0:
		st := s.stream(f.StreamID)
		if st == nil {
			// The remote may still be sending before our RST arrives;
			// refuse politely instead of tearing the session down.
			s.abortStream(f.StreamID, ReasonBusy)
			return nil
		}
		return st.pushData(f.Payload)
	case f.Flags&FlagFIN != 0:
		if st := s.stream(f.StreamID); st != nil {
			st.remoteClosed()
		}
		return nil
	case f.Flags&FlagRST != 0:
		s.resetStream(f.StreamID)
		return nil
	case f.Flags&FlagWIN != 0:
		if st := s.stream(f.StreamID); st != nil {
			st.addSendWindow(int64(binary.BigEndian.Uint32(f.Payload)))
		}
		return nil
	case f.Flags&FlagPING != 0:
		return s.writeFrame(&Frame{Version: ProtocolVersion, Flags: FlagPONG, Payload: f.Payload})
	case f.Flags&FlagPONG != 0:
		return nil
	case f.Flags&FlagGOAWAY != 0:
		return ErrSessionClosed
	default:
		return fmt.Errorf("%w: unhandled frame flags 0x%02x", ErrProtocol, f.Flags)
	}
}

func (s *Session) handleSYN(f *Frame) error {
	target, err := ParseTarget(f.Payload)
	if err != nil {
		s.abortStream(f.StreamID, ReasonProtocol)
		return nil
	}
	s.mu.Lock()
	if _, dup := s.streams[f.StreamID]; dup {
		s.mu.Unlock()
		s.abortStream(f.StreamID, ReasonDupStream)
		return nil
	}
	st := newStream(s, f.StreamID, target, int64(s.cfg.InitialWindow))
	s.streams[f.StreamID] = st
	s.mu.Unlock()

	select {
	case s.acceptCh <- st:
	default:
		s.resetStream(f.StreamID)
		s.abortStream(f.StreamID, ReasonBusy)
	}
	return nil
}

func (s *Session) abortStream(id uint32, reason uint8) {
	_ = s.writeFrame(&Frame{Version: ProtocolVersion, Flags: FlagRST, StreamID: id, Payload: []byte{reason}})
}

func (s *Session) keepAliveLoop() {
	ticker := time.NewTicker(s.cfg.KeepAlive)
	defer ticker.Stop()
	var nonce [8]byte
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			if n := time.Since(time.Unix(0, s.lastRecv.Load())); n > s.cfg.PingTimeout {
				s.closeWithError(errors.New("mux: keepalive timeout"))
				return
			}
			binary.LittleEndian.PutUint64(nonce[:], uint64(time.Now().UnixNano()))
			if err := s.writeFrame(&Frame{Version: ProtocolVersion, Flags: FlagPING, Payload: nonce[:]}); err != nil {
				s.closeWithError(err)
				return
			}
		}
	}
}
