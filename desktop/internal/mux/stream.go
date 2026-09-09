package mux

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

// Stream is one multiplexed channel. Created by Session.Open (outbound) or
// Session.Accept (inbound). Reads drain buffered data, then return io.EOF
// once the remote has half-closed; Close sends FIN for the write side only.
type Stream struct {
	ses    *Session
	id     uint32
	Target Target

	mu          sync.Mutex
	cond        *sync.Cond
	buf         []byte
	sendWin     int64
	recvUnacked uint32
	finRecv     bool
	finSent     bool
	reset       bool
	sclosed     bool
}

func newStream(s *Session, id uint32, t Target, window int64) *Stream {
	st := &Stream{ses: s, id: id, Target: t, sendWin: window}
	st.cond = sync.NewCond(&st.mu)
	return st
}

// ID returns the multiplexed stream identifier.
func (st *Stream) ID() uint32 { return st.id }

// Read returns buffered stream data, blocking while the buffer is empty. It
// returns io.EOF after the remote FIN has been observed and drained, and
// ErrStreamReset / ErrSessionClosed on abnormal termination.
func (st *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	st.mu.Lock()
	for len(st.buf) == 0 {
		if st.reset {
			st.mu.Unlock()
			return 0, ErrStreamReset
		}
		if st.finRecv {
			st.mu.Unlock()
			return 0, io.EOF
		}
		if st.sclosed {
			st.mu.Unlock()
			return 0, ErrSessionClosed
		}
		st.cond.Wait()
	}
	n := copy(p, st.buf)
	st.buf = st.buf[n:]
	unacked := st.recvUnacked + uint32(n)
	st.recvUnacked = 0
	st.mu.Unlock()

	// Return credit outside the lock; failure only matters if the whole
	// session is dying, in which case outstanding credit is irrelevant.
	_ = st.ses.writeFrame(&Frame{Version: ProtocolVersion, Flags: FlagWIN, StreamID: st.id, Payload: appendU32(nil, unacked)})
	return n, nil
}

// Write sends p, blocking while the peer's flow-control window is exhausted.
// Partial writes are possible only on error, with the count of bytes already
// framed returned.
func (st *Stream) Write(p []byte) (int, error) {
	total := 0
	for total < len(p) {
		st.mu.Lock()
		for st.sendWin == 0 {
			switch {
			case st.reset:
				st.mu.Unlock()
				return total, ErrStreamReset
			case st.sclosed:
				st.mu.Unlock()
				return total, ErrSessionClosed
			case st.finSent:
				st.mu.Unlock()
				return total, ErrStreamWriteClosed
			}
			st.cond.Wait()
		}
		if st.reset {
			st.mu.Unlock()
			return total, ErrStreamReset
		}
		n := int64(len(p) - total)
		if n > st.sendWin {
			n = st.sendWin
		}
		if n > int64(st.ses.cfg.MaxFramePayload) {
			n = int64(st.ses.cfg.MaxFramePayload)
		}
		st.sendWin -= n
		st.mu.Unlock()

		chunk := p[total : total+int(n)]
		err := st.ses.writeFrame(&Frame{Version: ProtocolVersion, Flags: FlagDATA, StreamID: st.id, Payload: chunk})
		if err != nil {
			return total, err
		}
		total += int(n)
	}
	return total, nil
}

// Close half-closes the write side with FIN. It is idempotent; the read side
// continues to drain until EOF.
func (st *Stream) Close() error {
	st.mu.Lock()
	if st.finSent {
		st.mu.Unlock()
		return nil
	}
	st.finSent = true
	both := st.finRecv
	st.cond.Broadcast()
	st.mu.Unlock()
	if both {
		st.ses.removeStream(st.id)
	}
	return st.ses.writeFrame(&Frame{Version: ProtocolVersion, Flags: FlagFIN, StreamID: st.id})
}

// pushData appends inbound DATA, enforcing the receive window contract.
func (st *Stream) pushData(b []byte) error {
	st.mu.Lock()
	if len(st.buf)+len(b) > int(st.ses.cfg.InitialWindow) {
		st.mu.Unlock()
		return fmt.Errorf("%w: receive window exceeded on stream %d", ErrProtocol, st.id)
	}
	if len(b) > 0 {
		st.buf = append(st.buf, b...)
	}
	st.cond.Broadcast()
	st.mu.Unlock()
	return nil
}

func (st *Stream) remoteClosed() {
	st.mu.Lock()
	st.finRecv = true
	both := st.finSent
	st.cond.Broadcast()
	st.mu.Unlock()
	if both {
		st.ses.removeStream(st.id)
	}
}

func (st *Stream) addSendWindow(n int64) {
	st.mu.Lock()
	st.sendWin += n
	st.cond.Broadcast()
	st.mu.Unlock()
}

func (st *Stream) sessionClosed() {
	st.mu.Lock()
	st.sclosed = true
	st.cond.Broadcast()
	st.mu.Unlock()
}

func (st *Stream) remoteReset() {
	st.mu.Lock()
	st.reset = true
	st.cond.Broadcast()
	st.mu.Unlock()
}

func appendU32(dst []byte, v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return append(dst, b[:]...)
}
