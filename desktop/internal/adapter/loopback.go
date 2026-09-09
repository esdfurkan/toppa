package adapter

import (
	"net"
	"sync"
)

// Loopback is an in-memory TunDevice pair for tests: anything written to one
// side is readable on the other, preserving packet boundaries. This lets the
// netstack and failsafe layers be exercised without Windows.
type Loopback struct {
	name string
	mtu  int
	peer *Loopback

	mu      sync.Mutex
	queue   [][]byte
	signal  chan struct{}
	closed  bool
}

// NewLoopbackPair returns two connected loopback devices.
func NewLoopbackPair(nameA, nameB string, mtu int) (*Loopback, *Loopback) {
	a := &Loopback{name: nameA, mtu: mtu, signal: make(chan struct{}, 1024)}
	b := &Loopback{name: nameB, mtu: mtu, signal: make(chan struct{}, 1024)}
	a.peer = b
	b.peer = a
	return a, b
}

func (l *Loopback) Name() string { return l.name }
func (l *Loopback) MTU() int     { return l.mtu }

// Write delivers the packet to the peer's read queue.
func (l *Loopback) Write(packet []byte) (int, error) {
	l.peer.mu.Lock()
	if l.peer.closed {
		l.peer.mu.Unlock()
		return 0, net.ErrClosed
	}
	cp := append([]byte(nil), packet...)
	l.peer.queue = append(l.peer.queue, cp)
	l.peer.mu.Unlock()
	select {
	case l.peer.signal <- struct{}{}:
	default:
	}
	return len(packet), nil
}

// Read pops one packet written by the peer; blocks until one arrives.
func (l *Loopback) Read(packet []byte) (int, error) {
	for {
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			return 0, net.ErrClosed
		}
		if len(l.queue) > 0 {
			pkt := l.queue[0]
			l.queue = l.queue[1:]
			l.mu.Unlock()
			n := len(pkt)
			if n > len(packet) {
				return 0, net.ErrClosed
			}
			copy(packet, pkt)
			return n, nil
		}
		l.mu.Unlock()
		<-l.signal
	}
}

func (l *Loopback) Close() error {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	close(l.signal)
	return nil
}
