package relay

import (
	"fmt"
	"sync"
)

// Pacer is the Step 4 pacing profile gate: caps concurrent relayed flows and
// optionally adds a small per-flow jitter so PC-shaped bursts (dozens of
// parallel sockets in one instant) are smoothed into phone-shaped behavior.
// It is honest about its limits: this changes flow-count signals, not volume
// or timing fingerprints inside e2e TLS.
type Pacer struct {
	mu          sync.Mutex
	maxStreams  int // 0 disables pacing
	jitterMillis int
	active      int
}

func NewPacer(maxStreams, jitterMillis int) *Pacer {
	return &Pacer{maxStreams: maxStreams, jitterMillis: jitterMillis}
}

func (p *Pacer) acquire() error {
	if p == nil || p.maxStreams <= 0 {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active >= p.maxStreams {
		return fmt.Errorf("relay: pacing cap (%d concurrent flows) reached", p.maxStreams)
	}
	p.active++
	return nil
}

func (p *Pacer) release() {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.active > 0 {
		p.active--
	}
	p.mu.Unlock()
}
