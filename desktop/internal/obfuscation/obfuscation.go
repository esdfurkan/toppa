// Package obfuscation hosts the Step 4 padding profiles. Pacing (concurrency
// caps + jitter) lives next door in internal/relay; padding rides the mux's
// PING channel so it can never corrupt stream framing (SPEC §6: padding must
// not alter frame semantics).
//
// Honesty note (threat model): padding and pacing shape what a LOCAL observer
// of the tunnel link sees and smooth PC-like burst patterns; they do not and
// cannot change volume/timing fingerprints inside end-to-end TLS.
package obfuscation

import (
	"crypto/rand"
	"time"

	"github.com/esdfurkan/toppa/desktop/internal/mux"
)

// Profile names (config obfuscation.profile).
const (
	ProfileNone     = "none"
	ProfileLight    = "light"
	ProfileParanoid = "paranoid"
)

// Settings is the resolved padding policy for a profile.
type Settings struct {
	PaddingInterval time.Duration // 0 disables
	PaddingMaxBytes int           // upper bound of per-PING padding payload
}

// SettingsFor resolves a profile name to concrete settings. Values are
// policy defaults (like the SAS domain), not operational parameters: the
// profile exists so contributors add NEW behaviors, not to hide magic
// numbers. interval==0 means the injector is idle.
func SettingsFor(profile string) Settings {
	switch profile {
	case ProfileLight:
		return Settings{PaddingInterval: 3 * time.Second, PaddingMaxBytes: 256}
	case ProfileParanoid:
		return Settings{PaddingInterval: 750 * time.Millisecond, PaddingMaxBytes: 2048}
	default: // none
		return Settings{}
	}
}

// PaddingInjector periodically sends PING frames carrying random-length
// payloads over the session. Random payload sizes defeat naive length-based
// classification of the keepalive channel.
type PaddingInjector struct {
	session  *mux.Session
	settings Settings
	stop     chan struct{}
	stopped  chan struct{}
}

func NewPaddingInjector(session *mux.Session, settings Settings) *PaddingInjector {
	return &PaddingInjector{session: session, settings: settings, stop: make(chan struct{}), stopped: make(chan struct{})}
}

// Start launches the injector goroutine. It exits when the session closes or
// Stop is called.
func (p *PaddingInjector) Start() {
	if p.settings.PaddingInterval <= 0 {
		close(p.stopped)
		return
	}
	go func() {
		defer close(p.stopped)
		ticker := time.NewTicker(p.settings.PaddingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-p.stop:
				return
			case <-ticker.C:
				if _, err := p.session.PingPayload(randomPadding(p.settings.PaddingMaxBytes)); err != nil {
					return
				}
			}
		}
	}()
}

// Stop halts the injector and waits for the goroutine to exit.
func (p *PaddingInjector) Stop() {
	close(p.stop)
	<-p.stopped
}

func randomPadding(max int) []byte {
	if max <= 0 {
		return nil
	}
	var sizeBuf [1]byte
	if _, err := rand.Read(sizeBuf[:]); err != nil {
		return nil
	}
	size := int(sizeBuf[0]) % max
	if size == 0 {
		return nil
	}
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		return nil
	}
	return payload
}
