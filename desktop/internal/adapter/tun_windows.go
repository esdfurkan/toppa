//go:build windows

package adapter

import (
	"fmt"
	"time"

	"golang.zx2c4.com/wintun"
	"golang.org/x/sys/windows"
)

// Wintun implements TunDevice over the wintun driver session.
type Wintun struct {
	name    string
	mtu     int
	adapter *wintun.Adapter
	session *wintun.Session
	logf    func(format string, args ...any)
}

const defaultRingCapacity = 0x800000 // 8 MiB

// NewWintun creates (or reopens) the adapter and starts a session.
// Requires elevation. Reopening an existing adapter with the same name keeps
// GUIDs stable across daemon restarts, which keeps rollback simple.
func NewWintun(cfg Config) (*Wintun, error) {
	if cfg.Name == "" {
		return nil, fmt.Errorf("adapter: name is required")
	}
	if cfg.MTU <= 0 {
		return nil, fmt.Errorf("adapter: mtu must be positive")
	}
	ring := cfg.RingCapacity
	if ring == 0 {
		ring = defaultRingCapacity
	}
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}

	adapter, err := wintun.CreateAdapter(cfg.Name, "Toppa", nil)
	if err != nil {
		// Left over from a crashed run: reopen instead of failing (the
		// failsafe journal deletes leftover adapters on reconcile).
		adapter, err = wintun.OpenAdapter(cfg.Name)
		if err != nil {
			return nil, fmt.Errorf("adapter: create/open %q: %w", cfg.Name, err)
		}
		logf("adapter: reopened existing adapter %q", cfg.Name)
	}
	session, err := adapter.StartSession(ring)
	if err != nil {
		_ = adapter.Close()
		return nil, fmt.Errorf("adapter: start session: %w", err)
	}
	return &Wintun{name: cfg.Name, mtu: cfg.MTU, adapter: adapter, session: session, logf: logf}, nil
}

func (w *Wintun) Name() string { return w.name }
func (w *Wintun) MTU() int     { return w.mtu }

// Read pulls one packet from the receive ring. Wintun's Go API has no
// blocking wait, so an empty ring polls at a short interval — the ring is
// still lock-free for the driver side.
func (w *Wintun) Read(packet []byte) (int, error) {
	for {
		pkt, err := w.session.ReceivePacket()
		switch {
		case err == nil:
			n := len(pkt)
			if n > len(packet) {
				w.session.ReleaseReceivePacket(pkt)
				return 0, fmt.Errorf("adapter: packet %d bytes exceeds read buffer %d", n, len(packet))
			}
			copy(packet, pkt)
			w.session.ReleaseReceivePacket(pkt)
			return n, nil
		case err == windows.ERROR_NO_MORE_ITEMS:
			time.Sleep(500 * time.Microsecond)
		default:
			return 0, fmt.Errorf("adapter: receive: %w", err)
		}
	}
}

func (w *Wintun) Write(packet []byte) (int, error) {
	if err := w.session.SendPacket(packet); err != nil {
		return 0, fmt.Errorf("adapter: send: %w", err)
	}
	return len(packet), nil
}

// Close ends the session and releases the adapter handle. The adapter itself
// is intentionally NOT deleted here: route/DNS state may still reference it,
// and teardown order belongs to the failsafe journal (delete happens on
// reconcile of a clean shutdown).
func (w *Wintun) Close() error {
	w.session.End()
	if err := w.adapter.Close(); err != nil {
		return fmt.Errorf("adapter: close: %w", err)
	}
	return nil
}

// DeleteAdapter removes the driver adapter entirely (clean-shutdown path).
func DeleteAdapter(name string) error {
	adapter, err := wintun.OpenAdapter(name)
	if err != nil {
		return nil // nothing to delete
	}
	var reboot bool
	if err := adapter.DeleteAdapter(&reboot); err != nil {
		return fmt.Errorf("adapter: delete %q: %w", name, err)
	}
	return nil
}
