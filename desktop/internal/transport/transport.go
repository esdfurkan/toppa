// Package transport implements the PC side of the link transports
// (docs/ARCHITECTURE.md §1.2): USB via adb forward (default), Wi-Fi SoftAP,
// and a loopback transport for tests. Each provides a *persistent* stream
// connection factory the daemon drives through the handshake.
package transport

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"time"
)

// Transport connects the PC to the phone's relay listener.
type Transport interface {
	// ID is the loop-guard key ("usb", "hotspot", "loopback").
	ID() string
	// Dial opens one fresh stream connection over the link.
	Dial(ctx context.Context) (net.Conn, error)
	// Prepare performs transport setup (e.g. `adb forward`) once per
	// session; implementations must be idempotent.
	Prepare(ctx context.Context) error
	// Available reports whether the link looks usable right now.
	Available(ctx context.Context) bool
}

// ADB is the USB transport. `adb forward tcp:<host> tcp:<phone>` makes the
// phone-side listener reachable at 127.0.0.1:<host> — the carrier sees
// nothing because the traffic rides the USB bus.
type ADB struct {
	Binary       string // adb executable (config transport.adb.binary)
	HostPort     int    // config transport.adb.host_port
	PhonePort    int    // config tunnel.listen_port
}

func (a *ADB) ID() string { return "usb" }

func (a *ADB) Prepare(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, a.Binary, "forward", fmt.Sprintf("tcp:%d", a.HostPort), fmt.Sprintf("tcp:%d", a.PhonePort))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("usb: adb forward failed: %w: %s", err, string(out))
	}
	return nil
}

func (a *ADB) Available(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, a.Binary, "get-state")
	return cmd.Run() == nil
}

func (a *ADB) Dial(ctx context.Context) (net.Conn, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(a.HostPort)))
	if err != nil {
		return nil, fmt.Errorf("usb: dial %d: %w", a.HostPort, err)
	}
	return conn, nil
}

// WLAN is the Wi-Fi SoftAP transport: the PC dials the phone's AP interface
// address (discovered/paired once, stored in config — never hardcoded).
type WLAN struct {
	PhoneAddr string // host:port of the phone on the hotspot network
}

func (w *WLAN) ID() string { return "hotspot" }

func (w *WLAN) Prepare(ctx context.Context) error { return nil }

func (w *WLAN) Available(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, err := dial(ctx, w.PhoneAddr)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (w *WLAN) Dial(ctx context.Context) (net.Conn, error) {
	return dial(ctx, w.PhoneAddr)
}

// Loopback is the test transport (the phone stack runs in-process).
type Loopback struct {
	Addr string
}

func (l *Loopback) ID() string                     { return "loopback" }
func (l *Loopback) Prepare(ctx context.Context) error { return nil }
func (l *Loopback) Available(ctx context.Context) bool { return true }
func (l *Loopback) Dial(ctx context.Context) (net.Conn, error) {
	return dial(ctx, l.Addr)
}

func dial(ctx context.Context, addr string) (net.Conn, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("transport: dial %s: %w", addr, err)
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	return conn, nil
}
