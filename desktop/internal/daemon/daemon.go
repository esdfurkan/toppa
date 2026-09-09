// Package daemon assembles the full PC-side pipeline (roadmap Step 3):
// transport → Noise handshake → mux → netstack (Wintun) with journaled
// routes/DNS, the resolver, obfuscation profiles, and the control API.
// Lifecycle rules:
//   - fail-closed kill-switch: routes are applied before any traffic flows
//     and rolled back only on clean stop; a crashed run leaves them in place
//     and the next start reconciles them (traffic dies in Wintun meanwhile —
//     never falls back to the physical NIC).
//   - reconnect with bounded exponential backoff, forever, until told to stop.
package daemon

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync/atomic"
	"time"

	"github.com/esdfurkan/toppa/desktop/internal/adapter"
	"github.com/esdfurkan/toppa/desktop/internal/api"
	"github.com/esdfurkan/toppa/desktop/internal/config"
	"github.com/esdfurkan/toppa/desktop/internal/failsafe"
	"github.com/esdfurkan/toppa/desktop/internal/mux"
	"github.com/esdfurkan/toppa/desktop/internal/netstack"
	"github.com/esdfurkan/toppa/desktop/internal/obfuscation"
	"github.com/esdfurkan/toppa/desktop/internal/relay"
	"github.com/esdfurkan/toppa/desktop/internal/resolver"
	"github.com/esdfurkan/toppa/desktop/internal/sysroute"
	"github.com/esdfurkan/toppa/desktop/internal/keys"
	"github.com/esdfurkan/toppa/desktop/internal/transport"
	"github.com/esdfurkan/toppa/desktop/internal/tunnel"
)

// State names reported over the control API.
const (
	StateOnline     = "online"
	StateConnecting = "connecting"
	StateOffline    = "offline"
)

type Daemon struct {
	cfg     *config.Config
	journal *failsafe.Journal
	routes  *sysroute.Manager
	dialer  *relay.TunnelDialer
	dns     *resolver.LocalDNS
	api     *api.Server

	state     atomic.Value // string
	transport atomic.Value // string
	since     atomic.Value // time.Time
	reconnect chan struct{}
}

func New(cfg *config.Config) (*Daemon, error) {
	journalPath := cfg.Daemon.JournalPath
	if journalPath == "" {
		journalPath = "toppa-journal.json" // packaging step overrides with ProgramData
	}
	journal, err := failsafe.Open(journalPath)
	if err != nil {
		return nil, err
	}
	dnsMode := cfg.DNS.Mode
	if cfg.Daemon.DNSModeOverride != "" {
		dnsMode = cfg.Daemon.DNSModeOverride
	}
	_ = dnsMode // pc_doh is the only fully wired v1 upstream (see connect())

	d := &Daemon{cfg: cfg, journal: journal, reconnect: make(chan struct{}, 1)}
	d.routes = sysroute.NewManager(sysroute.NetshConfigurer{}, journal)
	d.state.Store(StateOffline)
	d.transport.Store("")
	d.since.Store(time.Now())
	if cfg.API.Enabled {
		d.api = api.NewServer(cfg.API.Listen, d)
	}
	return d, nil
}

// Status implements api.Control.
func (d *Daemon) Status() api.Status {
	return api.Status{
		State:     d.state.Load().(string),
		Transport: d.transport.Load().(string),
		Since:     d.since.Load().(time.Time),
	}
}

// Reconnect implements api.Control: tears the current session down; the run
// loop reconnects immediately.
func (d *Daemon) Reconnect() {
	select {
	case d.reconnect <- struct{}{}:
	default:
	}
}

// Run blocks until ctx is cancelled: reconcile leftovers, serve the API,
// then reconnect forever with bounded exponential backoff.
func (d *Daemon) Run(ctx context.Context) error {
	rolled, err := d.routes.Reconcile()
	if err != nil {
		return fmt.Errorf("daemon: reconcile failed (system may hold stale state): %w", err)
	}
	if rolled > 0 {
		fmt.Printf("[daemon] reconciled %d leftover mutation(s) from a previous run\n", rolled)
	}
	if d.api != nil {
		if err := d.api.Listen(); err != nil {
			return err
		}
	}

	backoff := time.Duration(d.cfg.Daemon.ReconnectInitialMs) * time.Millisecond
	maxBackoff := time.Duration(d.cfg.Daemon.ReconnectMaxMs) * time.Millisecond
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		d.state.Store(StateConnecting)
		sessionLifetime, err := d.connect(ctx)
		switch {
		case err == nil:
			backoff = time.Duration(d.cfg.Daemon.ReconnectInitialMs) * time.Millisecond
		case ctx.Err() != nil:
			return ctx.Err()
		default:
			fmt.Printf("[daemon] session ended: %v\n", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-d.reconnect:
			// Immediate reconnect on demand.
		case <-time.After(jitter(backoff, sessionLifetime)):
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// connect runs ONE tunnel session to completion: transport, handshake, mux,
// Wintun + routes, resolver, obfuscation. It returns when the session dies.
func (d *Daemon) connect(ctx context.Context) (time.Duration, error) {
	started := time.Now()
	d.state.Store(StateConnecting)

	// 1) Transport: priority order from config.
	tr := d.pickTransport(ctx)
	if tr == nil {
		d.state.Store(StateOffline)
		return 0, fmt.Errorf("daemon: no available transport (usb needs adb + device; hotspot needs an address)")
	}
	d.transport.Store(tr.ID())
	if err := tr.Prepare(ctx); err != nil {
		return 0, err
	}
	dialCtx, cancelDial := context.WithTimeout(ctx, 5*time.Second)
	conn, err := tr.Dial(dialCtx)
	cancelDial()
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	// 2) Handshake (Noise_XX initiator) + mux.
	identity, err := keys.NewStore(d.cfg.ResolveKeysDir())
	if err != nil {
		return 0, err
	}
	localID, err := identity.Identity()
	if err != nil {
		return 0, err
	}
	pinned, hasPin, err := identity.PinnedPeer("default")
	if err != nil {
		return 0, err
	}
	handshakeResult, err := tunnel.Handshake(conn, tunnel.HandshakeConfig{
		Role:          tunnel.RoleInitiator,
		StaticPrivate: localID.Private,
		PinnedPeer:    pinned,
		Timeout:       time.Duration(d.cfg.Tunnel.HandshakeTimeoutMs) * time.Millisecond,
	})
	if err != nil {
		return 0, fmt.Errorf("daemon: handshake: %w", err)
	}
	fmt.Printf("[daemon] peer authenticated · SAS=%s · pinned=%v\n", handshakeResult.SAS, hasPin)

	session := mux.New(handshakeResult.Conn, mux.Config{
		IsInitiator:      true,
		MaxFramePayload:  uint32(d.cfg.Tunnel.MaxFramePayload),
		InitialWindow:    uint32(d.cfg.Tunnel.InitialStreamWindow),
		KeepAlive:        time.Duration(d.cfg.Tunnel.KeepAliveSecs) * time.Second,
	})
	defer session.Close()

	// 3) Relay dialer (+ Step 4 shaping).
	var pacer *relay.Pacer
	if d.cfg.Obfuscation.MaxConcurrent > 0 {
		pacer = relay.NewPacer(d.cfg.Obfuscation.MaxConcurrent, d.cfg.Obfuscation.JitterMs)
	}
	var sanitizer *relay.SanitizeConfig
	if d.cfg.Obfuscation.SanitizeHTTP {
		sanitizer = &relay.SanitizeConfig{Enabled: true, UserAgent: d.cfg.Obfuscation.UserAgent, StripForwarded: true}
	}
	dialer := relay.NewTunnelDialer(session, sanitizer, pacer)
	d.dialer = dialer

	// 4) Padding injector (obfuscation profile).
	injector := obfuscation.NewPaddingInjector(session, obfuscation.SettingsFor(d.cfg.Obfuscation.Profile))
	injector.Start()
	defer injector.Stop()

	// 5) Wintun + netstack + resolver + routes. Order matters: the adapter
	// and routes exist before any app traffic can select them, and the
	// journal entry lands BEFORE each mutation.
	tun, err := adapter.Open(adapter.Config{
		Name: d.cfg.Netstack.AdapterName,
		MTU:  d.cfg.Tunnel.MTU,
	})
	if err != nil {
		return 0, err
	}
	tunnelIP := net.ParseIP(d.cfg.Netstack.TunnelIP)

	doh := &resolver.DohUpstream{
		ServerURLs: d.cfg.DNS.DohServers,
		Dial: func(network, addr string) (net.Conn, error) {
			ip := net.ParseIP(hostOf(addr))
			port := portOf(addr)
			return dialer.DialTCP(&net.TCPAddr{IP: ip, Port: port})
		},
	}
	localDNS := resolver.NewLocalDNS(tunnelIP, doh)

	engine, err := netstack.Start(tun, dialer, localDNS, tunnelIP)
	if err != nil {
		_ = tun.Close()
		return 0, err
	}

	if err := d.routes.Apply(sysroute.Desired{
		AdapterName:        d.cfg.Netstack.AdapterName,
		TunnelIP:           tunnelIP,
		TunnelPrefixLen:    32,
		DefaultRouteMetric: d.cfg.Netstack.RouteMetric,
		DNS:                []net.IP{tunnelIP},
		RewritePhysicalDNS: d.cfg.Netstack.RewritePhysicalDNS,
	}); err != nil {
		engine.Stop()
		_ = tun.Close()
		return 0, err
	}

	d.state.Store(StateOnline)
	d.since.Store(started)
	fmt.Printf("[daemon] online via %s (tunnel ip %s, mtu %d)\n", tr.ID(), tunnelIP, d.cfg.Tunnel.MTU)

	// 6) Session death watch: Accept fails exactly when the session closes.
	sessionDown := make(chan struct{})
	go func() {
		for {
			if _, err := session.Accept(); err != nil {
				close(sessionDown)
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
	case <-sessionDown:
	case <-d.reconnect:
	}

	// Teardown: stack stops first (no new writes into a dying adapter),
	// then routes roll back, then the adapter handle.
	engine.Stop()
	if rolled, err := d.routes.Rollback(); err != nil {
		fmt.Printf("[daemon] rollback error (journal retains state): %v (rolled %d)\n", err, rolled)
	}
	_ = tun.Close()
	_ = adapter.DeleteAdapter(d.cfg.Netstack.AdapterName)
	d.state.Store(StateOffline)
	return time.Since(started), nil
}

// pickTransport walks transport.priority and returns the first usable one.
func (d *Daemon) pickTransport(ctx context.Context) transport.Transport {
	for _, name := range d.cfg.Transport.Priority {
		var t transport.Transport
		switch name {
		case "usb":
			t = &transport.ADB{Binary: d.cfg.Transport.ADB.Binary, HostPort: d.cfg.Transport.ADB.HostPort, PhonePort: d.cfg.Tunnel.ListenPort}
		case "hotspot":
			if d.cfg.Transport.HotspotAddr == "" {
				continue
			}
			t = &transport.WLAN{PhoneAddr: d.cfg.Transport.HotspotAddr}
		default:
			continue // "wfd" is experimental (Step 4/5 hardware pass)
		}
		if t.Available(ctx) {
			return t
		}
	}
	return nil
}

func jitter(base time.Duration, lifetime time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	return base + time.Duration(rand.Int63n(int64(base/4)+1))
}

func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func portOf(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 443
	}
	var port int
	fmt.Sscanf(p, "%d", &port)
	return port
}
