// Package config defines, loads, and validates the Toppa desktop
// configuration.
//
// Every operational parameter (ports, buffer sizes, keepalive intervals,
// feature toggles) lives here — nothing operational is hardcoded elsewhere.
// The JSON shape is shared with the Android client through
// protocol/schemas/config.schema.json; loading is strict (unknown fields are
// rejected) so schema drift fails fast instead of silently misconfiguring a
// session.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config is the root configuration object.
type Config struct {
	Tunnel      Tunnel      `json:"tunnel"`
	Transport   Transport   `json:"transport"`
	Relay       Relay       `json:"relay"`
	DNS         DNS         `json:"dns"`
	Log         Log         `json:"log"`
	Netstack    Netstack    `json:"netstack"`
	Obfuscation Obfuscation `json:"obfuscation"`
	API         API         `json:"api"`
	Daemon      Daemon      `json:"daemon"`

	// KeysDir overrides the directory for long-term key material. Empty
	// means ResolveKeysDir applies a platform default.
	KeysDir string `json:"keys_dir,omitempty"`
}

// Netstack carries the Wintun-facing parameters (Step 3).
type Netstack struct {
	// AdapterName is the Wintun adapter name (stable across restarts so the
	// failsafe reconcile can find leftovers).
	AdapterName string `json:"adapter_name"`
	// TunnelIP is the adapter address the default route rides.
	TunnelIP string `json:"tunnel_ip"`
	// RouteMetric must beat the physical default route's metric.
	RouteMetric int `json:"route_metric"`
	// RewritePhysicalDNS rewrites every physical adapter's DNS to the tunnel
	// resolver (kills Smart Multi-Homed parallel-query leaks).
	RewritePhysicalDNS bool `json:"rewrite_physical_dns"`
}

// Obfuscation selects the Step 4 shaping profile.
type Obfuscation struct {
	// Profile: "none" | "light" | "paranoid".
	Profile string `json:"profile"`
	// MaxConcurrent caps simultaneous relayed flows (0 disables pacing).
	MaxConcurrent int `json:"max_concurrent"`
	// JitterMs adds per-flow delay (0 disables).
	JitterMs int `json:"jitter_ms"`
	// SanitizeHTTP rewrites plaintext-HTTP User-Agent/Forwarded headers.
	SanitizeHTTP bool `json:"sanitize_http"`
	// UserAgent overrides the sanitizer's Android UA (empty = default).
	UserAgent string `json:"user_agent,omitempty"`
}

// API is the local control plane (tray/CLI).
type API struct {
	Enabled bool   `json:"enabled"`
	Listen  string `json:"listen"`
}

// Daemon carries lifecycle + fail-safe parameters.
type Daemon struct {
	// JournalPath is the failsafe mutation journal (ProgramData in prod).
	JournalPath string `json:"journal_path"`
	// ReconnectInitialMs / ReconnectMaxMs bound the exponential backoff.
	ReconnectInitialMs int `json:"reconnect_initial_ms"`
	ReconnectMaxMs     int `json:"reconnect_max_ms"`
	// DNSModeOverride lets the daemon pin dns.mode to "pc_doh" (the only
	// fully implemented v1 mode; see internal/resolver).
	DNSModeOverride string `json:"dns_mode_override,omitempty"`
}

// Tunnel carries link and multiplexer parameters shared by every transport.
type Tunnel struct {
	// MTU is the planned Wintun adapter MTU (Step 3). It must leave headroom
	// for outer transport headers plus tunnel overhead.
	MTU int `json:"mtu"`
	// MaxFramePayload caps a single TLMP frame payload in bytes.
	MaxFramePayload int `json:"max_frame_payload"`
	// InitialStreamWindow is the per-stream flow-control window in bytes.
	InitialStreamWindow int `json:"initial_stream_window"`
	// KeepAliveSecs is the TLMP PING interval; 0 disables keepalives.
	KeepAliveSecs int `json:"keepalive_secs"`
	// HandshakeTimeoutMs bounds the Noise handshake.
	HandshakeTimeoutMs int `json:"handshake_timeout_ms"`
	// ListenPort is the default TCP port for the on-phone relay listener and
	// the loopback development transport.
	ListenPort int `json:"listen_port"`
}

// Transport selects and configures the link transports in priority order.
type Transport struct {
	// Priority lists transport names in failover order: "usb", "hotspot", "wfd".
	Priority    []string `json:"priority"`
	ADB         ADB      `json:"adb"`
	HotspotAddr string   `json:"hotspot_addr"`
}

// ADB configures the USB transport (adb forward based).
type ADB struct {
	// Binary is the adb executable (absolute path or PATH lookup).
	Binary string `json:"binary"`
	// HostPort is the loopback port adb forward exposes on the PC.
	HostPort int `json:"host_port"`
}

// Relay configures the stream relay engine.
type Relay struct {
	MaxStreams   int    `json:"max_streams"`
	BufferKB     int    `json:"buffer_kb"`
	ExposeSOCKS  bool   `json:"expose_socks"`
	SocksBind    string `json:"socks_bind"`
}

// DNS selects the resolver strategy: "phone_doh" (default), "pc_doh", or
// "phone_system".
type DNS struct {
	Mode         string   `json:"mode"`
	DohServers   []string `json:"doh_servers"`
	BootstrapIPs []string `json:"bootstrap_ips"`
}

// Log configures logging output.
type Log struct {
	Level  string `json:"level"`
	Format string `json:"format"`
}

// Default returns the canonical configuration. All defaults live here (and
// mirror configs/defaults.json); nothing else in the tree may embed
// operational constants.
func Default() *Config {
	return &Config{
		Tunnel: Tunnel{
			MTU:                 1380,
			MaxFramePayload:     64 * 1024,
			InitialStreamWindow: 256 * 1024,
			KeepAliveSecs:       15,
			HandshakeTimeoutMs:  5000,
			ListenPort:          47471,
		},
		Transport: Transport{
			Priority: []string{"usb", "hotspot", "wfd"},
			ADB:      ADB{Binary: "adb", HostPort: 47472},
		},
		Relay: Relay{
			MaxStreams:  256,
			BufferKB:    256,
			ExposeSOCKS: false,
			SocksBind:   "127.0.0.1:47473",
		},
		DNS: DNS{
			Mode:       "phone_doh",
			DohServers: []string{"https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query"},
			// BootstrapIPs pin DoH resolver addresses to break the
			// bootstrap recursion; these are public anycast resolver IPs,
			// not application endpoints.
			BootstrapIPs: []string{"1.1.1.1", "8.8.8.8"},
		},
		Log: Log{Level: "info", Format: "text"},
		Netstack: Netstack{
			AdapterName:        "Toppa",
			TunnelIP:           "10.111.0.1",
			RouteMetric:        5,
			RewritePhysicalDNS: true,
		},
		Obfuscation: Obfuscation{
			Profile:       "light",
			MaxConcurrent: 0,
			JitterMs:      0,
			SanitizeHTTP:  true,
		},
		API: API{Enabled: true, Listen: "127.0.0.1:47474"},
		Daemon: Daemon{
			JournalPath:        "",
			ReconnectInitialMs: 1000,
			ReconnectMaxMs:     30000,
		},
	}
}

// Load reads path (JSON) and overlays it on Default. An empty path returns
// Default. Unknown fields are rejected.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		if err := cfg.Validate(); err != nil {
			return nil, err
		}
		return cfg, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	return cfg, nil
}

// Validate checks ranges and cross-field invariants.
func (c *Config) Validate() error {
	t := c.Tunnel
	switch {
	case t.MTU < 576 || t.MTU > 65535:
		return fmt.Errorf("tunnel.mtu %d out of range [576,65535]", t.MTU)
	case t.MaxFramePayload < 1024 || t.MaxFramePayload > 262144:
		return fmt.Errorf("tunnel.max_frame_payload %d out of range [1024,262144]", t.MaxFramePayload)
	case t.InitialStreamWindow < t.MaxFramePayload:
		return fmt.Errorf("tunnel.initial_stream_window (%d) must be >= tunnel.max_frame_payload (%d)", t.InitialStreamWindow, t.MaxFramePayload)
	case t.KeepAliveSecs < 0 || t.KeepAliveSecs > 600:
		return fmt.Errorf("tunnel.keepalive_secs %d out of range [0,600]", t.KeepAliveSecs)
	case t.HandshakeTimeoutMs < 500 || t.HandshakeTimeoutMs > 60000:
		return fmt.Errorf("tunnel.handshake_timeout_ms %d out of range [500,60000]", t.HandshakeTimeoutMs)
	case t.ListenPort < 1024 || t.ListenPort > 65535:
		return fmt.Errorf("tunnel.listen_port %d out of range [1024,65535]", t.ListenPort)
	}
	if c.Relay.MaxStreams < 1 || c.Relay.MaxStreams > 65535 {
		return fmt.Errorf("relay.max_streams %d out of range [1,65535]", c.Relay.MaxStreams)
	}
	if c.Relay.BufferKB < 4 || c.Relay.BufferKB > 8192 {
		return fmt.Errorf("relay.buffer_kb %d out of range [4,8192]", c.Relay.BufferKB)
	}
	switch c.DNS.Mode {
	case "phone_doh", "pc_doh", "phone_system":
	default:
		return fmt.Errorf("dns.mode %q not in {phone_doh, pc_doh, phone_system}", c.DNS.Mode)
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log.level %q not in {debug, info, warn, error}", c.Log.Level)
	}
	switch c.Log.Format {
	case "text", "json":
	default:
		return fmt.Errorf("log.format %q not in {text, json}", c.Log.Format)
	}
	return nil
}

// ResolveKeysDir returns the effective key store directory.
func (c *Config) ResolveKeysDir() string {
	if c.KeysDir != "" {
		return c.KeysDir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".toppa"
	}
	return filepath.Join(home, ".toppa", "desktop")
}
