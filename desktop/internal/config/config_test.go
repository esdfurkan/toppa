package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultsValidate(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("built-in defaults are invalid: %v", err)
	}
}

func TestLoadOverlay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "toppa.json")
	body := `{"tunnel": {"listen_port": 12345}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Tunnel.ListenPort != 12345 {
		t.Fatalf("override not applied: listen_port = %d", cfg.Tunnel.ListenPort)
	}
	if cfg.Tunnel.MaxFramePayload != 64*1024 {
		t.Fatalf("default not preserved: max_frame_payload = %d", cfg.Tunnel.MaxFramePayload)
	}
	if cfg.DNS.Mode != "phone_doh" {
		t.Fatalf("default not preserved: dns.mode = %q", cfg.DNS.Mode)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "toppa.json")
	body := `{"tunnel": {"nonsense": 1}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted an unknown field")
	}
}

func TestValidateRanges(t *testing.T) {
	cases := []func(*Config){
		func(c *Config) { c.Tunnel.MTU = 100 },
		func(c *Config) { c.Tunnel.InitialStreamWindow = 1024 }, // < max_frame_payload
		func(c *Config) { c.Tunnel.KeepAliveSecs = -1 },
		func(c *Config) { c.Tunnel.ListenPort = 80 },
		func(c *Config) { c.Relay.MaxStreams = 0 },
		func(c *Config) { c.DNS.Mode = "telepathy" },
		func(c *Config) { c.Log.Level = "verbose" },
	}
	for i, mutate := range cases {
		cfg := Default()
		mutate(cfg)
		if err := cfg.Validate(); err == nil {
			t.Fatalf("case %d: Validate accepted an invalid config", i)
		}
	}
}

func TestResolveKeysDir(t *testing.T) {
	cfg := Default()
	if cfg.KeysDir != "" {
		t.Fatalf("defaults must not pin KeysDir: %q", cfg.KeysDir)
	}
	if got := cfg.ResolveKeysDir(); got == "" {
		t.Fatal("ResolveKeysDir returned empty")
	}
	cfg.KeysDir = "custom"
	if got := cfg.ResolveKeysDir(); got != "custom" {
		t.Fatalf("KeysDir override ignored: %q", got)
	}
}
