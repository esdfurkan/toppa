// toppactl is the development CLI for the Toppa desktop stack. In Step 1 it
// exercises the encrypted channel end to end over loopback TCP: Noise_XX
// handshake, AEAD records, and TLMP streams.
//
// Step 3 replaces the loopback transport with the Wintun-backed daemon
// (toppasvc); the handshake/mux layers used here are exactly what the daemon
// will run.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/esdfurkan/toppa/desktop/internal/config"
	"github.com/esdfurkan/toppa/desktop/internal/keys"
	"github.com/esdfurkan/toppa/desktop/internal/mux"
	"github.com/esdfurkan/toppa/desktop/internal/tunnel"
)

const usage = `toppactl — Toppa development CLI (Step 1: encrypted loopback stack)

Usage:
  toppactl serve [-config FILE] [-listen ADDR]
  toppactl ping  [-config FILE] [-addr ADDR] [-count N] [-size BYTES]

Both commands print a 6-digit SAS; confirm it matches on both ends before
trusting a first (TOFU) pairing. Keys are stored under ~/.toppa/desktop.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(os.Args[2:])
	case "ping":
		err = runPing(os.Args[2:])
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "toppactl:", err)
		os.Exit(1)
	}
}

func loadConfig(path string) *config.Config {
	cfg, err := config.Load(path)
	if err != nil {
		fatal(err)
	}
	return cfg
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "toppactl:", err)
	os.Exit(1)
}

func fingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

func muxConfig(cfg *config.Config, initiator bool) mux.Config {
	return mux.Config{
		MaxFramePayload: uint32(cfg.Tunnel.MaxFramePayload),
		InitialWindow:   uint32(cfg.Tunnel.InitialStreamWindow),
		KeepAlive:       time.Duration(cfg.Tunnel.KeepAliveSecs) * time.Second,
		IsInitiator:     initiator,
	}
}

func pinnedIf(has bool, pinned []byte) []byte {
	if has {
		return pinned
	}
	return nil
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to config JSON (defaults to built-in defaults)")
	listen := fs.String("listen", "", `listen address (default "127.0.0.1:<tunnel.listen_port>")`)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg := loadConfig(*cfgPath)
	addr := *listen
	if addr == "" {
		addr = net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", cfg.Tunnel.ListenPort))
	}

	store, err := keys.NewStore(cfg.ResolveKeysDir())
	if err != nil {
		return err
	}
	id, err := store.Identity()
	if err != nil {
		return err
	}
	pinned, hasPin, err := store.PinnedPeer("default")
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("serve: listen %s: %w", addr, err)
	}
	fmt.Printf("[serve] listening on %s (identity %s)\n", addr, fingerprint(id.Public))

	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("serve: accept: %w", err)
		}
		go handleServeConn(conn, cfg, store, id, pinned, hasPin)
	}
}

func handleServeConn(conn net.Conn, cfg *config.Config, store *keys.Store, id *keys.Identity, pinned []byte, hasPin bool) {
	defer conn.Close()
	fmt.Printf("[serve] transport from %s; running Noise_XX as responder\n", conn.RemoteAddr())

	res, err := tunnel.Handshake(conn, tunnel.HandshakeConfig{
		Role:          tunnel.RoleResponder,
		StaticPrivate: id.Private,
		PinnedPeer:    pinnedIf(hasPin, pinned),
		Timeout:       time.Duration(cfg.Tunnel.HandshakeTimeoutMs) * time.Millisecond,
	})
	if err != nil {
		fmt.Printf("[serve] handshake failed: %v\n", err)
		return
	}
	fmt.Printf("[serve] peer %s authenticated · SAS=%s · pinned=%v\n",
		fingerprint(res.PeerStatic), res.SAS, hasPin)
	if !hasPin {
		if err := store.PinPeer("default", res.PeerStatic); err != nil {
			fmt.Printf("[serve] pinning failed: %v\n", err)
		} else {
			fmt.Println("[serve] peer pinned (TOFU): SAS should be visually confirmed; re-run to enforce")
		}
	}

	ses := mux.New(res.Conn, muxConfig(cfg, false))
	defer ses.Close()
	for {
		st, err := ses.Accept()
		if err != nil {
			fmt.Printf("[serve] session ended: %v\n", err)
			return
		}
		fmt.Printf("[serve] stream %d → %s\n", st.ID(), st.Target)
		go func(st *mux.Stream) {
			_, _ = io.Copy(st, st)
			_ = st.Close()
		}(st)
	}
}

func runPing(args []string) error {
	fs := flag.NewFlagSet("ping", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to config JSON")
	addr := fs.String("addr", "", `target address (default "127.0.0.1:<tunnel.listen_port>")`)
	count := fs.Int("count", 4, "round trips to measure")
	size := fs.Int("size", 64*1024, "payload bytes per round trip")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *count < 1 || *size < 1 {
		return fmt.Errorf("ping: -count and -size must be >= 1")
	}

	cfg := loadConfig(*cfgPath)
	target := *addr
	if target == "" {
		target = net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", cfg.Tunnel.ListenPort))
	}

	store, err := keys.NewStore(cfg.ResolveKeysDir())
	if err != nil {
		return err
	}
	id, err := store.Identity()
	if err != nil {
		return err
	}
	pinned, hasPin, err := store.PinnedPeer("default")
	if err != nil {
		return err
	}

	conn, err := net.Dial("tcp", target)
	if err != nil {
		return fmt.Errorf("ping: dial %s: %w", target, err)
	}
	defer conn.Close()
	fmt.Printf("[ping] connected to %s; running Noise_XX as initiator\n", target)

	res, err := tunnel.Handshake(conn, tunnel.HandshakeConfig{
		Role:          tunnel.RoleInitiator,
		StaticPrivate: id.Private,
		PinnedPeer:    pinnedIf(hasPin, pinned),
		Timeout:       time.Duration(cfg.Tunnel.HandshakeTimeoutMs) * time.Millisecond,
	})
	if err != nil {
		return fmt.Errorf("ping: handshake: %w", err)
	}
	fmt.Printf("[ping] peer %s authenticated · SAS=%s · pinned=%v\n",
		fingerprint(res.PeerStatic), res.SAS, hasPin)
	if !hasPin {
		if err := store.PinPeer("default", res.PeerStatic); err == nil {
			fmt.Println("[ping] peer pinned (TOFU): SAS should be visually confirmed; re-run to enforce")
		}
	}

	ses := mux.New(res.Conn, muxConfig(cfg, true))
	defer ses.Close()
	st, err := ses.Open(mux.Target{Network: mux.NetTCP, ATYP: mux.ATYPFQDN, Address: []byte("echo.toppa.invalid"), Port: 0})
	if err != nil {
		return fmt.Errorf("ping: open stream: %w", err)
	}
	defer st.Close()

	payload := make([]byte, *size)
	for i := range payload {
		payload[i] = byte(i * 31)
	}
	echo := make([]byte, *size)

	var total time.Duration
	for i := 1; i <= *count; i++ {
		start := time.Now()
		if _, err := st.Write(payload); err != nil {
			return fmt.Errorf("ping: write: %w", err)
		}
		if _, err := io.ReadFull(st, echo); err != nil {
			return fmt.Errorf("ping: read: %w", err)
		}
		rtt := time.Since(start)
		total += rtt
		if !bytesEqual(payload, echo) {
			return fmt.Errorf("ping: echo payload mismatch on round %d", i)
		}
		fmt.Printf("[ping] round %d/%d · %d bytes echoed · rtt=%s\n", i, *count, *size, rtt.Round(time.Microsecond))
	}
	fmt.Printf("[ping] done · avg rtt=%s\n", (total / time.Duration(*count)).Round(time.Microsecond))
	return nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
