// Package tunnel implements the Toppa encrypted channel: the Noise_XX
// handshake and the AEAD record layer (protocol/SPEC.md §2–3), exposed as a
// net.Conn that the mux can ride.
//
// Invariants:
//   - The handshake library (github.com/flynn/noise) is referenced only in
//     handshake.go; swapping crypto stacks must not touch secure.go or mux.
//   - Nonces follow protocol/SPEC.md §2.5: one counter per direction,
//     starting at 0 and incremented once per record, owned by the library's
//     CipherState and never reset within a session.
package tunnel

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/flynn/noise"
)

// Role selects the Noise handshake role. The device that opened the transport
// connection is the initiator.
type Role int

const (
	RoleInitiator Role = iota + 1
	RoleResponder
)

// Errors.
var (
	ErrPeerMismatch     = errors.New("tunnel: pinned peer key does not match remote")
	ErrBadKey           = errors.New("tunnel: malformed static key")
	ErrHandshakeFailed  = errors.New("tunnel: handshake failed")
	ErrRecordTooLarge   = errors.New("tunnel: record exceeds negotiated maximum")
)

const (
	// handshake framing (SPEC §2.2)
	handshakeHeaderSize = 2
	handshakeMaxMessage = 64 * 1024
	// record framing (SPEC §3): 3-byte length prefix (ciphertext size)
	recordHeaderSize  = 3
	recordOverhead    = 16 // ChaCha20-Poly1305 tag
	defaultMaxPayload = 256 * 1024
	defaultTimeout    = 5 * time.Second
	minMaxPayload     = 4 * 1024
	maxMaxPayload     = 16 * 1024 * 1024
	// sasDomain separates the SAS derivation from the Noise hash domain.
	sasDomain = "toppa-sas-v1"
)

// HandshakeConfig parameterizes one handshake.
type HandshakeConfig struct {
	// Role is RoleInitiator or RoleResponder (required).
	Role Role
	// StaticPrivate is the 32-byte X25519 private key (from keys.Identity).
	StaticPrivate []byte
	// PinnedPeer is the expected remote static public key; nil disables
	// pinning (first pairing).
	PinnedPeer []byte
	// MaxPayload bounds a record's plaintext (default 256 KiB).
	MaxPayload uint32
	// Timeout bounds the whole handshake (default 5s).
	Timeout time.Duration
}

func (c *HandshakeConfig) withDefaults() {
	if c.MaxPayload == 0 {
		c.MaxPayload = defaultMaxPayload
	}
	if c.Timeout == 0 {
		c.Timeout = defaultTimeout
	}
}

// HandshakeResult is the outcome of a successful handshake.
type HandshakeResult struct {
	// Conn is the encrypted connection ready for TLMP traffic.
	Conn *SecureConn
	// SAS is the 6-digit short authentication string; display on both ends
	// during first pairing and require visual confirmation.
	SAS string
	// PeerStatic is the remote static public key carried in the handshake
	// payload (SPEC §2.3); pin it after SAS confirmation.
	PeerStatic []byte
}

// Handshake runs Noise_XX over conn and returns the secured connection.
func Handshake(conn net.Conn, cfg HandshakeConfig) (*HandshakeResult, error) {
	cfg.withDefaults()
	if cfg.Role != RoleInitiator && cfg.Role != RoleResponder {
		return nil, fmt.Errorf("%w: role %d", ErrBadKey, cfg.Role)
	}
	if len(cfg.StaticPrivate) != 32 {
		return nil, fmt.Errorf("%w: private key is %d bytes, want 32", ErrBadKey, len(cfg.StaticPrivate))
	}
	if cfg.MaxPayload < minMaxPayload || cfg.MaxPayload > maxMaxPayload {
		return nil, fmt.Errorf("%w: max payload %d out of [%d,%d]", ErrRecordTooLarge, cfg.MaxPayload, minMaxPayload, maxMaxPayload)
	}

	if err := conn.SetDeadline(time.Now().Add(cfg.Timeout)); err != nil {
		return nil, fmt.Errorf("%w: set deadline: %v", ErrHandshakeFailed, err)
	}
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	public, err := publicFromPrivate(cfg.StaticPrivate)
	if err != nil {
		return nil, err
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:       noise.HandshakeXX,
		Initiator:     cfg.Role == RoleInitiator,
		StaticKeypair: noise.DHKey{Private: cfg.StaticPrivate, Public: public},
	})
	if err != nil {
		return nil, fmt.Errorf("%w: init: %v", ErrHandshakeFailed, err)
	}

	var csRead, csWrite *noise.CipherState
	var peer []byte

	if cfg.Role == RoleInitiator {
		// -> e
		m1, _, _, err := hs.WriteMessage(nil, nil)
		if err != nil {
			return nil, fmt.Errorf("%w: msg1: %v", ErrHandshakeFailed, err)
		}
		if err := sendFrame(conn, m1); err != nil {
			return nil, fmt.Errorf("%w: send msg1: %v", ErrHandshakeFailed, err)
		}
		// <- e, ee, s, es ; payload = responder static
		m2, err := recvFrame(conn)
		if err != nil {
			return nil, fmt.Errorf("%w: recv msg2: %v", ErrHandshakeFailed, err)
		}
		peerPayload, _, _, err := hs.ReadMessage(nil, m2)
		if err != nil {
			return nil, fmt.Errorf("%w: read msg2: %v", ErrHandshakeFailed, err)
		}
		peer = peerPayload
		// -> s, se ; payload = initiator static ; returns final cipher states
		m3, cs0, cs1, err := hs.WriteMessage(nil, public)
		if err != nil {
			return nil, fmt.Errorf("%w: msg3: %v", ErrHandshakeFailed, err)
		}
		if err := sendFrame(conn, m3); err != nil {
			return nil, fmt.Errorf("%w: send msg3: %v", ErrHandshakeFailed, err)
		}
		csWrite, csRead = cs0, cs1
	} else {
		// <- e
		m1, err := recvFrame(conn)
		if err != nil {
			return nil, fmt.Errorf("%w: recv msg1: %v", ErrHandshakeFailed, err)
		}
		if _, _, _, err := hs.ReadMessage(nil, m1); err != nil {
			return nil, fmt.Errorf("%w: read msg1: %v", ErrHandshakeFailed, err)
		}
		// <- e, ee, s, es ; payload = responder static
		m2, _, _, err := hs.WriteMessage(nil, public)
		if err != nil {
			return nil, fmt.Errorf("%w: msg2: %v", ErrHandshakeFailed, err)
		}
		if err := sendFrame(conn, m2); err != nil {
			return nil, fmt.Errorf("%w: send msg2: %v", ErrHandshakeFailed, err)
		}
		// -> s, se ; payload = initiator static ; final cipher states here
		m3, err := recvFrame(conn)
		if err != nil {
			return nil, fmt.Errorf("%w: recv msg3: %v", ErrHandshakeFailed, err)
		}
		peerPayload, cs0, cs1, err := hs.ReadMessage(nil, m3)
		if err != nil {
			return nil, fmt.Errorf("%w: read msg3: %v", ErrHandshakeFailed, err)
		}
		peer = peerPayload
		csWrite, csRead = cs1, cs0
	}

	if len(peer) != 32 {
		return nil, fmt.Errorf("%w: remote static payload is %d bytes, want 32", ErrHandshakeFailed, len(peer))
	}
	if cfg.PinnedPeer != nil && !pinnedEqual(peer, cfg.PinnedPeer) {
		return nil, ErrPeerMismatch
	}

	hash := hs.ChannelBinding() // the Noise handshake hash per SPEC §2.4
	return &HandshakeResult{
		Conn:       newSecureConn(conn, csRead, csWrite, cfg.MaxPayload),
		SAS:        ShortAuthString(hash),
		PeerStatic: append([]byte(nil), peer...),
	}, nil
}

// ShortAuthString derives the 6-digit SAS displayed on both ends during
// first pairing (SPEC §2.4). Exported for the vector generator and CLIs.
func ShortAuthString(handshakeHash []byte) string {
	h := sha256.New()
	h.Write([]byte(sasDomain))
	h.Write(handshakeHash)
	sum := h.Sum(nil)
	code := binary.BigEndian.Uint32(sum[:4]) % 1_000_000
	return fmt.Sprintf("%06d", code)
}

// sendFrame/recvFrame implement the 2-byte handshake framing (SPEC §2.2).
func sendFrame(conn net.Conn, msg []byte) error {
	if len(msg) > handshakeMaxMessage {
		return fmt.Errorf("%w: message too large", ErrHandshakeFailed)
	}
	var hdr [handshakeHeaderSize]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(msg)))
	if _, err := conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err := conn.Write(msg)
	return err
}

func recvFrame(conn net.Conn) ([]byte, error) {
	var hdr [handshakeHeaderSize]byte
	if _, err := readFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint16(hdr[:])
	if size == 0 {
		return nil, fmt.Errorf("%w: empty handshake message", ErrHandshakeFailed)
	}
	msg := make([]byte, size)
	if _, err := readFull(conn, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// publicFromPrivate derives the X25519 public key. crypto/ecdh guarantees the
// same clamping/encoding as the noise library's DH25519.
func publicFromPrivate(priv []byte) ([]byte, error) {
	key, err := ecdhFromPrivate(priv)
	if err != nil {
		return nil, err
	}
	return key.PublicKey().Bytes(), nil
}

// pinnedEqual is a constant-time comparison for pinned peer keys.
func pinnedEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
