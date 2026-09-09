package tunnel

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/flynn/noise"
)

// SecureConn is the AEAD record layer (protocol/SPEC.md §3): each record is a
// 3-byte big-endian ciphertext length followed by a ChaCha20-Poly1305
// ciphertext. It satisfies net.Conn so the mux can ride it unchanged.
//
// Nonces are managed by the noise CipherState: one counter per direction,
// starting at 0 and incremented once per record — exactly the semantics of
// SPEC §2.5.
type SecureConn struct {
	conn net.Conn

	readCS  *noise.CipherState
	writeCS *noise.CipherState

	maxPayload uint32
	rbuf       []byte // decrypted bytes not yet consumed by the caller
}

func newSecureConn(conn net.Conn, readCS, writeCS *noise.CipherState, maxPayload uint32) *SecureConn {
	return &SecureConn{conn: conn, readCS: readCS, writeCS: writeCS, maxPayload: maxPayload}
}

// Write encrypts b in records of at most MaxPayload plaintext bytes.
func (c *SecureConn) Write(b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n := len(b) - total
		if uint32(n) > c.maxPayload {
			n = int(c.maxPayload)
		}
		ct, err := c.writeCS.Encrypt(nil, nil, b[total:total+n])
		if err != nil {
			return total, err
		}
		var hdr [recordHeaderSize]byte
		// 24-bit length; the maxPayload cap keeps this well within range.
		hdr[0] = byte(len(ct) >> 16)
		hdr[1] = byte(len(ct) >> 8)
		hdr[2] = byte(len(ct))
		if _, err := c.conn.Write(hdr[:]); err != nil {
			return total, err
		}
		if _, err := c.conn.Write(ct); err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// Read decrypts the next record (or drains a partially consumed one) into p.
func (c *SecureConn) Read(p []byte) (int, error) {
	if len(c.rbuf) > 0 {
		n := copy(p, c.rbuf)
		c.rbuf = c.rbuf[n:]
		return n, nil
	}
	if len(p) == 0 {
		return 0, nil
	}
	var hdr [recordHeaderSize]byte
	if _, err := io.ReadFull(c.conn, hdr[:]); err != nil {
		return 0, err
	}
	size := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
	if size < recordOverhead || size > int(c.maxPayload)+recordOverhead {
		return 0, fmt.Errorf("%w: record size %d", ErrRecordTooLarge, size)
	}
	ct := make([]byte, size)
	if _, err := io.ReadFull(c.conn, ct); err != nil {
		return 0, err
	}
	pt, err := c.readCS.Decrypt(nil, nil, ct)
	if err != nil {
		return 0, fmt.Errorf("tunnel: record authentication failed: %w", err)
	}
	n := copy(p, pt)
	if n < len(pt) {
		c.rbuf = append(c.rbuf, pt[n:]...)
	}
	return n, nil
}

// Close closes the underlying transport.
func (c *SecureConn) Close() error { return c.conn.Close() }

// LocalAddr/RemoteAddr forward to the transport for logging.
func (c *SecureConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *SecureConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// Deadline setters forward to the transport.
func (c *SecureConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *SecureConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *SecureConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// ecdhFromPrivate reconstructs a crypto/ecdh key from raw X25519 bytes.
func ecdhFromPrivate(priv []byte) (*ecdh.PrivateKey, error) {
	key, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("%w: bad x25519 private key: %v", ErrBadKey, err)
	}
	return key, nil
}

// GenerateIdentity produces a fresh keypair for callers that need ephemeral
// test identities.
func GenerateIdentity() (priv, pub []byte, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return k.Bytes(), k.PublicKey().Bytes(), nil
}
