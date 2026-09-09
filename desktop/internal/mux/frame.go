// Package mux implements TLMP v1 (Toppa Link Multiplexing Protocol) as
// specified in protocol/SPEC.md: frame codec, stream multiplexing with
// window-credit flow control, and the session control channel.
//
// Invariants:
//   - This package is transport-agnostic: it operates on any ordered,
//     reliable byte stream (typically the tunnel package's AEAD record layer).
//   - It never touches OS resources, DNS, or policy — protocol only.
//   - Flag/size validation is strict: violations are fatal to the session.
package mux

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ProtocolVersion is the TLMP wire version this package implements.
const ProtocolVersion uint8 = 1

// HeaderSize is the fixed TLMP frame header size in bytes.
const HeaderSize = 10

// Frame flags (protocol/SPEC.md §4.2).
const (
	FlagSYN    uint8 = 1 << iota // open a stream; payload = address block
	FlagFIN                      // sender will send no more DATA on the stream
	FlagRST                      // abort the stream; payload = 1-byte reason
	FlagWIN                      // WINDOW_UPDATE; payload = 4-byte BE credit
	FlagDATA                     // stream payload
	FlagPING                     // session keepalive; streamID must be 0
	FlagPONG                     // keepalive reply; streamID must be 0
	FlagGOAWAY                   // session teardown; payload = 1-byte reason
)

// GOAWAY / RST reason codes.
const (
	ReasonNormal   uint8 = 0
	ReasonProtocol uint8 = 1
	ReasonBusy     uint8 = 2
	ReasonDupStream uint8 = 2 // RST reason: duplicate SYN for a live stream
)

// Errors.
var (
	ErrVersion      = errors.New("mux: unsupported protocol version")
	ErrFrameTooLarge = errors.New("mux: frame payload exceeds maximum")
)

// Frame is a decoded TLMP frame.
type Frame struct {
	Version  uint8
	Flags    uint8
	StreamID uint32
	Payload  []byte
}

// WriteFrame encodes f and writes it to w. maxPayload mirrors the session's
// negotiated cap; larger payloads are rejected locally instead of corrupting
// the peer.
func WriteFrame(w io.Writer, f *Frame, maxPayload uint32) error {
	if f.Version != ProtocolVersion {
		return fmt.Errorf("%w: %d", ErrVersion, f.Version)
	}
	if uint32(len(f.Payload)) > maxPayload {
		return fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, len(f.Payload), maxPayload)
	}
	var hdr [HeaderSize]byte
	hdr[0] = ProtocolVersion
	hdr[1] = f.Flags
	binary.BigEndian.PutUint32(hdr[2:6], f.StreamID)
	binary.BigEndian.PutUint32(hdr[6:10], uint32(len(f.Payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(f.Payload) > 0 {
		_, err := w.Write(f.Payload)
		return err
	}
	return nil
}

// AppendFrame encodes f onto dst and returns the extended slice. It performs
// the same validation as WriteFrame and exists for tests and vector
// generation.
func AppendFrame(dst []byte, f *Frame, maxPayload uint32) ([]byte, error) {
	if f.Version != ProtocolVersion {
		return dst, fmt.Errorf("%w: %d", ErrVersion, f.Version)
	}
	if uint32(len(f.Payload)) > maxPayload {
		return dst, fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, len(f.Payload), maxPayload)
	}
	var hdr [HeaderSize]byte
	hdr[0] = ProtocolVersion
	hdr[1] = f.Flags
	binary.BigEndian.PutUint32(hdr[2:6], f.StreamID)
	binary.BigEndian.PutUint32(hdr[6:10], uint32(len(f.Payload)))
	dst = append(dst, hdr[:]...)
	return append(dst, f.Payload...), nil
}

// ReadFrame reads exactly one frame from r. The returned Frame is valid until
// the next call on the same Session-owned reader path; callers that retain the
// payload must copy it.
func ReadFrame(r io.Reader, maxPayload uint32) (*Frame, error) {
	var hdr [HeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != ProtocolVersion {
		return nil, fmt.Errorf("%w: %d", ErrVersion, hdr[0])
	}
	f := &Frame{
		Version:  hdr[0],
		Flags:    hdr[1],
		StreamID: binary.BigEndian.Uint32(hdr[2:6]),
	}
	size := binary.BigEndian.Uint32(hdr[6:10])
	if size > maxPayload {
		return nil, fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, size, maxPayload)
	}
	if size > 0 {
		f.Payload = make([]byte, size)
		if _, err := io.ReadFull(r, f.Payload); err != nil {
			return nil, err
		}
	}
	if err := validateFrame(f); err != nil {
		return nil, err
	}
	return f, nil
}

// validateFrame enforces the per-flag structural rules from SPEC §4.2.
func validateFrame(f *Frame) error {
	if f.Flags&FlagSYN != 0 && f.Flags&FlagDATA != 0 {
		return fmt.Errorf("%w: SYN combined with DATA", ErrProtocol)
	}
	if f.Flags&(FlagPING|FlagPONG|FlagGOAWAY) != 0 && f.StreamID != 0 {
		return fmt.Errorf("%w: control frame carries stream id %d", ErrProtocol, f.StreamID)
	}
	if f.Flags&FlagWIN != 0 && len(f.Payload) != 4 {
		return fmt.Errorf("%w: WIN payload must be exactly 4 bytes, got %d", ErrProtocol, len(f.Payload))
	}
	if f.Flags&FlagRST != 0 && len(f.Payload) != 1 {
		return fmt.Errorf("%w: RST payload must be exactly 1 byte, got %d", ErrProtocol, len(f.Payload))
	}
	if f.Flags&FlagGOAWAY != 0 && len(f.Payload) != 1 {
		return fmt.Errorf("%w: GOAWAY payload must be exactly 1 byte, got %d", ErrProtocol, len(f.Payload))
	}
	if f.Flags&^(FlagSYN|FlagFIN|FlagRST|FlagWIN|FlagDATA|FlagPING|FlagPONG|FlagGOAWAY) != 0 {
		return fmt.Errorf("%w: unknown flag bits 0x%02x", ErrProtocol, f.Flags)
	}
	return nil
}
