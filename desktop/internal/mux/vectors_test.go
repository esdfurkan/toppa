package mux

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// vectorsDir points at the repository-wide protocol/vectors directory from
// this package's location (desktop/internal/mux).
var vectorsDir = filepath.Join("..", "..", "..", "protocol", "vectors")

func loadVectors(t *testing.T, name string, v any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorsDir, name))
	if errors.Is(err, os.ErrNotExist) {
		t.Skipf("golden vectors not found (%s); full repository checkout required", name)
	}
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
}

type framesVectorFile struct {
	Protocol string      `json:"protocol"`
	Version  int         `json:"version"`
	Cases    []frameCase `json:"cases"`
}

type frameCase struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Reason     string `json:"reason"`
	MaxPayload uint32 `json:"maxPayload"`
	Version    int    `json:"version"`
	Flags      int    `json:"flags"`
	StreamID   uint32 `json:"streamId"`
	PayloadHex string `json:"payloadHex"`
	EncodedHex string `json:"encodedHex"`
}

// frameReasonSentinel maps a vector rejection reason to the exported sentinel
// the implementation must classify the error as.
func frameReasonSentinel(reason string) error {
	switch reason {
	case "unsupported_version":
		return ErrVersion
	case "frame_too_large":
		return ErrFrameTooLarge
	default:
		return ErrProtocol
	}
}

func TestFramesGoldenVectors(t *testing.T) {
	var vf framesVectorFile
	loadVectors(t, "frames.json", &vf)
	for _, c := range vf.Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			encoded, err := hex.DecodeString(c.EncodedHex)
			if err != nil {
				t.Fatalf("bad vector hex: %v", err)
			}
			got, err := ReadFrame(bytes.NewReader(encoded), c.MaxPayload)
			if c.Kind == "error" {
				if err == nil {
					t.Fatalf("expected error %q, decoded a valid frame instead", c.Reason)
				}
				if !errors.Is(err, frameReasonSentinel(c.Reason)) {
					t.Fatalf("expected %q-class error, got: %v", c.Reason, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadFrame rejected a valid frame: %v", err)
			}
			if got.Version != uint8(c.Version) || got.Flags != uint8(c.Flags) || got.StreamID != c.StreamID {
				t.Fatalf("header mismatch: got (v%d flags=0x%02x id=%d)", got.Version, got.Flags, got.StreamID)
			}
			wantPayload, err := hex.DecodeString(c.PayloadHex)
			if err != nil {
				t.Fatalf("bad payload hex: %v", err)
			}
			if !bytes.Equal(got.Payload, wantPayload) {
				t.Fatalf("payload mismatch: got %x want %x", got.Payload, wantPayload)
			}
			var buf bytes.Buffer
			if err := WriteFrame(&buf, got, c.MaxPayload); err != nil {
				t.Fatalf("WriteFrame: %v", err)
			}
			if !bytes.Equal(buf.Bytes(), encoded) {
				t.Fatal("re-encode mismatch")
			}
		})
	}
}

type targetsVectorFile struct {
	Protocol string      `json:"protocol"`
	Version  int         `json:"version"`
	Cases    []targetCase `json:"cases"`
}

type targetCase struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Network    string `json:"network"`
	ATYP       string `json:"atyp"`
	Host       string `json:"host"`
	Port       uint16 `json:"port"`
	EncodedHex string `json:"encodedHex"`
}

func TestTargetsGoldenVectors(t *testing.T) {
	var vf targetsVectorFile
	loadVectors(t, "targets.json", &vf)
	for _, c := range vf.Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			raw, err := hex.DecodeString(c.EncodedHex)
			if err != nil {
				t.Fatalf("bad vector hex: %v", err)
			}
			got, err := ParseTarget(raw)
			if c.Kind == "error" {
				if err == nil {
					t.Fatal("expected rejection, decoded a valid target instead")
				}
				if !errors.Is(err, ErrBadTarget) {
					t.Fatalf("expected ErrBadTarget, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTarget rejected a valid target: %v", err)
			}
			var wantNetwork uint8
			switch c.Network {
			case "tcp":
				wantNetwork = NetTCP
			case "udp":
				wantNetwork = NetUDP
			default:
				t.Fatalf("bad vector network %q", c.Network)
			}
			var wantATYP uint8
			var wantAddr []byte
			switch c.ATYP {
			case "ipv4":
				wantATYP = ATYPIPv4
				wantAddr = net.ParseIP(c.Host).To4()
			case "ipv6":
				wantATYP = ATYPIPv6
				wantAddr = net.ParseIP(c.Host).To16()
			case "fqdn":
				wantATYP = ATYPFQDN
				wantAddr = []byte(c.Host)
			default:
				t.Fatalf("bad vector atyp %q", c.ATYP)
			}
			if got.Network != wantNetwork || got.ATYP != wantATYP || got.Port != c.Port || !bytes.Equal(got.Address, wantAddr) {
				t.Fatalf("target mismatch: got %+v", got)
			}
			if !bytes.Equal(AppendTarget(nil, got), raw) {
				t.Fatal("re-encode mismatch")
			}
		})
	}
}
