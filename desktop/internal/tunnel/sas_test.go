package tunnel

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type sasVectorFile struct {
	Protocol string    `json:"protocol"`
	Version  int       `json:"version"`
	Cases    []sasCase `json:"cases"`
}

type sasCase struct {
	Name             string `json:"name"`
	HandshakeHashHex string `json:"handshakeHashHex"`
	Sas              string `json:"sas"`
}

func TestSASGoldenVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "protocol", "vectors", "sas.json"))
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("golden vectors not found; full repository checkout required")
	}
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vf sasVectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	for _, c := range vf.Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			hash, err := hex.DecodeString(c.HandshakeHashHex)
			if err != nil {
				t.Fatalf("bad vector hex: %v", err)
			}
			if len(hash) != 32 {
				t.Fatalf("handshake hash must be 32 bytes, got %d", len(hash))
			}
			if got := ShortAuthString(hash); got != c.Sas {
				t.Fatalf("SAS mismatch: got %s want %s", got, c.Sas)
			}
		})
	}
}
