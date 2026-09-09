// Package keys persists the local Noise static identity and pinned peer keys.
//
// v1 storage is permission-restricted JSON under the configured key directory
// (config.KeysDir / ResolveKeysDir). Windows DPAPI wrapping of the private
// key is planned for the Step 3 packaging milestone; until then this store
// must never live inside a synced or shared folder — CONTRIBUTING.md notes
// that key files are gitignored.
package keys

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Identity is the local Noise static keypair (X25519, compatible with Noise
// DH25519 key encoding).
type Identity struct {
	Private []byte `json:"private"`
	Public  []byte `json:"public"`
}

// pinnedPeer is the on-disk shape of a pinned remote static key.
type pinnedPeer struct {
	Public   []byte    `json:"public"`
	PinnedAt time.Time `json:"pinned_at"`
}

// Store is a file-backed key store rooted at dir.
type Store struct {
	dir string
}

// NewStore creates the key directory (mode 0700) if needed.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("keys: create %s: %w", dir, err)
	}
	return &Store{dir: dir}, nil
}

// Identity loads the local identity, generating and persisting a new one on
// first use.
func (s *Store) Identity() (*Identity, error) {
	path := filepath.Join(s.dir, "identity.json")
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		var id Identity
		if err := json.Unmarshal(raw, &id); err != nil {
			return nil, fmt.Errorf("keys: parse %s: %w", path, err)
		}
		if len(id.Private) != 32 || len(id.Public) != 32 {
			return nil, fmt.Errorf("keys: %s has corrupt key lengths", path)
		}
		return &id, nil
	case errors.Is(err, os.ErrNotExist):
		id, genErr := generate()
		if genErr != nil {
			return nil, genErr
		}
		if saveErr := s.SaveIdentity(id); saveErr != nil {
			return nil, saveErr
		}
		return id, nil
	default:
		return nil, fmt.Errorf("keys: read %s: %w", path, err)
	}
}

// SaveIdentity persists id with owner-only permissions.
func (s *Store) SaveIdentity(id *Identity) error {
	return s.writeJSON("identity.json", id)
}

// PinPeer records the verified remote static key under name. Call only after
// the user has visually confirmed the SAS (see protocol/SPEC.md §2.4).
func (s *Store) PinPeer(name string, public []byte) error {
	if len(public) != 32 {
		return fmt.Errorf("keys: peer public key must be 32 bytes, got %d", len(public))
	}
	return s.writeJSON("peer-"+name+".json", pinnedPeer{Public: public, PinnedAt: time.Now().UTC()})
}

// PinnedPeer returns the pinned key for name, and whether one exists.
func (s *Store) PinnedPeer(name string) ([]byte, bool, error) {
	raw, err := os.ReadFile(filepath.Join(s.dir, "peer-"+name+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("keys: read pinned peer: %w", err)
	}
	var p pinnedPeer
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, false, fmt.Errorf("keys: parse pinned peer: %w", err)
	}
	return p.Public, true, nil
}

func (s *Store) writeJSON(name string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("keys: encode %s: %w", name, err)
	}
	path := filepath.Join(s.dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("keys: write %s: %w", path, err)
	}
	return nil
}

// generate creates a fresh X25519 keypair. crypto/ecdh is used (rather than
// the noise library's DH type) so this package has no protocol dependency;
// the encoding is identical.
func generate() (*Identity, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("keys: generate x25519: %w", err)
	}
	return &Identity{Private: k.Bytes(), Public: k.PublicKey().Bytes()}, nil
}
