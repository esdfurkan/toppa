// Package failsafe implements the mutation journal and rollback policy
// (docs/ARCHITECTURE.md §3.4): every stateful system change (routes, DNS,
// adapter creation, proxy settings) is journaled BEFORE it is applied, and
// every path — graceful stop, crash + restart reconciliation, or explicit
// rollback — funnels through the same undo commands.
package failsafe

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry states.
const (
	StatePending    = "pending"
	StateApplied    = "applied"
	StateRolledBack = "rolledback"
)

// Entry is one journaled mutation. Apply is informational (what was/will be
// run); Undo is the exact command list executed to revert it.
type Entry struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	Apply       []string  `json:"apply"`
	Undo        []string  `json:"undo"`
	State       string    `json:"state"`
	CreatedAt   time.Time `json:"created_at"`
}

// Journal is a file-backed, append-first mutation log.
type Journal struct {
	path string

	mu      sync.Mutex
	entries []Entry
}

// Open loads the journal at path (parent directory created if needed).
func Open(path string) (*Journal, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("failsafe: mkdir: %w", err)
	}
	j := &Journal{path: path}
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(raw, &j.entries); err != nil {
			return nil, fmt.Errorf("failsafe: parse %s: %w", path, err)
		}
	case os.IsNotExist(err):
		// fresh journal
	default:
		return nil, fmt.Errorf("failsafe: read %s: %w", path, err)
	}
	return j, nil
}

// Add records a pending mutation durably BEFORE it is applied.
func (j *Journal) Add(description string, apply, undo []string) (Entry, error) {
	entry := Entry{
		ID:          newID(),
		Description: description,
		Apply:       apply,
		Undo:        undo,
		State:       StatePending,
		CreatedAt:   time.Now().UTC(),
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.entries = append(j.entries, entry)
	if err := j.persist(); err != nil {
		return Entry{}, err
	}
	return entry, nil
}

// MarkState transitions an entry (pending→applied after success,
// *→rolledback after undo) and persists.
func (j *Journal) MarkState(id, state string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	for i := range j.entries {
		if j.entries[i].ID == id {
			j.entries[i].State = state
			return j.persist()
		}
	}
	return fmt.Errorf("failsafe: unknown entry %s", id)
}

// Outstanding returns every entry that still mutates the system (applied or
// pending) in application order.
func (j *Journal) Outstanding() []Entry {
	j.mu.Lock()
	defer j.mu.Unlock()
	var out []Entry
	for _, e := range j.entries {
		if e.State == StateApplied || e.State == StatePending {
			out = append(out, e)
		}
	}
	return out
}

// RollbackAll reverts all outstanding entries in REVERSE order via run, then
// marks them rolled back. Returns how many were rolled back.
func (j *Journal) RollbackAll(run func(e Entry) error) (int, error) {
	outstanding := j.Outstanding()
	rolled := 0
	var firstErr error
	for i := len(outstanding) - 1; i >= 0; i-- {
		e := outstanding[i]
		if err := run(e); err != nil && firstErr == nil {
			firstErr = err
			continue // keep rolling back the rest
		}
		if err := j.MarkState(e.ID, StateRolledBack); err != nil && firstErr == nil {
			firstErr = err
		}
		rolled++
	}
	return rolled, firstErr
}

func (j *Journal) persist() error {
	raw, err := json.MarshalIndent(j.entries, "", "  ")
	if err != nil {
		return fmt.Errorf("failsafe: encode: %w", err)
	}
	// Write-then-rename so a crash mid-write cannot truncate the journal.
	tmp := j.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("failsafe: write: %w", err)
	}
	if err := os.Rename(tmp, j.path); err != nil {
		return fmt.Errorf("failsafe: rename: %w", err)
	}
	return nil
}

func newID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
