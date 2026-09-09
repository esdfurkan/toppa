package failsafe

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestJournalAppendAndRollbackOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.json")
	j, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}

	// Two mutations, applied in order; rollback must run in REVERSE order.
	var applied []string
	for _, m := range []struct{ desc, undo string }{
		{"route 0/0", "undo-route"},
		{"dns rewrite", "undo-dns"},
	} {
		if _, err := j.Add(m.desc, []string{"apply-" + m.undo}, []string{m.undo}); err != nil {
			t.Fatal(err)
		}
		applied = append(applied, m.undo)
	}
	for _, e := range j.Outstanding() {
		if err := j.MarkState(e.ID, StateApplied); err != nil {
			t.Fatal(err)
		}
	}

	var undoOrder []string
	rolled, err := j.RollbackAll(func(e Entry) error {
		undoOrder = append(undoOrder, e.Undo...)
		return nil
	})
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if rolled != 2 {
		t.Fatalf("rolled back %d entries, want 2", rolled)
	}
	if len(undoOrder) != 2 || undoOrder[0] != "undo-dns" || undoOrder[1] != "undo-route" {
		t.Fatalf("rollback order wrong: %v", undoOrder)
	}
	if len(j.Outstanding()) != 0 {
		t.Fatalf("outstanding entries remain: %d", len(j.Outstanding()))
	}
}

func TestJournalSurvivesCrashAndReconciles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.json")

	// "Process" 1: journal a mutation, apply it, then "crash" (never mark or
	// roll back — the journal still holds it as applied).
	j1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := j1.Add("route 0/0", []string{"route add"}, []string{"route del"})
	if err != nil {
		t.Fatal(err)
	}
	if err := j1.MarkState(entry.ID, StateApplied); err != nil {
		t.Fatal(err)
	}

	// "Process" 2 (restart): reconcile must surface the leftover.
	j2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	outstanding := j2.Outstanding()
	if len(outstanding) != 1 || outstanding[0].ID != entry.ID {
		t.Fatalf("restart lost the leftover mutation: %+v", outstanding)
	}
	rolled, err := j2.RollbackAll(func(e Entry) error { return nil })
	if err != nil || rolled != 1 {
		t.Fatalf("reconcile rollback: rolled=%d err=%v", rolled, err)
	}

	// A third open sees a clean journal.
	j3, _ := Open(path)
	if len(j3.Outstanding()) != 0 {
		t.Fatal("journal not clean after reconcile")
	}
}

func TestJournalRollbackContinuesOnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.json")
	j, _ := Open(path)
	for i := 0; i < 3; i++ {
		j.Add("m", []string{"a"}, []string{"u"})
	}
	var attempts int
	_, err := j.RollbackAll(func(e Entry) error {
		attempts++
		if attempts == 2 {
			return errors.New("boom") // middle undo fails
		}
		return nil
	})
	if err == nil {
		t.Fatal("expected the failing undo to surface")
	}
	if attempts != 3 {
		t.Fatalf("rollback must continue past failures; ran %d undos", attempts)
	}
}
