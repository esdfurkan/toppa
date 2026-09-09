package obfuscation

import (
	"bytes"
	"testing"
)

func TestSettingsForProfiles(t *testing.T) {
	if s := SettingsFor(ProfileNone); s.PaddingInterval != 0 {
		t.Fatal("none profile must disable padding")
	}
	if s := SettingsFor(ProfileLight); s.PaddingInterval == 0 || s.PaddingMaxBytes == 0 {
		t.Fatal("light profile must pad")
	}
	if s := SettingsFor(ProfileParanoid); s.PaddingMaxBytes <= SettingsFor(ProfileLight).PaddingMaxBytes {
		t.Fatal("paranoid must pad more than light")
	}
	// Unknown profiles resolve to none (fail-open to no padding, never crash).
	if s := SettingsFor("bogus"); s.PaddingInterval != 0 {
		t.Fatal("unknown profile must resolve to none")
	}
}

func TestRandomPaddingBounds(t *testing.T) {
	sawNonZero := false
	for i := 0; i < 200; i++ {
		pad := randomPadding(300)
		if len(pad) > 300 {
			t.Fatalf("padding %d exceeds max 300", len(pad))
		}
		if len(pad) > 0 {
			sawNonZero = true
		}
	}
	if !sawNonZero {
		t.Fatal("random padding never produced a payload in 200 draws")
	}
	if pad := randomPadding(0); pad != nil {
		t.Fatal("max=0 must produce no padding")
	}
}

func TestPaddingIsRandomNotConstant(t *testing.T) {
	a := randomPadding(2048)
	b := randomPadding(2048)
	if bytes.Equal(a, b) && len(a) > 0 {
		t.Fatal("two consecutive paddings were identical")
	}
}
