//go:build !windows

package adapter

import "fmt"

// DeleteAdapter is a no-op off Windows (no adapter ever existed).
func DeleteAdapter(name string) error { return nil }

// Open refuses cleanly on non-Windows platforms so the rest of the module
// (netstack, daemon logic) still builds and unit-tests on Linux CI. The
// loopback pair (loopback.go) is the TunDevice for those tests.
func Open(cfg Config) (TunDevice, error) {
	return nil, fmt.Errorf("adapter: the Wintun device requires Windows (use NewLoopbackPair in tests)")
}
