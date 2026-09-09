// Package adapter owns the virtual adapter lifecycle (roadmap Step 3).
//
// Invariants:
//   - The only package in the desktop tree that touches driver APIs; the
//     Windows implementation is isolated in tun_windows.go, and other GOOS
//     values get a factory that refuses cleanly (CI builds and unit-tests
//     the rest of the module on Linux).
//   - wintun.dll must sit next to the executable and the process must run
//     elevated to create adapters or mutate routes.
package adapter

// Event reported by adapters that support asynchronous state changes.
type Event int

const (
	EventUp Event = iota
	EventDown
)

// TunDevice is the L3 packet interface the netstack reads and writes.
// Read/Write operate on full IP packets (no link header on Wintun).
type TunDevice interface {
	Name() string
	MTU() int
	// Read blocks until a packet arrives, copies it into packet, and returns
	// its length. Returns an error when the device is closed.
	Read(packet []byte) (int, error)
	Write(packet []byte) (int, error)
	Close() error
}

// Config for Open. RingCapacity is the Wintun session ring in bytes; the
// default suits >1 Gbps and is a driver-level constant, not an operational
// setting.
type Config struct {
	Name         string
	MTU          int
	RingCapacity uint32
	Logf         func(format string, args ...any)
}
