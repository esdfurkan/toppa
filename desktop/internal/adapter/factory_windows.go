//go:build windows

package adapter

// Open returns the platform TUN device (Wintun on Windows).
func Open(cfg Config) (TunDevice, error) {
	return NewWintun(cfg)
}
