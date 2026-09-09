module github.com/esdfurkan/toppa/desktop

go 1.27

require github.com/flynn/noise v1.1.0

require (
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2 // indirect
	golang.org/x/sys v0.0.0-20201119102817-f84b799fce68 // indirect
)

// Step 3 addition (Wintun driver bindings). `go mod tidy` (network) must run
// once so go.sum and transitive requirements resolve.
require golang.zx2c4.com/wintun v0.0.0-20230104170424-64e6f66f274b

// gvisor.dev/gvisor is imported by internal/netstack; let `go mod tidy` pick
// the exact version so the API snapshot matches what we compile against.
