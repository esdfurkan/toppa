// Command vectorgen regenerates protocol/vectors/{frames,targets,sas}.json
// after a protocol change:
//
//	cd desktop && go run ./cmd/vectorgen -out ../protocol/vectors
//
// The generator is the mechanical source for frame/target cases (built from
// the mux package types) and SAS values (via tunnel.ShortAuthString). The
// committed vector files are kept in sync with this output; tests consume
// the JSON semantically, so cosmetic formatting differences between
// hand-edited and generated files are harmless.
package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/esdfurkan/toppa/desktop/internal/mux"
	"github.com/esdfurkan/toppa/desktop/internal/tunnel"
)

type frameCase struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Reason     string `json:"reason,omitempty"`
	MaxPayload uint32 `json:"maxPayload"`
	Version    int    `json:"version"`
	Flags      int    `json:"flags"`
	StreamID   uint32 `json:"streamId"`
	PayloadHex string `json:"payloadHex,omitempty"`
	EncodedHex string `json:"encodedHex"`
}

type framesFile struct {
	Protocol string      `json:"protocol"`
	Version  int         `json:"version"`
	Cases    []frameCase `json:"cases"`
}

type targetCase struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Network    string `json:"network,omitempty"`
	ATYP       string `json:"atyp,omitempty"`
	Host       string `json:"host,omitempty"`
	Port       uint16 `json:"port,omitempty"`
	EncodedHex string `json:"encodedHex"`
}

type targetsFile struct {
	Protocol string       `json:"protocol"`
	Version  int          `json:"version"`
	Cases    []targetCase `json:"cases"`
}

type sasCase struct {
	Name             string `json:"name"`
	HandshakeHashHex string `json:"handshakeHashHex"`
	Sas              string `json:"sas"`
}

type sasFile struct {
	Protocol string    `json:"protocol"`
	Version  int       `json:"version"`
	Cases    []sasCase `json:"cases"`
}

func main() {
	out := flag.String("out", filepath.Join("..", "protocol", "vectors"), "output directory")
	flag.Parse()
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fatal(err)
	}
	writeJSON(filepath.Join(*out, "frames.json"), buildFrames())
	writeJSON(filepath.Join(*out, "targets.json"), buildTargets())
	writeJSON(filepath.Join(*out, "sas.json"), buildSAS())
	fmt.Printf("vectorgen: wrote frames.json, targets.json, sas.json to %s\n", *out)
}

func validFrame(name string, f *mux.Frame, maxPayload uint32) frameCase {
	encoded, err := mux.AppendFrame(nil, f, maxPayload)
	if err != nil {
		fatal(fmt.Errorf("valid frame %s: %w", name, err))
	}
	return frameCase{
		Name:       name,
		Kind:       "valid",
		MaxPayload: maxPayload,
		Version:    int(f.Version),
		Flags:      int(f.Flags),
		StreamID:   f.StreamID,
		PayloadHex: hex.EncodeToString(f.Payload),
		EncodedHex: hex.EncodeToString(encoded),
	}
}

// rawErrorFrame assembles a frame the mux must reject; AppendFrame cannot
// build these because they violate the validation rules under test.
func rawErrorFrame(name, reason string, maxPayload uint32, version, flags int, streamID uint32, payloadHex string) frameCase {
	payload, err := hex.DecodeString(payloadHex)
	if err != nil {
		fatal(err)
	}
	header := make([]byte, 10)
	header[0] = byte(version)
	header[1] = byte(flags)
	binary.BigEndian.PutUint32(header[2:6], streamID)
	binary.BigEndian.PutUint32(header[6:10], uint32(len(payload)))
	return frameCase{
		Name:       name,
		Kind:       "error",
		Reason:     reason,
		MaxPayload: maxPayload,
		EncodedHex: hex.EncodeToString(append(header, payload...)),
	}
}

func buildFrames() framesFile {
	const max = 65536
	cases := []frameCase{
		validFrame("data_simple", &mux.Frame{Version: 1, Flags: mux.FlagDATA, StreamID: 1, Payload: []byte("hello tlmp")}, max),
		validFrame("syn_fqdn", &mux.Frame{Version: 1, Flags: mux.FlagSYN, StreamID: 3, Payload: mux.AppendTarget(nil, mustFQDN("example.com", 443))}, max),
		validFrame("syn_ipv4", &mux.Frame{Version: 1, Flags: mux.FlagSYN, StreamID: 5, Payload: mux.AppendTarget(nil, mux.TCPv4([4]byte{192, 168, 1, 1}, 8080))}, max),
		validFrame("syn_ipv6", &mux.Frame{Version: 1, Flags: mux.FlagSYN, StreamID: 7, Payload: mux.AppendTarget(nil, mux.Target{Network: mux.NetTCP, ATYP: mux.ATYPIPv6, Address: fd00One(), Port: 53})}, max),
		validFrame("win_update", &mux.Frame{Version: 1, Flags: mux.FlagWIN, StreamID: 9, Payload: []byte{0x00, 0x01, 0x00, 0x00}}, max),
		validFrame("fin", &mux.Frame{Version: 1, Flags: mux.FlagFIN, StreamID: 11}, max),
		validFrame("rst", &mux.Frame{Version: 1, Flags: mux.FlagRST, StreamID: 13, Payload: []byte{mux.ReasonBusy}}, max),
		validFrame("ping", &mux.Frame{Version: 1, Flags: mux.FlagPING, Payload: []byte{1, 2, 3, 4, 5, 6, 7, 8}}, max),
		validFrame("pong", &mux.Frame{Version: 1, Flags: mux.FlagPONG, Payload: []byte{1, 2, 3, 4, 5, 6, 7, 8}}, max),
		validFrame("goaway", &mux.Frame{Version: 1, Flags: mux.FlagGOAWAY, Payload: []byte{mux.ReasonNormal}}, max),
		validFrame("data_high_stream_id", &mux.Frame{Version: 1, Flags: mux.FlagDATA, StreamID: 65535, Payload: []byte{0xaa}}, max),
		rawErrorFrame("reject_unsupported_version", "unsupported_version", max, 2, int(mux.FlagDATA), 1, ""),
		rawErrorFrame("reject_frame_too_large", "frame_too_large", 4, 1, int(mux.FlagDATA), 1, "aabbccddee"),
		rawErrorFrame("reject_ping_with_stream_id", "control_stream_id", max, 1, int(mux.FlagPING), 4, "0000000000000000"),
		rawErrorFrame("reject_win_short_payload", "win_payload_size", max, 1, int(mux.FlagWIN), 1, "0001"),
		rawErrorFrame("reject_rst_short_payload", "rst_payload_size", max, 1, int(mux.FlagRST), 1, "0001"),
		rawErrorFrame("reject_goaway_with_stream_id", "control_stream_id", max, 1, int(mux.FlagGOAWAY), 7, "00"),
		rawErrorFrame("reject_syn_combined_with_data", "syn_with_data", max, 1, int(mux.FlagSYN|mux.FlagDATA), 1, ""),
	}
	return framesFile{Protocol: "TLMP", Version: 1, Cases: cases}
}

func mustFQDN(host string, port uint16) mux.Target {
	t, err := mux.TCPFQDN(host, port)
	if err != nil {
		fatal(err)
	}
	return t
}

func fd00One() []byte {
	addr := make([]byte, 16)
	addr[0] = 0xfd
	addr[15] = 0x01
	return addr
}

func buildTargets() targetsFile {
	cases := []targetCase{
		mustTarget("tcp_ipv4", mux.Target{Network: mux.NetTCP, ATYP: mux.ATYPIPv4, Address: []byte{192, 168, 1, 1}, Port: 8080}),
		mustTarget("tcp_fqdn", mustFQDN("example.com", 443)),
		mustTarget("udp_ipv6", mux.Target{Network: mux.NetUDP, ATYP: mux.ATYPIPv6, Address: fd00One(), Port: 53}),
		rawErrorTarget("reject_truncated", "0101"),
		rawErrorTarget("reject_bad_network", "0901c0a801011f90"),
		rawErrorTarget("reject_bad_atyp", "0107c0a801011f90"),
		rawErrorTarget("reject_empty_fqdn", "010300"),
		rawErrorTarget("reject_fqdn_length_lie", "01030561626301bb"),
		rawErrorTarget("reject_short_ipv4", "0101c0a801"),
	}
	return targetsFile{Protocol: "TLMP", Version: 1, Cases: cases}
}

func mustTarget(name string, t mux.Target) targetCase {
	return targetCase{
		Name:       name,
		Kind:       "valid",
		Network:    networkName(t.Network),
		ATYP:       atypName(t.ATYP),
		Host:       hostString(t),
		Port:       t.Port,
		EncodedHex: hex.EncodeToString(mux.AppendTarget(nil, t)),
	}
}

func rawErrorTarget(name, encodedHex string) targetCase {
	return targetCase{Name: name, Kind: "error", EncodedHex: encodedHex}
}

func networkName(n uint8) string {
	if n == mux.NetUDP {
		return "udp"
	}
	return "tcp"
}

func atypName(a uint8) string {
	switch a {
	case mux.ATYPIPv4:
		return "ipv4"
	case mux.ATYPIPv6:
		return "ipv6"
	default:
		return "fqdn"
	}
}

func hostString(t mux.Target) string {
	if t.ATYP == mux.ATYPFQDN {
		return string(t.Address)
	}
	return net.IP(t.Address).String()
}

func buildSAS() sasFile {
	hashes := []struct {
		name string
		hash []byte
	}{
		{"zero_hash", make([]byte, 32)},
		{"counting_hash", counting32()},
		{"ff_hash", ones32()},
	}
	cases := make([]sasCase, 0, len(hashes))
	for _, h := range hashes {
		cases = append(cases, sasCase{
			Name:             h.name,
			HandshakeHashHex: hex.EncodeToString(h.hash),
			Sas:              tunnel.ShortAuthString(h.hash),
		})
	}
	return sasFile{Protocol: "TLMP", Version: 1, Cases: cases}
}

func counting32() []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

func ones32() []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = 0xff
	}
	return out
}

func writeJSON(path string, v any) {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fatal(err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		fatal(fmt.Errorf("write %s: %w", path, err))
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "vectorgen:", err)
	os.Exit(1)
}
