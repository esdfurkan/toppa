package mux

import (
	"errors"
	"fmt"
	"net"
)

// Address-block network and address-type codes (protocol/SPEC.md §4.4).
const (
	NetTCP uint8 = 1
	NetUDP uint8 = 2

	ATYPIPv4 uint8 = 1
	ATYPFQDN uint8 = 3
	ATYPIPv6 uint8 = 4
)

// MaxFQDNLength bounds the encoded hostname per the spec.
const MaxFQDNLength = 255

// ErrBadTarget is returned for malformed address blocks.
var ErrBadTarget = errors.New("mux: malformed target address block")

// Target identifies the destination of a relayed stream, mirroring the SOCKS5
// address family set. Domain targets are resolved on the phone (see the DNS
// architecture in docs/ARCHITECTURE.md §1.5).
type Target struct {
	Network uint8
	ATYP    uint8
	Address []byte // 4B IPv4 / 16B IPv6 / FQDN bytes (no inner length)
	Port    uint16
}

// TCPv4 is a convenience constructor for IPv4 TCP targets.
func TCPv4(ip [4]byte, port uint16) Target {
	return Target{Network: NetTCP, ATYP: ATYPIPv4, Address: ip[:], Port: port}
}

// TCPFQDN is a convenience constructor for hostname TCP targets.
func TCPFQDN(host string, port uint16) (Target, error) {
	if len(host) == 0 || len(host) > MaxFQDNLength {
		return Target{}, fmt.Errorf("%w: fqdn length %d", ErrBadTarget, len(host))
	}
	return Target{Network: NetTCP, ATYP: ATYPFQDN, Address: []byte(host), Port: port}, nil
}

// AppendTarget encodes t per SPEC §4.4 and appends it to dst.
func AppendTarget(dst []byte, t Target) []byte {
	dst = append(dst, t.Network, t.ATYP)
	switch t.ATYP {
	case ATYPFQDN:
		dst = append(dst, uint8(len(t.Address)))
		dst = append(dst, t.Address...)
	case ATYPIPv4, ATYPIPv6:
		dst = append(dst, t.Address...)
	}
	var p [2]byte
	p[0] = byte(t.Port >> 8)
	p[1] = byte(t.Port)
	return append(dst, p[:]...)
}

// ParseTarget decodes an address block from b.
func ParseTarget(b []byte) (Target, error) {
	if len(b) < 4 {
		return Target{}, fmt.Errorf("%w: truncated header", ErrBadTarget)
	}
	t := Target{Network: b[0], ATYP: b[1]}
	if t.Network != NetTCP && t.Network != NetUDP {
		return Target{}, fmt.Errorf("%w: network %d", ErrBadTarget, t.Network)
	}
	rest := b[2:]
	switch t.ATYP {
	case ATYPIPv4:
		if len(rest) < 6 {
			return Target{}, fmt.Errorf("%w: short ipv4", ErrBadTarget)
		}
		t.Address = append([]byte(nil), rest[:4]...)
		t.Port = be16(rest[4:6])
	case ATYPIPv6:
		if len(rest) < 18 {
			return Target{}, fmt.Errorf("%w: short ipv6", ErrBadTarget)
		}
		t.Address = append([]byte(nil), rest[:16]...)
		t.Port = be16(rest[16:18])
	case ATYPFQDN:
		if len(rest) < 1 {
			return Target{}, fmt.Errorf("%w: missing fqdn length", ErrBadTarget)
		}
		n := int(rest[0])
		if n == 0 || len(rest) < 1+n+2 {
			return Target{}, fmt.Errorf("%w: bad fqdn", ErrBadTarget)
		}
		t.Address = append([]byte(nil), rest[1:1+n]...)
		t.Port = be16(rest[1+n : 3+n])
	default:
		return Target{}, fmt.Errorf("%w: atyp %d", ErrBadTarget, t.ATYP)
	}
	return t, nil
}

// String renders the target in host:port form for logs and diagnostics.
func (t Target) String() string {
	host := ""
	switch t.ATYP {
	case ATYPIPv4, ATYPIPv6:
		host = net.IP(t.Address).String()
	case ATYPFQDN:
		host = string(t.Address)
	}
	netName := "tcp"
	if t.Network == NetUDP {
		netName = "udp"
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", t.Port)) + "/" + netName
}

func be16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }
