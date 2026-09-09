// Package netstack bridges the Wintun L3 world and the relay's L5 world
// (roadmap Step 3): a gVisor user-space TCP/IP stack terminates every flow
// so Windows-native headers never exist beyond the adapter, then dials the
// phone through the tunnel dialer. MSS needs no explicit clamping: the
// netstack advertises MSS from the adapter MTU, which config keeps below the
// tunnel's transport ceiling by construction.
//
// NOTE ON VERSIONS: gVisor's link-endpoint and forwarder APIs migrate
// frequently. This file targets the gvisor.dev/gvisor "go" branch API
// (pinned via a replace to the esdfurkan/gvisor fork: bridge_test package
// fix + tmpl template cleanup — see the fork's toppa-fix branch). Adjust
// renamed symbols at compile time; no logic here should need to change.
package netstack

import (
	"fmt"
	"io"
	"net"

	"github.com/esdfurkan/toppa/desktop/internal/adapter"
	"github.com/esdfurkan/toppa/desktop/internal/resolver"
	"github.com/esdfurkan/toppa/desktop/internal/relay"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nicID     tcpip.NICID = 1
	dnsPort             = 53
	defaultTTL          = 64 // informational: netstack replies use their own defaults
)

// Engine wires TunDevice ↔ netstack ↔ Dialer.
type Engine struct {
	tun      adapter.TunDevice
	dialer   relay.Dialer
	dns      *resolver.LocalDNS
	tunnelIP net.IP
	stack    *stack.Stack
	stopRead chan struct{}
}

// Start brings the user-space stack up on tun. tunnelIP is the adapter
// address (ICMP echo to it is answered locally by the stack; internet-bound
// ICMP is intentionally unsupported in v1 — traceroute fingerprints).
func Start(tun adapter.TunDevice, dialer relay.Dialer, dns *resolver.LocalDNS, tunnelIP net.IP) (*Engine, error) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
	})

	link := &tunLink{tun: tun, mtu: uint32(tun.MTU())}
	if err := s.CreateNIC(nicID, link); err != nil {
		return nil, fmt.Errorf("netstack: create nic: %v", err)
	}

	proto := ipv4.ProtocolNumber
	if tunnelIP.To4() == nil {
		proto = ipv6.ProtocolNumber
	}
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          proto,
		AddressWithPrefix: tcpip.AddrFromSlice(tunnelIP.To16()).WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("netstack: add address: %v", err)
	}

	// Default routes through the NIC: 0.0.0.0/0 and ::/0. The v6 default
	// routes into the stack, which answers unreachable — the IPv6-leak
	// blackhole (architecture §1.1).
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	eng := &Engine{
		tun:      tun,
		dialer:   dialer,
		dns:      dns,
		tunnelIP: tunnelIP,
		stack:    s,
		stopRead: make(chan struct{}),
	}

	tcpForwarder := tcp.NewForwarder(s, 0, 10, eng.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	udpForwarder := udp.NewForwarder(s, eng.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	go eng.readLoop(link)
	return eng, nil
}

func (eng *Engine) handleTCP(req *tcp.ForwarderRequest) {
	var wq waiter.Queue
	ep, err := req.CreateEndpoint(&wq)
	if err != nil {
		req.Complete(true) // RST: nothing to relay to
		return
	}
	req.Complete(false)

	go func() {
		conn := gonet.NewTCPConn(&wq, ep)
		defer conn.Close()

		// The original destination, as Windows addressed it.
		remote, ok := conn.RemoteAddr().(*net.TCPAddr)
		if !ok {
			return
		}
		destination := &net.TCPAddr{IP: remote.IP, Port: int(req.ID().LocalPort)}

		if destination.Port == dnsPort && eng.dns != nil {
			_ = eng.dns.HandleTCP(conn)
			return
		}

		upstream, err := eng.dialer.DialTCP(destination)
		if err != nil {
			return // RST already implied by conn.Close
		}
		defer upstream.Close()
		pumpBidirectional(conn, upstream)
	}()
}

func (eng *Engine) handleUDP(req *udp.ForwarderRequest) (handled bool) {
	var wq waiter.Queue
	ep, err := req.CreateEndpoint(&wq)
	if err != nil {
		return
	}
	go func() {
		defer ep.Close()
		conn := gonet.NewUDPConn(&wq, ep)
		if uint16(req.ID().LocalPort) != dnsPort || eng.dns == nil {
			// Non-DNS UDP is dropped by design in v1 (SPEC §6 — the
			// datagram channel is a later milestone).
			return
		}
		buf := make([]byte, 4096)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		resp, err := eng.dns.QueryWireUpstream(buf[:n])
		if err != nil {
			return
		}
		_, _ = conn.WriteTo(resp, nil)
	}()
	return true
}

func (eng *Engine) readLoop(link *tunLink) {
	buf := make([]byte, 65536)
	for {
		select {
		case <-eng.stopRead:
			return
		default:
		}
		n, err := eng.tun.Read(buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		proto := protocolNumber(buf[0])
		if proto == 0 {
			continue
		}
		link.inject(proto, append([]byte(nil), buf[:n]...))
	}
}

func protocolNumber(firstByte byte) tcpip.NetworkProtocolNumber {
	switch firstByte >> 4 {
	case 4:
		return ipv4.ProtocolNumber
	case 6:
		return ipv6.ProtocolNumber
	default:
		return 0
	}
}

// pumpBidirectional moves bytes both ways; TCP half-close is preserved so
// protocols that rely on shutdown semantics (HTTP/1.0 servers, SMTP) work.
func pumpBidirectional(a, b net.Conn) {
	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()
		_, _ = io.Copy(dst, src)
		if c, ok := dst.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
	}
	go copyOne(a, b)
	go copyOne(b, a)
	<-done
	<-done
	_ = a.Close()
	_ = b.Close()
}

// Stop tears the stack down (adapter close is owned by the daemon).
func (eng *Engine) Stop() {
	close(eng.stopRead)
	eng.stack.Close()
}
