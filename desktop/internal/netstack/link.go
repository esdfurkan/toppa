package netstack

import (
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/esdfurkan/toppa/desktop/internal/adapter"
)

// tunLink is the gVisor LinkEndpoint over a TunDevice: no link header
// (Wintun exchanges bare IP packets), inbound packets are injected from the
// engine's read loop, outbound frames are written straight back down.
type tunLink struct {
	tun      adapter.TunDevice
	mtu      uint32
	dispatch stack.NetworkDispatcher
}

func (l *tunLink) MTU() uint32 { return l.mtu }

func (l *tunLink) SetMTU(mtu uint32) {}

func (l *tunLink) Capabilities() stack.LinkEndpointCapabilities {
	// No checksum offload: netstack computes checksums.
	return 0
}

func (l *tunLink) MaxHeaderLength() uint16 { return 0 }

func (l *tunLink) LinkAddress() tcpip.LinkAddress { return "" }

func (l *tunLink) SetLinkAddress(addr tcpip.LinkAddress) {}

func (l *tunLink) Attach(dispatcher stack.NetworkDispatcher) { l.dispatch = dispatcher }

func (l *tunLink) IsAttached() bool { return l.dispatch != nil }

func (l *tunLink) Wait() {}

func (l *tunLink) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }

// AddHeader is a no-op: this link has no link-layer header.
func (l *tunLink) AddHeader(*stack.PacketBuffer) {}

func (l *tunLink) ParseHeader(*stack.PacketBuffer) bool { return true }

func (l *tunLink) Close() {}

func (l *tunLink) SetOnCloseAction(func()) {}

// inject delivers one inbound IP packet to the netstack.
func (l *tunLink) inject(proto tcpip.NetworkProtocolNumber, payload []byte) {
	if l.dispatch == nil {
		return
	}
	var buf buffer.Buffer
	_, _ = buf.WriteFromReader(bytesReader(payload), int64(len(payload)))
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buf})
	l.dispatch.DeliverNetworkPacket(proto, pkt)
}

// WritePackets drains the netstack's outbound queue into the TUN device.
func (l *tunLink) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, pkt := range pkts.AsSlice() {
		if _, err := l.tun.Write(pkt.ToView().AsSlice()); err != nil {
			return n, &tcpip.ErrAborted{}
		}
		n++
	}
	return n, nil
}
