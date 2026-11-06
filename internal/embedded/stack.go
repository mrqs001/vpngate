package embedded

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// packetStack is only an adapter, not a new TCP/IP implementation. It connects
// gVisor directly to WireGuard's batch interface, without a kernel TUN or an
// intermediate flattened packet allocation. The existing gateway owns DNS.
type packetStack struct {
	s      *stack.Stack
	ep     *channel.Endpoint
	events chan tun.Event
	mtu    int
	close  sync.Once
}

var _ tun.Device = (*packetStack)(nil)

func newPacketStack(addresses []netip.Addr, mtu int) (*packetStack, error) {
	p := &packetStack{
		s:  stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6}, HandleLocal: true}),
		ep: channel.New(1024, uint32(mtu), ""), events: make(chan tun.Event, 1), mtu: mtu,
	}
	ok := false
	defer func() {
		if !ok {
			p.Close()
		}
	}()
	sack := tcpip.TCPSACKEnabled(true)
	if e := p.s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); e != nil {
		return nil, errors.New("cannot enable TCP SACK")
	}
	if e := p.s.CreateNIC(1, p.ep); e != nil {
		return nil, errors.New("cannot create embedded NIC")
	}
	for _, ip := range addresses {
		protocol := ipv4.ProtocolNumber
		destination := header.IPv4EmptySubnet
		if ip.Is6() {
			protocol = ipv6.ProtocolNumber
			destination = header.IPv6EmptySubnet
		}
		if e := p.s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: protocol, AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix()}, stack.AddressProperties{}); e != nil {
			return nil, errors.New("cannot configure embedded address")
		}
		p.s.AddRoute(tcpip.Route{Destination: destination, NIC: 1})
	}
	p.events <- tun.EventUp
	ok = true
	return p, nil
}

func (p *packetStack) File() *os.File           { return nil }
func (p *packetStack) Name() (string, error)    { return "embedded", nil }
func (p *packetStack) MTU() (int, error)        { return p.mtu, nil }
func (p *packetStack) Events() <-chan tun.Event { return p.events }
func (p *packetStack) BatchSize() int           { return conn.IdealBatchSize }

func (p *packetStack) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) < len(bufs) || offset < 0 {
		return 0, io.ErrShortBuffer
	}
	pkt := p.ep.ReadContext(context.Background())
	if pkt == nil {
		return 0, os.ErrClosed
	}
	for i := range bufs {
		if offset > len(bufs[i]) || pkt.Size() > len(bufs[i])-offset {
			pkt.DecRef()
			return i, io.ErrShortBuffer
		}
		sizes[i] = copyPacket(bufs[i][offset:], pkt)
		pkt.DecRef()
		if i+1 == len(bufs) {
			return i + 1, nil
		}
		// Drain only already queued packets: batching must never delay the first.
		pkt = p.ep.Read()
		if pkt == nil {
			return i + 1, nil
		}
	}
	panic("unreachable")
}

func copyPacket(dst []byte, pkt *stack.PacketBuffer) int {
	views, skip := pkt.AsViewList()
	n := 0
	for v := views.Front(); v != nil; v = v.Next() {
		b := v.AsSlice()
		if skip >= len(b) {
			skip -= len(b)
			continue
		}
		n += copy(dst[n:], b[skip:])
		skip = 0
	}
	return n
}

func (p *packetStack) Write(bufs [][]byte, offset int) (int, error) {
	for i, b := range bufs {
		if offset < 0 || offset > len(b) {
			return i, io.ErrShortBuffer
		}
		b = b[offset:]
		if len(b) == 0 {
			continue
		}
		var protocol tcpip.NetworkProtocolNumber
		switch b[0] >> 4 {
		case 4:
			protocol = ipv4.ProtocolNumber
		case 6:
			protocol = ipv6.ProtocolNumber
		default:
			return i, syscall.EAFNOSUPPORT
		}
		// WireGuard reuses its decryption buffers on return, so the stack must
		// own this copy. Release our packet reference after synchronous delivery;
		// any queued transport segment holds its own reference.
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
		p.ep.InjectInbound(protocol, pkt)
		pkt.DecRef()
	}
	return len(bufs), nil
}

func (p *packetStack) Close() error {
	p.close.Do(func() {
		p.ep.Close() // wakes a blocked WireGuard reader and drains queued packets
		p.s.Close()
		p.s.Wait()
		close(p.events)
	})
	return nil
}

func fullAddress(a netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	protocol := ipv4.ProtocolNumber
	if a.Addr().Is6() {
		protocol = ipv6.ProtocolNumber
	}
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(a.Addr().AsSlice()), Port: a.Port()}, protocol
}

func (p *packetStack) dial(ctx context.Context, network string, a netip.AddrPort) (net.Conn, error) {
	address, protocol := fullAddress(a)
	switch network {
	case "tcp", "tcp4", "tcp6":
		return gonet.DialContextTCP(ctx, p.s, address, protocol)
	case "udp", "udp4", "udp6":
		return gonet.DialUDP(p.s, nil, &address, protocol)
	default:
		return nil, errors.New("unsupported embedded transport")
	}
}
