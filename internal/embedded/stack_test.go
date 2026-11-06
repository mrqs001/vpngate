package embedded

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"os"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestPacketBridgeBatchIntegrityAndClose(t *testing.T) {
	p, err := newPacketStack([]netip.Addr{netip.MustParseAddr("10.77.0.2")}, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	var packets stack.PacketBufferList
	want := []byte("header!payload-tail")
	for i := 0; i < 2; i++ {
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: 32, Payload: buffer.MakeWithData([]byte("payload"))})
		copy(pkt.NetworkHeader().Push(7), "header!")
		pkt.Data().AppendView(buffer.NewViewWithData([]byte("-tail")))
		packets.PushBack(pkt)
	}
	if n, e := p.ep.WritePackets(packets); n != 2 || e != nil {
		t.Fatal("queue write failed", n, e)
	}
	packets.DecRef()
	bufs := [][]byte{bytes.Repeat([]byte{0xaa}, 128), bytes.Repeat([]byte{0xaa}, 128), make([]byte, 128)}
	sizes := make([]int, 3)
	n, err := p.Read(bufs, sizes, 16)
	if err != nil || n != 2 {
		t.Fatal("did not drain available batch", n, err)
	}
	for i := 0; i < n; i++ {
		if sizes[i] != len(want) || !bytes.Equal(bufs[i][16:16+sizes[i]], want) || !bytes.Equal(bufs[i][:16], bytes.Repeat([]byte{0xaa}, 16)) || bufs[i][16+sizes[i]] != 0xaa {
			t.Fatal("packet or offset corrupted")
		}
	}
	if _, err := p.Read(nil, nil, 0); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatal("invalid read accepted")
	}
	done := make(chan error, 1)
	go func() { _, err := p.Read(bufs, sizes, 0); done <- err }()
	p.Close()
	p.Close()
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatal("blocked reader not closed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked reader leaked")
	}
}
