//go:build linux

package netns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Factory returns a nonblocking socket in the selected network namespace.
// It is deliberately incapable of changing interfaces or accepting namespace paths.
type Factory func(lane, family, kind int) (int, error)

func SocketPair() (*net.UnixConn, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fds[0]), "broker-parent")
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		unix.Close(fds[1])
		return nil, nil, err
	}
	return c.(*net.UnixConn), os.NewFile(uintptr(fds[1]), "broker-child"), nil
}

func NamespaceFactory(names, interfaces []string) (Factory, func(), error) {
	if len(names) != len(interfaces) {
		return nil, nil, errors.New("namespace/interface count mismatch")
	}
	origin, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return nil, nil, err
	}
	generations := make([]os.FileInfo, 0, len(names))
	openNamespace := func(name string) (*os.File, error) {
		fd, err := unix.Open("/var/run/netns/"+name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(fd), "namespace"), nil
	}
	for _, name := range names {
		f, err := openNamespace(name)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot open namespace for lane %d", len(generations))
		}
		target, e := f.Stat()
		f.Close()
		if e != nil || os.SameFile(origin, target) {
			return nil, nil, errors.New("refusing the host network namespace")
		}
		generations = append(generations, target)
	}
	// This factory must only be called by ServeBroker's pinned OS thread.
	// Open that thread's original namespace lazily, on its first request.
	var home *os.File
	factory := func(lane, family, kind int) (int, error) {
		if lane < 0 || lane >= len(names) {
			return -1, errors.New("unknown lane")
		}
		// Do not pin an attached namespace indefinitely while idle, or silently
		// follow a recreated namespace to a different VPN identity.
		target, err := openNamespace(names[lane])
		if err != nil {
			return -1, errors.New("lane namespace unavailable")
		}
		defer target.Close()
		generation, err := target.Stat()
		if err != nil || !os.SameFile(generations[lane], generation) {
			return -1, errors.New("lane namespace generation changed")
		}
		if home == nil {
			var err error
			home, err = os.Open(fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid()))
			if err != nil {
				return -1, errors.New("cannot pin original namespace")
			}
		}
		if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
			return -1, err
		}
		fd, err := NewSocket(family, kind)
		if err == nil && interfaces[lane] != "" {
			// Route changes must never redirect source or DNS traffic through an
			// attached namespace's transport interface when its VPN is unavailable.
			if e := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, interfaces[lane]); e != nil {
				unix.Close(fd)
				fd, err = -1, errors.New("lane interface unavailable")
			}
		}
		if restore := unix.Setns(int(home.Fd()), unix.CLONE_NEWNET); restore != nil {
			if fd >= 0 {
				unix.Close(fd)
			}
			// Never return a contaminated privileged thread to the Go scheduler.
			panic("cannot restore socket-worker namespace")
		}
		return fd, err
	}
	return factory, func() {
		if home != nil {
			home.Close()
		}
	}, nil
}

func NewSocket(family, kind int) (int, error) {
	if family != unix.AF_INET && family != unix.AF_INET6 || kind != unix.SOCK_STREAM && kind != unix.SOCK_DGRAM {
		return -1, errors.New("unsupported socket type")
	}
	fd, err := unix.Socket(family, kind|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if family == unix.AF_INET6 {
		if err = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1); err != nil {
			unix.Close(fd)
			return -1, err
		}
	}
	return fd, nil
}

// ServeBroker is a single bounded socket-creation worker. It does not resolve,
// connect, forward payload, or wait for remote servers.
func ServeBroker(c *net.UnixConn, factory Factory) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer c.Close()
	buf, anc := make([]byte, 8), make([]byte, unix.CmsgSpace(4))
	for {
		n, oobn, flags, _, err := c.ReadMsgUnix(buf, anc)
		if err != nil {
			return err
		}
		closeRights(anc[:oobn])
		if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n != 8 || oobn != 0 || buf[0] != 1 || buf[3] != 0 {
			return errors.New("invalid socket request")
		}
		family, kind := int(buf[1]), int(buf[2])
		lane := int(binary.BigEndian.Uint32(buf[4:]))
		fd, err := factory(lane, family, kind)
		if err != nil {
			if _, _, e := c.WriteMsgUnix([]byte{1}, nil, nil); e != nil {
				return e
			}
			continue
		}
		_, _, err = c.WriteMsgUnix([]byte{0}, unix.UnixRights(fd), nil)
		unix.Close(fd)
		if err != nil {
			return err
		}
	}
}

type Broker struct {
	conn *net.UnixConn
	gate chan struct{}
	once sync.Once
}

func NewBroker(f *os.File) (*Broker, error) {
	c, err := net.FileConn(f)
	if err != nil {
		return nil, err
	}
	u, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		return nil, errors.New("invalid broker descriptor")
	}
	return &Broker{conn: u, gate: make(chan struct{}, 1)}, nil
}

func (b *Broker) Close() error { var err error; b.once.Do(func() { err = b.conn.Close() }); return err }

func (b *Broker) Socket(ctx context.Context, lane, family, kind int) (*os.File, error) {
	select {
	case b.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-b.gate }()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// Once sent, finish this short local transaction even if the caller cancels.
	// Otherwise a late reply could be mistaken for the next caller's descriptor.
	b.conn.SetDeadline(time.Now().Add(5 * time.Second))
	defer b.conn.SetDeadline(time.Time{})
	req := make([]byte, 8)
	req[0] = 1
	req[1] = byte(family)
	req[2] = byte(kind)
	binary.BigEndian.PutUint32(req[4:], uint32(lane))
	if _, _, err := b.conn.WriteMsgUnix(req, nil, nil); err != nil {
		b.Close()
		return nil, errors.New("socket broker unavailable")
	}
	data, anc := make([]byte, 1), make([]byte, unix.CmsgSpace(4*8))
	n, oobn, flags, _, err := b.conn.ReadMsgUnix(data, anc)
	if err != nil {
		closeRights(anc[:oobn])
		b.Close()
		return nil, errors.New("socket broker unavailable")
	}
	fds, parseErr := rights(anc[:oobn])
	if n != 1 || data[0] != 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || parseErr != nil || len(fds) != 1 {
		for _, fd := range fds {
			unix.Close(fd)
		}
		return nil, errors.New("lane socket unavailable")
	}
	unix.CloseOnExec(fds[0])
	if ctx.Err() != nil {
		unix.Close(fds[0])
		return nil, ctx.Err()
	}
	return os.NewFile(uintptr(fds[0]), "lane-socket"), nil
}

func rights(b []byte) ([]int, error) {
	msgs, err := unix.ParseSocketControlMessage(b)
	if err != nil {
		return nil, err
	}
	var out []int
	for _, m := range msgs {
		if m.Header.Level != unix.SOL_SOCKET || m.Header.Type != unix.SCM_RIGHTS {
			return out, errors.New("unexpected socket metadata")
		}
		fds, e := unix.ParseUnixRights(&m)
		out = append(out, fds...)
		if e != nil {
			return out, e
		}
	}
	return out, nil
}
func closeRights(b []byte) {
	fds, _ := rights(b)
	for _, fd := range fds {
		unix.Close(fd)
	}
}

// Dial connects a namespace-owned descriptor from the unprivileged frontend.
// Waiting uses Go's poller, so remote latency does not occupy the socket worker.
func (b *Broker) Dial(ctx context.Context, lane int, network string, address netip.AddrPort) (net.Conn, error) {
	family, kind := unix.AF_INET, unix.SOCK_STREAM
	if address.Addr().Is6() {
		family = unix.AF_INET6
	}
	if network == "udp" {
		kind = unix.SOCK_DGRAM
	} else if network != "tcp" {
		return nil, errors.New("unsupported network")
	}
	f, err := b.Socket(ctx, lane, family, kind)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Connect(ctx, f, address)
}

func Connect(ctx context.Context, f *os.File, address netip.AddrPort) (net.Conn, error) {
	var sa unix.Sockaddr
	if address.Addr().Is4() {
		sa = &unix.SockaddrInet4{Port: int(address.Port()), Addr: address.Addr().As4()}
	} else {
		sa = &unix.SockaddrInet6{Port: int(address.Port()), Addr: address.Addr().As16()}
	}
	raw, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var connectStart error
	if err = raw.Control(func(fd uintptr) { connectStart = unix.Connect(int(fd), sa) }); err != nil {
		return nil, err
	}
	err = connectStart
	if err != nil && err != unix.EINPROGRESS && err != unix.EALREADY && err != unix.EINTR {
		return nil, errors.New("destination connection failed")
	}
	if err != nil {
		if d, ok := ctx.Deadline(); ok {
			if err = f.SetWriteDeadline(d); err != nil {
				return nil, err
			}
		}
		done := make(chan struct{})
		stop := context.AfterFunc(ctx, func() { f.SetWriteDeadline(time.Now()); close(done) })
		var connectErr error
		err = raw.Write(func(fd uintptr) bool {
			n, e := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ERROR)
			if e != nil || n != 0 {
				connectErr = errors.New("destination connection failed")
				return true
			}
			_, e = unix.Getpeername(int(fd))
			return e == nil
		})
		if !stop() {
			<-done
		}
		f.SetWriteDeadline(time.Time{})
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			return nil, err
		}
		if connectErr != nil {
			return nil, connectErr
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	conn, err := net.FileConn(f)
	if err == nil {
		if t, ok := conn.(*net.TCPConn); ok {
			t.SetNoDelay(true)
			t.SetKeepAlive(true)
		}
	}
	return conn, err
}
