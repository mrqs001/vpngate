package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

func rawSocket(c net.Conn) (syscall.RawConn, error) {
	if s, ok := c.(*slotConn); ok {
		c = s.Conn
	}
	if t, ok := c.(*net.TCPConn); ok {
		return t.SyscallConn()
	}
	return nil, errors.New("not a TCP socket")
}

// spliceRelay keeps payload in kernel pipe pages. Read/Write use Go's poller:
// EAGAIN parks a goroutine, never a dedicated thread or a busy loop. The pipe
// is empty before reading the source and fully drained before the next read,
// so EAGAIN always refers to the socket, not to pipe readiness.
// handled=false is returned only before consuming any input.
func (g *Gateway) spliceRelay(ctx context.Context, dst, src net.Conn, download bool, total *atomic.Uint64, activity *relayActivity) (handled bool, err error) {
	r, err := rawSocket(src)
	if err != nil {
		return false, nil
	}
	w, err := rawSocket(dst)
	if err != nil {
		return false, nil
	}
	pipe := []int{0, 0}
	if unix.Pipe2(pipe, unix.O_NONBLOCK|unix.O_CLOEXEC) != nil {
		return false, nil
	}
	defer unix.Close(pipe[0])
	defer unix.Close(pipe[1])
	// A denied resize is harmless: splice still respects the actual pipe size.
	_, _ = unix.FcntlInt(uintptr(pipe[0]), unix.F_SETPIPE_SZ, 64<<10)
	var n int64
	var callErr error
	remaining := 0
	read := func(fd uintptr) bool {
		for {
			n, callErr = unix.Splice(int(fd), nil, pipe[1], nil, 64<<10, unix.SPLICE_F_NONBLOCK)
			if callErr != unix.EINTR {
				return callErr != unix.EAGAIN
			}
		}
	}
	write := func(fd uintptr) bool {
		for remaining > 0 {
			var moved int64
			moved, callErr = unix.Splice(pipe[0], nil, int(fd), nil, remaining, unix.SPLICE_F_NONBLOCK)
			if moved > 0 {
				remaining -= int(moved)
				total.Add(uint64(moved))
				activity.touch()
			}
			if callErr == unix.EINTR {
				continue
			}
			if callErr == unix.EAGAIN {
				return false
			}
			if callErr != nil {
				return true
			}
			if moved == 0 {
				callErr = io.ErrNoProgress
				return true
			}
		}
		return true
	}
	for {
		err = r.Read(read)
		if !handled && err == nil && callErr == unix.EINVAL {
			return false, nil
		}
		if !handled && n > 0 {
			g.spliceDirections.Add(1)
		}
		handled = true
		if err != nil {
			return true, err
		}
		if callErr != nil || n == 0 {
			return true, callErr
		}
		activity.touch()
		if download {
			if err = g.waitDownload(ctx, int(n), activity); err != nil {
				return true, err
			}
		}
		remaining = int(n)
		err = w.Write(write)
		if err != nil {
			return true, err
		}
		if callErr != nil {
			return true, callErr
		}
	}
}
