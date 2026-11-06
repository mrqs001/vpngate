//go:build linux

package health

import (
	"encoding/binary"
	"errors"

	"golang.org/x/sys/unix"
)

// Read-only subset of Linux wireguard.h / genetlink.h. No SET command exists in
// this package. We copy only handshake times/counts; key/endpoint attributes are
// ignored, never logged or retained, and receive buffers are cleared after use.
var native = binary.NativeEndian
var errMalformed = errors.New("invalid kernel health reply")

func align(n int) int { return (n + 3) &^ 3 }
func attribute(kind uint16, value []byte) []byte {
	b := make([]byte, align(4+len(value)))
	native.PutUint16(b, uint16(4+len(value)))
	native.PutUint16(b[2:], kind)
	copy(b[4:], value)
	return b
}
func attributes(data []byte, visit func(uint16, []byte) error) error {
	for len(data) != 0 {
		if len(data) < 4 {
			return errMalformed
		}
		n := int(native.Uint16(data))
		step := align(n)
		if n < 4 || step > len(data) {
			return errMalformed
		}
		if err := visit(native.Uint16(data[2:])&0x3fff, data[4:n]); err != nil {
			return err
		}
		data = data[step:]
	}
	return nil
}

func readWireGuard(name string, buffer []byte) (WireGuard, error) {
	var result WireGuard
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_GENERIC)
	if err != nil {
		return result, err
	}
	defer unix.Close(fd)
	if err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return result, err
	}
	timeout := unix.NsecToTimeval(250_000_000)
	if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		return result, err
	}
	var family uint16
	err = exchange(fd, buffer, 1, unix.GENL_ID_CTRL, 3, attribute(2, []byte("wireguard\x00")), false, func(data []byte) error {
		return attributes(data, func(kind uint16, value []byte) error {
			if kind == 1 {
				if len(value) != 2 {
					return errMalformed
				}
				family = native.Uint16(value)
			}
			return nil
		})
	})
	if err != nil {
		return result, err
	}
	if family < unix.NLMSG_MIN_TYPE {
		return result, errMalformed
	}
	err = exchange(fd, buffer, 2, family, 0, attribute(2, append([]byte(name), 0)), true, func(data []byte) error { return parseDevice(data, &result) })
	if err != nil {
		return WireGuard{}, err
	}
	return result, nil
}

func parseDevice(data []byte, result *WireGuard) error {
	return attributes(data, func(kind uint16, peers []byte) error {
		if kind != 8 {
			return nil
		}
		return attributes(peers, func(_ uint16, peer []byte) error {
			// Continuation fragments contain a public key and allowed IPs, not another
			// LAST_HANDSHAKE_TIME. Count that field once per peer, including time zero.
			return attributes(peer, func(kind uint16, value []byte) error {
				if kind != 6 {
					return nil
				}
				if len(value) != 16 {
					return errMalformed
				}
				seconds := int64(native.Uint64(value))
				if seconds < 0 {
					return errMalformed
				}
				result.Peers++
				if seconds > result.LatestHandshakeUnix {
					result.LatestHandshakeUnix = seconds
				}
				return nil
			})
		})
	})
}

func exchange(fd int, buffer []byte, sequence uint32, family uint16, command byte, attrs []byte, dump bool, visit func([]byte) error) error {
	packet := make([]byte, 20+len(attrs))
	native.PutUint32(packet, uint32(len(packet)))
	native.PutUint16(packet[4:], family)
	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK)
	if dump {
		flags |= unix.NLM_F_DUMP
	}
	native.PutUint16(packet[6:], flags)
	native.PutUint32(packet[8:], sequence)
	packet[16], packet[17] = command, 1
	copy(packet[20:], attrs)
	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	defer clear(buffer)
	// Bound even a corrupt/oversized multipart response; a lane is one VPN device.
	for received := 0; received < 4<<20; {
		n, _, flags, sender, err := unix.Recvmsg(fd, buffer, nil, 0)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		from, ok := sender.(*unix.SockaddrNetlink)
		if !ok || from.Pid != 0 || flags&unix.MSG_TRUNC != 0 || n == 0 {
			return errMalformed
		}
		received += n
		data := buffer[:n]
		for len(data) > 0 {
			if len(data) < 16 {
				return errMalformed
			}
			length := int(native.Uint32(data))
			step := align(length)
			if length < 16 || step > len(data) || native.Uint32(data[8:]) != sequence {
				return errMalformed
			}
			kind := native.Uint16(data[4:])
			messageFlags := native.Uint16(data[6:])
			payload := data[16:length]
			if messageFlags&unix.NLM_F_DUMP_INTR != 0 {
				return errors.New("interrupted kernel health dump")
			}
			switch kind {
			case unix.NLMSG_ERROR:
				if len(payload) < 4 {
					return errMalformed
				}
				code := int32(native.Uint32(payload))
				if code != 0 {
					return unix.Errno(-code)
				}
				if !dump {
					return nil
				}
			case unix.NLMSG_DONE:
				if !dump {
					return errMalformed
				}
				if len(payload) >= 4 {
					if code := int32(native.Uint32(payload)); code != 0 {
						return unix.Errno(-code)
					}
				}
				return nil
			default:
				if kind != family || len(payload) < 4 {
					return errMalformed
				}
				if err = visit(payload[4:]); err != nil {
					return err
				}
			}
			data = data[step:]
		}
		clear(buffer[:n])
	}
	return errors.New("kernel health reply exceeds bound")
}
