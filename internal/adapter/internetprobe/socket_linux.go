//go:build linux

package internetprobe

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	"golang.org/x/sys/unix"
)

type systemMarkedDeviceDialer struct{}

func (systemMarkedDeviceDialer) DialContext(ctx context.Context, network, address string, proxyLink domain.LinkIdentity, packetMark uint32) (net.Conn, error) {
	dialer := net.Dialer{
		KeepAlive: -1,
		Control: func(_, _ string, raw syscall.RawConn) error {
			var socketErr error
			if err := raw.Control(func(fileDescriptor uintptr) {
				if err := unix.SetsockoptInt(int(fileDescriptor), unix.SOL_SOCKET, unix.SO_MARK, int(packetMark)); err != nil {
					socketErr = fmt.Errorf("set SO_MARK: %w", err)
					return
				}
				if err := unix.SetsockoptString(int(fileDescriptor), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, proxyLink.Name); err != nil {
					socketErr = fmt.Errorf("set SO_BINDTODEVICE: %w", err)
				}
			}); err != nil {
				return fmt.Errorf("control capability probe socket: %w", err)
			}
			return socketErr
		},
	}
	return dialer.DialContext(ctx, network, address)
}
