//go:build linux && integration

package internetprobe

import (
	"context"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	vnetlink "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestIntegrationMarkedDeviceDialerAppliesSocketIdentity(t *testing.T) {
	loopback, err := vnetlink.LinkByName("lo")
	if err != nil {
		t.Fatalf("find loopback link: %v", err)
	}
	if err := vnetlink.LinkSetUp(loopback); err != nil {
		t.Fatalf("set loopback link up: %v", err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on loopback: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if connection != nil {
			_ = connection.Close()
		}
		accepted <- acceptErr
	}()

	const packetMark = 0x11
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := (systemMarkedDeviceDialer{}).DialContext(
		ctx,
		"tcp4",
		listener.Addr().String(),
		domain.LinkIdentity{Index: loopback.Attrs().Index, Name: loopback.Attrs().Name},
		packetMark,
	)
	if err != nil {
		_ = listener.Close()
		<-accepted
		t.Fatalf("dial through marked device-bound socket: %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })

	syscallConnection, ok := connection.(syscall.Conn)
	if !ok {
		t.Fatalf("connection type %T does not expose its socket", connection)
	}
	rawConnection, err := syscallConnection.SyscallConn()
	if err != nil {
		t.Fatalf("access client socket: %v", err)
	}
	var observedMark int
	var observedDevice string
	var socketErr error
	if err := rawConnection.Control(func(fileDescriptor uintptr) {
		observedMark, socketErr = unix.GetsockoptInt(int(fileDescriptor), unix.SOL_SOCKET, unix.SO_MARK)
		if socketErr != nil {
			return
		}
		observedDevice, socketErr = unix.GetsockoptString(int(fileDescriptor), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	}); err != nil {
		t.Fatalf("inspect client socket: %v", err)
	}
	if socketErr != nil {
		t.Fatalf("read client socket identity: %v", socketErr)
	}
	if observedMark != packetMark || observedDevice != loopback.Attrs().Name {
		t.Fatalf("socket identity = mark %#x device %q, want mark %#x device %q", observedMark, observedDevice, packetMark, loopback.Attrs().Name)
	}
	select {
	case acceptErr := <-accepted:
		if acceptErr != nil {
			t.Fatalf("accept marked connection: %v", acceptErr)
		}
	case <-ctx.Done():
		t.Fatalf("marked connection was not accepted: %v", ctx.Err())
	}
}
