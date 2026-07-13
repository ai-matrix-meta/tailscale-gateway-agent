//go:build !linux

package internetprobe

import (
	"context"
	"errors"
	"net"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
)

type systemMarkedDeviceDialer struct{}

func (systemMarkedDeviceDialer) DialContext(context.Context, string, string, domain.LinkIdentity, uint32) (net.Conn, error) {
	return nil, errors.New("marked device-bound capability probes require Linux")
}
