//go:build !linux

package netlink

import (
	"context"
	"errors"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
)

var errUnsupported = errors.New("rtnetlink is supported only on Linux")

type Adapter struct{}

func New() (*Adapter, error)          { return &Adapter{}, nil }
func (adapter *Adapter) Close() error { return nil }
func (adapter *Adapter) Discover(context.Context, domain.DiscoveryRequest) (domain.NetworkSnapshot, error) {
	return domain.NetworkSnapshot{}, errUnsupported
}
func (adapter *Adapter) DiscoverProxyTunnel(context.Context, domain.ProxyTunnelDiscoveryRequest) (domain.LinkIdentity, error) {
	return domain.LinkIdentity{}, errUnsupported
}
func (adapter *Adapter) ReadRouting(context.Context, domain.RoutingOwnership) (domain.RoutingState, error) {
	return domain.RoutingState{}, errUnsupported
}
func (adapter *Adapter) ApplyRouting(context.Context, domain.RoutingChanges) (int, error) {
	return 0, errUnsupported
}
func (adapter *Adapter) Subscribe(context.Context) (<-chan domain.NetworkEvent, <-chan error, error) {
	return nil, nil, errUnsupported
}
