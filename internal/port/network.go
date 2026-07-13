package port

import (
	"context"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
)

type NetworkDiscovery interface {
	Discover(context.Context, domain.DiscoveryRequest) (domain.NetworkSnapshot, error)
}

type ProxyTunnelDiscovery interface {
	DiscoverProxyTunnel(context.Context, domain.ProxyTunnelDiscoveryRequest) (domain.LinkIdentity, error)
}

type RoutingStore interface {
	ReadRouting(context.Context, domain.RoutingOwnership) (domain.RoutingState, error)
	ApplyRouting(context.Context, domain.RoutingChanges) (int, error)
}

type NetworkEventSource interface {
	Subscribe(context.Context) (<-chan domain.NetworkEvent, <-chan error, error)
}

type KernelPrerequisiteChecker interface {
	Check(context.Context) error
}
