package port

import (
	"context"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
)

type PacketFilterStore interface {
	Observe(context.Context, domain.PacketFilterPolicy) (domain.PacketFilterObservation, error)
	Apply(context.Context, domain.PacketFilterPolicy, domain.PacketFilterObservation) error
}
