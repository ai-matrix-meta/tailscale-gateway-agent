package port

import (
	"context"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
)

type TailnetControl interface {
	ReadState(context.Context) (domain.TailnetState, error)
	WritePreferences(context.Context, domain.TailnetPreferences) error
}

type TailnetEventSource interface {
	Subscribe(context.Context) (<-chan domain.TailnetEvent, <-chan error, error)
}
