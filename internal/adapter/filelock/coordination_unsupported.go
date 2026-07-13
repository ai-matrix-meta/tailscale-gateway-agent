//go:build !linux

package filelock

import (
	"context"
	"errors"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
)

var errUnsupported = errors.New("file-lock coordination is supported only on Linux")

type Coordinator struct{}

func NewCoordinator(domain.CoordinationConfiguration) *Coordinator { return &Coordinator{} }
func (coordinator *Coordinator) Run(context.Context, func(context.Context) error) error {
	return errUnsupported
}
