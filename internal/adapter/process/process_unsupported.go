//go:build !linux

package process

import (
	"context"
	"errors"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/port"
)

var errUnsupported = errors.New("process supervision is supported only on Linux")

type Launcher struct{}

func NewLauncher() *Launcher { return &Launcher{} }
func (launcher *Launcher) Start(domain.ProcessSpec) (port.ManagedProcess, error) {
	return nil, errUnsupported
}

type ManagedProcess struct{}

func (process *ManagedProcess) Wait() error                     { return errUnsupported }
func (process *ManagedProcess) Terminate(context.Context) error { return errUnsupported }
