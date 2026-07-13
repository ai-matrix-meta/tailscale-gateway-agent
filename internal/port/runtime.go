package port

import (
	"context"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
)

type StatusProvider interface {
	HealthSnapshot() domain.HealthSnapshot
}

type HealthServer interface {
	Run(context.Context) error
}

type MetricsRecorder interface {
	RecordReconcile(string, time.Duration, domain.ReconcileReport, error)
	SetReady(bool)
}

type Coordinator interface {
	Run(context.Context, func(context.Context) error) error
}

type ManagedProcess interface {
	Wait() error
	Terminate(context.Context) error
}

type ProcessLauncher interface {
	Start(domain.ProcessSpec) (ManagedProcess, error)
}
