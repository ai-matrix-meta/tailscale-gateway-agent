package application

import (
	"fmt"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
)

type RuntimeMode string

const (
	RuntimeModeExternal               RuntimeMode = "run"
	RuntimeModeSuperviseContainerboot RuntimeMode = "supervise-containerboot"
)

func ValidateRuntimeMode(configuration domain.Configuration, mode RuntimeMode) error {
	switch mode {
	case RuntimeModeExternal:
		if configuration.Coordination.Backend != domain.CoordinationFileLock {
			return fmt.Errorf("runtime mode %q requires coordination backend %q, got %q", mode, domain.CoordinationFileLock, configuration.Coordination.Backend)
		}
	case RuntimeModeSuperviseContainerboot:
		if configuration.Coordination.Backend != domain.CoordinationKubernetesLease {
			return fmt.Errorf("runtime mode %q requires coordination backend %q, got %q", mode, domain.CoordinationKubernetesLease, configuration.Coordination.Backend)
		}
	default:
		return fmt.Errorf("runtime mode %q is unsupported", mode)
	}
	return nil
}
