package process

import "github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"

func NewSpecification(executable string, arguments, environment []string) domain.ProcessSpec {
	return domain.NewProcessSpec(executable, arguments, environment)
}
