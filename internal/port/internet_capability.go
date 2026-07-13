package port

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
)

type InternetEgressProbeRequest struct {
	Family     domain.AddressFamily
	ProxyLink  domain.LinkIdentity
	PacketMark uint32
}

func (request InternetEgressProbeRequest) Validate() error {
	if request.Family != domain.IPv4 && request.Family != domain.IPv6 {
		return fmt.Errorf("internet egress probe family %d is unsupported", request.Family)
	}
	if err := request.ProxyLink.Validate(); err != nil {
		return fmt.Errorf("internet egress probe proxy link: %w", err)
	}
	if request.PacketMark == 0 {
		return errors.New("internet egress probe packet mark is required")
	}
	if request.PacketMark&^domain.LocalEgressPacketMarkMask != 0 {
		return fmt.Errorf("internet egress probe packet mark %#x exceeds the Agent-owned low 16 bits", request.PacketMark)
	}
	return nil
}

type InternetEgressProber interface {
	Probe(context.Context, InternetEgressProbeRequest) error
}

type InternetCapabilityProbeResult string

const (
	InternetCapabilityProbeSucceeded InternetCapabilityProbeResult = "success"
	InternetCapabilityProbeFailed    InternetCapabilityProbeResult = "failure"
	InternetCapabilityProbeCanceled  InternetCapabilityProbeResult = "canceled"
)

type InternetCapabilityMetrics interface {
	RecordInternetCapabilityProbe(domain.AddressFamily, InternetCapabilityProbeResult)
	RecordInternetCapabilitySnapshot(domain.InternetCapabilitySnapshot, time.Time)
}
