package capability

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/port"
)

type familyState struct {
	capability   domain.InternetFamilyCapability
	successCount uint32
	failureCount uint32
}

type Monitor struct {
	configuration domain.InternetCapabilityConfiguration
	packetMark    uint32
	prober        port.InternetEgressProber
	metrics       port.InternetCapabilityMetrics
	now           func() time.Time
	cycle         chan struct{}

	proxyLink domain.LinkIdentity
	lastProbe time.Time
	ipv4      familyState
	ipv6      familyState
}

func NewMonitor(configuration domain.InternetCapabilityConfiguration, packetMark uint32, prober port.InternetEgressProber, metrics port.InternetCapabilityMetrics) (*Monitor, error) {
	if prober == nil || metrics == nil {
		return nil, errors.New("internet egress prober and metrics are required")
	}
	if configuration.ProbeInterval <= 0 || configuration.ProbeTimeout <= 0 || configuration.ProbeTimeout >= configuration.ProbeInterval {
		return nil, errors.New("capability probe timing is invalid")
	}
	if configuration.ProbeValidity <= configuration.ProbeInterval {
		return nil, errors.New("capability probe validity must exceed its interval")
	}
	if configuration.SuccessThreshold == 0 || configuration.SuccessThreshold > 16 || configuration.FailureThreshold == 0 || configuration.FailureThreshold > 16 {
		return nil, errors.New("capability probe thresholds must be within 1..16")
	}
	if packetMark == 0 || packetMark&^domain.LocalEgressPacketMarkMask != 0 {
		return nil, fmt.Errorf("capability packet mark %#x is outside the Agent-owned low 16 bits", packetMark)
	}
	return &Monitor{
		configuration: configuration,
		packetMark:    packetMark,
		prober:        prober,
		metrics:       metrics,
		now:           time.Now,
		cycle:         make(chan struct{}, 1),
	}, nil
}

func (monitor *Monitor) Observe(ctx context.Context, proxyLink domain.LinkIdentity) (domain.InternetCapabilitySnapshot, error) {
	if ctx == nil {
		return domain.InternetCapabilitySnapshot{}, errors.New("capability observation context is required")
	}
	if err := proxyLink.Validate(); err != nil {
		return domain.InternetCapabilitySnapshot{}, fmt.Errorf("validate capability proxy link: %w", err)
	}
	select {
	case monitor.cycle <- struct{}{}:
		defer func() { <-monitor.cycle }()
	case <-ctx.Done():
		return domain.InternetCapabilitySnapshot{}, ctx.Err()
	}

	now := monitor.now()
	if now.IsZero() {
		return domain.InternetCapabilitySnapshot{}, errors.New("capability clock returned a zero time")
	}
	if monitor.proxyLink != proxyLink {
		monitor.resetForLink(proxyLink)
	}
	if !monitor.lastProbe.IsZero() && now.Before(monitor.lastProbe) {
		return monitor.snapshot(), errors.New("capability clock moved backwards")
	}
	if !monitor.probeDue(now) {
		snapshot := monitor.snapshot()
		monitor.metrics.RecordInternetCapabilitySnapshot(snapshot, now)
		return snapshot, nil
	}

	results := make(chan probeResult, 2)
	for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
		go monitor.probeFamily(ctx, proxyLink, family, results)
	}
	observations := [2]probeResult{<-results, <-results}
	for _, observation := range observations {
		result := port.InternetCapabilityProbeFailed
		if ctx.Err() != nil {
			result = port.InternetCapabilityProbeCanceled
		} else if observation.err == nil {
			result = port.InternetCapabilityProbeSucceeded
		}
		monitor.metrics.RecordInternetCapabilityProbe(observation.family, result)
	}
	if err := ctx.Err(); err != nil {
		return monitor.snapshot(), err
	}
	observedAt := monitor.now()
	if observedAt.IsZero() || observedAt.Before(now) {
		return monitor.snapshot(), errors.New("capability clock returned an invalid observation time")
	}
	for _, observation := range observations {
		monitor.applyObservation(observation.family, observation.err == nil, observedAt)
	}
	monitor.lastProbe = observedAt
	snapshot := monitor.snapshot()
	if err := snapshot.Validate(); err != nil {
		return domain.InternetCapabilitySnapshot{}, fmt.Errorf("validate capability snapshot: %w", err)
	}
	monitor.metrics.RecordInternetCapabilitySnapshot(snapshot, observedAt)
	return snapshot, nil
}

type probeResult struct {
	family domain.AddressFamily
	err    error
}

func (monitor *Monitor) probeFamily(ctx context.Context, proxyLink domain.LinkIdentity, family domain.AddressFamily, results chan<- probeResult) {
	probeContext, cancel := context.WithTimeout(ctx, monitor.configuration.ProbeTimeout)
	defer cancel()
	err := monitor.prober.Probe(probeContext, port.InternetEgressProbeRequest{
		Family: family, ProxyLink: proxyLink, PacketMark: monitor.packetMark,
	})
	results <- probeResult{family: family, err: err}
}

func (monitor *Monitor) probeDue(now time.Time) bool {
	if monitor.lastProbe.IsZero() || !now.Before(monitor.lastProbe.Add(monitor.configuration.ProbeInterval)) {
		return true
	}
	return expired(monitor.ipv4.capability, now) || expired(monitor.ipv6.capability, now)
}

func expired(capability domain.InternetFamilyCapability, now time.Time) bool {
	return capability.Available && now.After(capability.ValidUntil)
}

func (monitor *Monitor) resetForLink(proxyLink domain.LinkIdentity) {
	monitor.proxyLink = proxyLink
	monitor.lastProbe = time.Time{}
	monitor.ipv4 = familyState{}
	monitor.ipv6 = familyState{}
}

func (monitor *Monitor) applyObservation(family domain.AddressFamily, succeeded bool, observedAt time.Time) {
	state := monitor.family(family)
	if succeeded {
		state.failureCount = 0
		state.successCount = saturatingIncrement(state.successCount, monitor.configuration.SuccessThreshold)
		if state.successCount >= monitor.configuration.SuccessThreshold {
			state.capability = domain.InternetFamilyCapability{
				Initialized: true,
				Available:   true,
				ObservedAt:  observedAt,
				ValidUntil:  observedAt.Add(monitor.configuration.ProbeValidity),
			}
		}
		return
	}
	state.successCount = 0
	state.failureCount = saturatingIncrement(state.failureCount, monitor.configuration.FailureThreshold)
	if state.failureCount >= monitor.configuration.FailureThreshold {
		state.capability = domain.InternetFamilyCapability{
			Initialized: true,
			Available:   false,
			ObservedAt:  observedAt,
		}
	}
}

func (monitor *Monitor) family(family domain.AddressFamily) *familyState {
	if family == domain.IPv4 {
		return &monitor.ipv4
	}
	return &monitor.ipv6
}

func (monitor *Monitor) snapshot() domain.InternetCapabilitySnapshot {
	return domain.InternetCapabilitySnapshot{
		ProxyLink: monitor.proxyLink,
		IPv4:      monitor.ipv4.capability,
		IPv6:      monitor.ipv6.capability,
	}
}

func saturatingIncrement(value, maximum uint32) uint32 {
	if value >= maximum {
		return maximum
	}
	return value + 1
}
