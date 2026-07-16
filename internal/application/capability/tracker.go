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

type Tracker struct {
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

func NewTracker(configuration domain.InternetCapabilityConfiguration, packetMark uint32, prober port.InternetEgressProber, metrics port.InternetCapabilityMetrics) (*Tracker, error) {
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
	return &Tracker{
		configuration: configuration,
		packetMark:    packetMark,
		prober:        prober,
		metrics:       metrics,
		now:           time.Now,
		cycle:         make(chan struct{}, 1),
	}, nil
}

func (tracker *Tracker) Observe(ctx context.Context, proxyLink domain.LinkIdentity) (domain.InternetCapabilitySnapshot, error) {
	if ctx == nil {
		return domain.InternetCapabilitySnapshot{}, errors.New("capability observation context is required")
	}
	if err := proxyLink.Validate(); err != nil {
		return domain.InternetCapabilitySnapshot{}, fmt.Errorf("validate capability proxy link: %w", err)
	}
	select {
	case tracker.cycle <- struct{}{}:
		defer func() { <-tracker.cycle }()
	case <-ctx.Done():
		return domain.InternetCapabilitySnapshot{}, ctx.Err()
	}

	now := tracker.now()
	if now.IsZero() {
		return domain.InternetCapabilitySnapshot{}, errors.New("capability clock returned a zero time")
	}
	if tracker.proxyLink != proxyLink {
		tracker.resetForLink(proxyLink)
	}
	if !tracker.lastProbe.IsZero() && now.Before(tracker.lastProbe) {
		return tracker.snapshot(), errors.New("capability clock moved backwards")
	}
	if !tracker.probeDue(now) {
		snapshot := tracker.snapshot()
		tracker.metrics.RecordInternetCapabilitySnapshot(snapshot, now)
		return snapshot, nil
	}

	results := make(chan probeResult, 2)
	for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
		go tracker.probeFamily(ctx, proxyLink, family, results)
	}
	observations := [2]probeResult{<-results, <-results}
	for _, observation := range observations {
		result := port.InternetCapabilityProbeFailed
		if ctx.Err() != nil {
			result = port.InternetCapabilityProbeCanceled
		} else if observation.err == nil {
			result = port.InternetCapabilityProbeSucceeded
		}
		tracker.metrics.RecordInternetCapabilityProbe(observation.family, result)
	}
	if err := ctx.Err(); err != nil {
		return tracker.snapshot(), err
	}
	observedAt := tracker.now()
	if observedAt.IsZero() || observedAt.Before(now) {
		return tracker.snapshot(), errors.New("capability clock returned an invalid observation time")
	}
	for _, observation := range observations {
		tracker.applyObservation(observation.family, observation.err == nil, observedAt)
	}
	tracker.lastProbe = observedAt
	snapshot := tracker.snapshot()
	if err := snapshot.Validate(); err != nil {
		return domain.InternetCapabilitySnapshot{}, fmt.Errorf("validate capability snapshot: %w", err)
	}
	tracker.metrics.RecordInternetCapabilitySnapshot(snapshot, observedAt)
	return snapshot, nil
}

type probeResult struct {
	family domain.AddressFamily
	err    error
}

func (tracker *Tracker) probeFamily(ctx context.Context, proxyLink domain.LinkIdentity, family domain.AddressFamily, results chan<- probeResult) {
	probeContext, cancel := context.WithTimeout(ctx, tracker.configuration.ProbeTimeout)
	defer cancel()
	err := tracker.prober.Probe(probeContext, port.InternetEgressProbeRequest{
		Family: family, ProxyLink: proxyLink, PacketMark: tracker.packetMark,
	})
	results <- probeResult{family: family, err: err}
}

func (tracker *Tracker) probeDue(now time.Time) bool {
	if tracker.lastProbe.IsZero() || !now.Before(tracker.lastProbe.Add(tracker.configuration.ProbeInterval)) {
		return true
	}
	return expired(tracker.ipv4.capability, now) || expired(tracker.ipv6.capability, now)
}

func expired(capability domain.InternetFamilyCapability, now time.Time) bool {
	return capability.Available && now.After(capability.ValidUntil)
}

func (tracker *Tracker) resetForLink(proxyLink domain.LinkIdentity) {
	tracker.proxyLink = proxyLink
	tracker.lastProbe = time.Time{}
	tracker.ipv4 = familyState{}
	tracker.ipv6 = familyState{}
}

func (tracker *Tracker) applyObservation(family domain.AddressFamily, succeeded bool, observedAt time.Time) {
	state := tracker.family(family)
	if succeeded {
		state.failureCount = 0
		state.successCount = saturatingIncrement(state.successCount, tracker.configuration.SuccessThreshold)
		if state.successCount >= tracker.configuration.SuccessThreshold {
			state.capability = domain.InternetFamilyCapability{
				Initialized: true,
				Available:   true,
				ObservedAt:  observedAt,
				ValidUntil:  observedAt.Add(tracker.configuration.ProbeValidity),
			}
		}
		return
	}
	state.successCount = 0
	state.failureCount = saturatingIncrement(state.failureCount, tracker.configuration.FailureThreshold)
	if state.failureCount >= tracker.configuration.FailureThreshold {
		state.capability = domain.InternetFamilyCapability{
			Initialized: true,
			Available:   false,
			ObservedAt:  observedAt,
		}
	}
}

func (tracker *Tracker) family(family domain.AddressFamily) *familyState {
	if family == domain.IPv4 {
		return &tracker.ipv4
	}
	return &tracker.ipv6
}

func (tracker *Tracker) snapshot() domain.InternetCapabilitySnapshot {
	return domain.InternetCapabilitySnapshot{
		ProxyLink: tracker.proxyLink,
		IPv4:      tracker.ipv4.capability,
		IPv6:      tracker.ipv6.capability,
	}
}

func saturatingIncrement(value, maximum uint32) uint32 {
	if value >= maximum {
		return maximum
	}
	return value + 1
}
