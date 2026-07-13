package capability

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/port"
)

func TestMonitorDebouncesBothFamiliesAndSkipsEarlyCycles(t *testing.T) {
	now := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	prober := newFakeProber()
	monitor := newTestMonitor(t, prober, &now)
	link := domain.LinkIdentity{Index: 7, Name: "proxy-test"}

	first, err := monitor.Observe(context.Background(), link)
	if err != nil {
		t.Fatal(err)
	}
	if first.IPv4.Initialized || first.IPv6.Initialized || prober.callCount(domain.IPv4) != 1 || prober.callCount(domain.IPv6) != 1 {
		t.Fatalf("first success bypassed debounce: snapshot=%#v calls=%v", first, prober.calls)
	}
	if _, err := monitor.Observe(context.Background(), link); err != nil {
		t.Fatal(err)
	}
	if prober.callCount(domain.IPv4) != 1 || prober.callCount(domain.IPv6) != 1 {
		t.Fatal("monitor probed again before its interval")
	}

	now = now.Add(monitor.configuration.ProbeInterval)
	second, err := monitor.Observe(context.Background(), link)
	if err != nil {
		t.Fatal(err)
	}
	if !second.ExitAvailable(now, link) {
		t.Fatalf("second dual-stack success did not satisfy debounce: %#v", second)
	}
}

func TestMonitorDebouncesFailureAndRecoveryWithSaturatingCounters(t *testing.T) {
	now := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	prober := newFakeProber()
	monitor := newTestMonitor(t, prober, &now)
	monitor.configuration.SuccessThreshold = 1
	link := domain.LinkIdentity{Index: 7, Name: "proxy-test"}
	if _, err := monitor.Observe(context.Background(), link); err != nil {
		t.Fatal(err)
	}
	monitor.configuration.SuccessThreshold = 2

	prober.setError(domain.IPv6, errors.New("ipv6 target unavailable"))
	now = now.Add(monitor.configuration.ProbeInterval)
	firstFailure, err := monitor.Observe(context.Background(), link)
	if err != nil {
		t.Fatal(err)
	}
	if !firstFailure.IPv6.Available {
		t.Fatal("single failure bypassed the configured failure threshold")
	}
	now = now.Add(monitor.configuration.ProbeInterval)
	secondFailure, err := monitor.Observe(context.Background(), link)
	if err != nil {
		t.Fatal(err)
	}
	if !secondFailure.IPv6.Initialized || secondFailure.IPv6.Available {
		t.Fatalf("failure threshold did not make ipv6 unavailable: %#v", secondFailure.IPv6)
	}
	for range 32 {
		now = now.Add(monitor.configuration.ProbeInterval)
		if _, err := monitor.Observe(context.Background(), link); err != nil {
			t.Fatal(err)
		}
	}
	if monitor.ipv6.failureCount != monitor.configuration.FailureThreshold {
		t.Fatalf("failure counter did not saturate: %d", monitor.ipv6.failureCount)
	}

	prober.setError(domain.IPv6, nil)
	now = now.Add(monitor.configuration.ProbeInterval)
	if snapshot, err := monitor.Observe(context.Background(), link); err != nil || snapshot.IPv6.Available {
		t.Fatalf("single recovery success bypassed debounce: snapshot=%#v err=%v", snapshot, err)
	}
	now = now.Add(monitor.configuration.ProbeInterval)
	recovered, err := monitor.Observe(context.Background(), link)
	if err != nil || !recovered.IPv6.Fresh(now) {
		t.Fatalf("ipv6 did not recover after its success threshold: snapshot=%#v err=%v", recovered, err)
	}
}

func TestMonitorTreatsExpiredSuccessAsStaleBeforeFailureDebounceCompletes(t *testing.T) {
	now := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	prober := newFakeProber()
	monitor := newTestMonitor(t, prober, &now)
	monitor.configuration.SuccessThreshold = 1
	monitor.configuration.ProbeValidity = 15 * time.Second
	link := domain.LinkIdentity{Index: 7, Name: "proxy-test"}
	if _, err := monitor.Observe(context.Background(), link); err != nil {
		t.Fatal(err)
	}
	prober.setError(domain.IPv6, errors.New("ipv6 target unavailable"))
	now = now.Add(16 * time.Second)
	snapshot, err := monitor.Observe(context.Background(), link)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.IPv6.Available || snapshot.IPv6.Fresh(now) {
		t.Fatalf("expired success was not retained as stale during debounce: %#v", snapshot.IPv6)
	}
}

func TestMonitorInvalidatesOldLinkBeforeProbingReplacement(t *testing.T) {
	now := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	prober := newFakeProber()
	monitor := newTestMonitor(t, prober, &now)
	monitor.configuration.SuccessThreshold = 1
	firstLink := domain.LinkIdentity{Index: 7, Name: "proxy-first"}
	secondLink := domain.LinkIdentity{Index: 8, Name: "proxy-second"}
	if _, err := monitor.Observe(context.Background(), firstLink); err != nil {
		t.Fatal(err)
	}
	prober.setError(domain.IPv4, errors.New("replacement unavailable"))
	replaced, err := monitor.Observe(context.Background(), secondLink)
	if err != nil {
		t.Fatal(err)
	}
	if replaced.ProxyLink != secondLink || replaced.IPv4.Available || !replaced.IPv6.Available {
		t.Fatalf("replacement link retained old capability: %#v", replaced)
	}
}

func TestMonitorRunsAtMostTwoFamilyProbesAndJoinsCancellation(t *testing.T) {
	now := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	prober := newFakeProber()
	prober.block = make(chan struct{})
	prober.entered = make(chan domain.AddressFamily, 2)
	metrics := &fakeCapabilityMetrics{}
	monitor := newTestMonitorWithMetrics(t, prober, metrics, &now)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := monitor.Observe(ctx, domain.LinkIdentity{Index: 7, Name: "proxy-test"})
		result <- err
	}()
	for range 2 {
		select {
		case <-prober.entered:
		case <-time.After(time.Second):
			cancel()
			t.Fatal("both family probes did not start")
		}
	}
	if prober.maximumInFlight() != 2 {
		t.Fatalf("maximum concurrent probes = %d, want 2", prober.maximumInFlight())
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("monitor did not join canceled family probes")
	}
	if monitor.ipv4.successCount != 0 || monitor.ipv4.failureCount != 0 || monitor.ipv6.successCount != 0 || monitor.ipv6.failureCount != 0 {
		t.Fatal("inconclusive cancellation changed debounce state")
	}
	if metrics.probeCount(domain.IPv4, port.InternetCapabilityProbeCanceled) != 1 || metrics.probeCount(domain.IPv6, port.InternetCapabilityProbeCanceled) != 1 {
		t.Fatalf("inconclusive cycle metrics were not canceled for both families: %v", metrics.probes)
	}
}

func newTestMonitor(t *testing.T, prober *fakeProber, now *time.Time) *Monitor {
	return newTestMonitorWithMetrics(t, prober, &fakeCapabilityMetrics{}, now)
}

func newTestMonitorWithMetrics(t *testing.T, prober *fakeProber, metrics *fakeCapabilityMetrics, now *time.Time) *Monitor {
	t.Helper()
	configuration := domain.InternetCapabilityConfiguration{
		ProbeInterval: 10 * time.Second, ProbeTimeout: time.Second, ProbeValidity: time.Minute,
		SuccessThreshold: 2, FailureThreshold: 2,
	}
	monitor, err := NewMonitor(configuration, 0x11, prober, metrics)
	if err != nil {
		t.Fatal(err)
	}
	monitor.now = func() time.Time { return *now }
	return monitor
}

type fakeProber struct {
	mutex       sync.Mutex
	calls       map[domain.AddressFamily]int
	errors      map[domain.AddressFamily]error
	entered     chan domain.AddressFamily
	block       <-chan struct{}
	inFlight    int
	maxInFlight int
}

type fakeCapabilityMetrics struct {
	mutex  sync.Mutex
	probes map[domain.AddressFamily]map[port.InternetCapabilityProbeResult]int
}

func (metrics *fakeCapabilityMetrics) RecordInternetCapabilityProbe(family domain.AddressFamily, result port.InternetCapabilityProbeResult) {
	metrics.mutex.Lock()
	defer metrics.mutex.Unlock()
	if metrics.probes == nil {
		metrics.probes = make(map[domain.AddressFamily]map[port.InternetCapabilityProbeResult]int)
	}
	if metrics.probes[family] == nil {
		metrics.probes[family] = make(map[port.InternetCapabilityProbeResult]int)
	}
	metrics.probes[family][result]++
}

func (*fakeCapabilityMetrics) RecordInternetCapabilitySnapshot(domain.InternetCapabilitySnapshot, time.Time) {
}

func (metrics *fakeCapabilityMetrics) probeCount(family domain.AddressFamily, result port.InternetCapabilityProbeResult) int {
	metrics.mutex.Lock()
	defer metrics.mutex.Unlock()
	return metrics.probes[family][result]
}

func newFakeProber() *fakeProber {
	return &fakeProber{calls: make(map[domain.AddressFamily]int), errors: make(map[domain.AddressFamily]error)}
}

func (prober *fakeProber) Probe(ctx context.Context, request port.InternetEgressProbeRequest) error {
	prober.mutex.Lock()
	prober.calls[request.Family]++
	prober.inFlight++
	if prober.inFlight > prober.maxInFlight {
		prober.maxInFlight = prober.inFlight
	}
	entered, block, probeErr := prober.entered, prober.block, prober.errors[request.Family]
	prober.mutex.Unlock()
	defer func() {
		prober.mutex.Lock()
		prober.inFlight--
		prober.mutex.Unlock()
	}()
	if entered != nil {
		entered <- request.Family
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return probeErr
}

func (prober *fakeProber) setError(family domain.AddressFamily, err error) {
	prober.mutex.Lock()
	defer prober.mutex.Unlock()
	prober.errors[family] = err
}

func (prober *fakeProber) callCount(family domain.AddressFamily) int {
	prober.mutex.Lock()
	defer prober.mutex.Unlock()
	return prober.calls[family]
}

func (prober *fakeProber) maximumInFlight() int {
	prober.mutex.Lock()
	defer prober.mutex.Unlock()
	return prober.maxInFlight
}
