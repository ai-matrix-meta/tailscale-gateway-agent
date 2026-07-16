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

func TestTrackerDebouncesBothFamiliesAndSkipsEarlyCycles(t *testing.T) {
	now := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	prober := newFakeProber()
	tracker := newTestTracker(t, prober, &now)
	link := domain.LinkIdentity{Index: 7, Name: "proxy-test"}

	first, err := tracker.Observe(context.Background(), link)
	if err != nil {
		t.Fatal(err)
	}
	if first.IPv4.Initialized || first.IPv6.Initialized || prober.callCount(domain.IPv4) != 1 || prober.callCount(domain.IPv6) != 1 {
		t.Fatalf("first success bypassed debounce: snapshot=%#v calls=%v", first, prober.calls)
	}
	if _, err := tracker.Observe(context.Background(), link); err != nil {
		t.Fatal(err)
	}
	if prober.callCount(domain.IPv4) != 1 || prober.callCount(domain.IPv6) != 1 {
		t.Fatal("tracker probed again before its interval")
	}

	now = now.Add(tracker.configuration.ProbeInterval)
	second, err := tracker.Observe(context.Background(), link)
	if err != nil {
		t.Fatal(err)
	}
	if !second.AvailableExitDefaultRoutes(now, link).Equal(domain.AllExitDefaultRoutes()) {
		t.Fatalf("second dual-stack success did not satisfy debounce: %#v", second)
	}
}

func TestTrackerDebouncesFailureAndRecoveryWithSaturatingCounters(t *testing.T) {
	now := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	prober := newFakeProber()
	tracker := newTestTracker(t, prober, &now)
	tracker.configuration.SuccessThreshold = 1
	link := domain.LinkIdentity{Index: 7, Name: "proxy-test"}
	if _, err := tracker.Observe(context.Background(), link); err != nil {
		t.Fatal(err)
	}
	tracker.configuration.SuccessThreshold = 2

	prober.setError(domain.IPv6, errors.New("ipv6 target unavailable"))
	now = now.Add(tracker.configuration.ProbeInterval)
	firstFailure, err := tracker.Observe(context.Background(), link)
	if err != nil {
		t.Fatal(err)
	}
	if !firstFailure.IPv6.Available {
		t.Fatal("single failure bypassed the configured failure threshold")
	}
	now = now.Add(tracker.configuration.ProbeInterval)
	secondFailure, err := tracker.Observe(context.Background(), link)
	if err != nil {
		t.Fatal(err)
	}
	if !secondFailure.IPv6.Initialized || secondFailure.IPv6.Available {
		t.Fatalf("failure threshold did not make ipv6 unavailable: %#v", secondFailure.IPv6)
	}
	for range 32 {
		now = now.Add(tracker.configuration.ProbeInterval)
		if _, err := tracker.Observe(context.Background(), link); err != nil {
			t.Fatal(err)
		}
	}
	if tracker.ipv6.failureCount != tracker.configuration.FailureThreshold {
		t.Fatalf("failure counter did not saturate: %d", tracker.ipv6.failureCount)
	}

	prober.setError(domain.IPv6, nil)
	now = now.Add(tracker.configuration.ProbeInterval)
	if snapshot, err := tracker.Observe(context.Background(), link); err != nil || snapshot.IPv6.Available {
		t.Fatalf("single recovery success bypassed debounce: snapshot=%#v err=%v", snapshot, err)
	}
	now = now.Add(tracker.configuration.ProbeInterval)
	recovered, err := tracker.Observe(context.Background(), link)
	if err != nil || !recovered.IPv6.Fresh(now) {
		t.Fatalf("ipv6 did not recover after its success threshold: snapshot=%#v err=%v", recovered, err)
	}
}

func TestTrackerTreatsExpiredSuccessAsStaleBeforeFailureDebounceCompletes(t *testing.T) {
	now := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	prober := newFakeProber()
	tracker := newTestTracker(t, prober, &now)
	tracker.configuration.SuccessThreshold = 1
	tracker.configuration.ProbeValidity = 15 * time.Second
	link := domain.LinkIdentity{Index: 7, Name: "proxy-test"}
	if _, err := tracker.Observe(context.Background(), link); err != nil {
		t.Fatal(err)
	}
	prober.setError(domain.IPv6, errors.New("ipv6 target unavailable"))
	now = now.Add(16 * time.Second)
	snapshot, err := tracker.Observe(context.Background(), link)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.IPv6.Available || snapshot.IPv6.Fresh(now) {
		t.Fatalf("expired success was not retained as stale during debounce: %#v", snapshot.IPv6)
	}
}

func TestTrackerInvalidatesOldLinkBeforeProbingReplacement(t *testing.T) {
	now := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	prober := newFakeProber()
	tracker := newTestTracker(t, prober, &now)
	tracker.configuration.SuccessThreshold = 1
	firstLink := domain.LinkIdentity{Index: 7, Name: "proxy-first"}
	secondLink := domain.LinkIdentity{Index: 8, Name: "proxy-second"}
	if _, err := tracker.Observe(context.Background(), firstLink); err != nil {
		t.Fatal(err)
	}
	prober.setError(domain.IPv4, errors.New("replacement unavailable"))
	replaced, err := tracker.Observe(context.Background(), secondLink)
	if err != nil {
		t.Fatal(err)
	}
	if replaced.ProxyLink != secondLink || replaced.IPv4.Available || !replaced.IPv6.Available {
		t.Fatalf("replacement link retained old capability: %#v", replaced)
	}
}

func TestTrackerRunsAtMostTwoFamilyProbesAndJoinsCancellation(t *testing.T) {
	now := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	prober := newFakeProber()
	prober.block = make(chan struct{})
	prober.entered = make(chan domain.AddressFamily, 2)
	metrics := &fakeCapabilityMetrics{}
	tracker := newTestTrackerWithMetrics(t, prober, metrics, &now)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := tracker.Observe(ctx, domain.LinkIdentity{Index: 7, Name: "proxy-test"})
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
		t.Fatal("tracker did not join canceled family probes")
	}
	if tracker.ipv4.successCount != 0 || tracker.ipv4.failureCount != 0 || tracker.ipv6.successCount != 0 || tracker.ipv6.failureCount != 0 {
		t.Fatal("inconclusive cancellation changed debounce state")
	}
	if metrics.probeCount(domain.IPv4, port.InternetCapabilityProbeCanceled) != 1 || metrics.probeCount(domain.IPv6, port.InternetCapabilityProbeCanceled) != 1 {
		t.Fatalf("inconclusive cycle metrics were not canceled for both families: %v", metrics.probes)
	}
}

func newTestTracker(t *testing.T, prober *fakeProber, now *time.Time) *Tracker {
	return newTestTrackerWithMetrics(t, prober, &fakeCapabilityMetrics{}, now)
}

func newTestTrackerWithMetrics(t *testing.T, prober *fakeProber, metrics *fakeCapabilityMetrics, now *time.Time) *Tracker {
	t.Helper()
	configuration := domain.InternetCapabilityConfiguration{
		ProbeInterval: 10 * time.Second, ProbeTimeout: time.Second, ProbeValidity: time.Minute,
		SuccessThreshold: 2, FailureThreshold: 2,
	}
	tracker, err := NewTracker(configuration, 0x11, prober, metrics)
	if err != nil {
		t.Fatal(err)
	}
	tracker.now = func() time.Time { return *now }
	return tracker
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
