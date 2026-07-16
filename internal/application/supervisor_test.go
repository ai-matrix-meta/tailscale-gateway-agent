package application

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/port"
)

func TestNetworkEventCancelsActiveReconcileAndSchedulesFreshDiscovery(t *testing.T) {
	fixture := newReconcilerFixture(t)
	if err := fixture.reconciler.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	fixture.discovery.entered = entered
	fixture.discovery.release = release

	status := NewStatus(time.Minute)
	metrics := newFakeMetrics()
	events := newFakeNetworkEvents()
	controller, err := NewController(fixture.configuration, fixture.reconciler, events, newFakeTailnetEvents(), status, metrics, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- controller.Run(ctx) }()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("startup reconciliation did not enter discovery")
	}
	events.events <- domain.NetworkEvent{Kind: domain.NetworkEventRoute}
	waitForDirtyEpoch(t, status, 2)
	if status.HealthSnapshot().Ready {
		t.Fatal("network event did not immediately revoke readiness")
	}
	waitForFailedRuns(t, status, 1)
	close(release)

	select {
	case <-metrics.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("event-triggered follow-up reconciliation did not become ready")
	}
	if fixture.discovery.calls < 2 {
		t.Fatalf("event that arrived during reconciliation was lost; discovery calls=%d", fixture.discovery.calls)
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatalf("controller shutdown failed: %v", err)
	}
}

func TestTailnetEventCancelsActiveReconcileAndSchedulesFreshObservation(t *testing.T) {
	fixture := newReconcilerFixture(t)
	if err := fixture.reconciler.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	fixture.discovery.entered = entered
	fixture.discovery.release = release

	status := NewStatus(time.Minute)
	metrics := newFakeMetrics()
	tailnetEvents := newFakeTailnetEvents()
	controller, err := NewController(
		fixture.configuration, fixture.reconciler, newFakeNetworkEvents(), tailnetEvents,
		status, metrics, slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- controller.Run(ctx) }()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("startup reconciliation did not enter discovery")
	}
	tailnetEvents.events <- domain.TailnetEvent{Kind: domain.TailnetEventSelfNode}
	waitForDirtyEpoch(t, status, 2)
	if status.HealthSnapshot().Ready {
		t.Fatal("tailnet event did not immediately revoke readiness")
	}
	waitForFailedRuns(t, status, 1)
	close(release)

	select {
	case <-metrics.ready:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("tailnet-event follow-up reconciliation did not become ready")
	}
	if fixture.discovery.calls < 2 {
		t.Fatalf("tailnet event did not schedule a fresh authoritative observation; discovery calls=%d", fixture.discovery.calls)
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatalf("controller shutdown failed: %v", err)
	}
}

func TestTailnetWatchReconnectsWithoutStoppingAuthoritativePolling(t *testing.T) {
	fixture := newReconcilerFixture(t)
	if err := fixture.reconciler.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	status := NewStatus(time.Minute)
	metrics := newFakeMetrics()
	tailnetEvents := newRecoveringTailnetEvents()
	controller, err := NewController(
		fixture.configuration, fixture.reconciler, newFakeNetworkEvents(), tailnetEvents,
		status, metrics, slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatal(err)
	}
	controller.tailnetWatchInitialDelay = time.Millisecond
	controller.tailnetWatchMaximumDelay = 4 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- controller.Run(ctx) }()
	for want := 1; want <= 2; want++ {
		select {
		case got := <-tailnetEvents.subscribed:
			if got != want {
				cancel()
				t.Fatalf("subscription attempt = %d, want %d", got, want)
			}
		case <-time.After(time.Second):
			cancel()
			t.Fatalf("tailnet watch subscription attempt %d did not occur", want)
		}
	}
	select {
	case <-metrics.ready:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("authoritative reconciliation stopped while the Tailnet watch reconnected")
	}
	select {
	case runErr := <-result:
		cancel()
		t.Fatalf("controller exited on a non-authoritative watch failure: %v", runErr)
	default:
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatalf("controller shutdown failed: %v", err)
	}
}

func TestTailnetWatchBackoffSaturates(t *testing.T) {
	if got := nextTailnetWatchDelay(time.Second, 8*time.Second); got != 2*time.Second {
		t.Fatalf("first retry delay = %s, want 2s", got)
	}
	if got := nextTailnetWatchDelay(5*time.Second, 8*time.Second); got != 8*time.Second {
		t.Fatalf("overflowing retry delay = %s, want 8s", got)
	}
	if got := nextTailnetWatchDelay(8*time.Second, 8*time.Second); got != 8*time.Second {
		t.Fatalf("saturated retry delay = %s, want 8s", got)
	}
}

func TestControllerSchedulesCapabilityAuditAtTheConfiguredCadence(t *testing.T) {
	fixture := newReconcilerFixture(t)
	if err := fixture.reconciler.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	metrics := newFakeMetrics()
	controller, err := NewController(
		fixture.configuration, fixture.reconciler, newFakeNetworkEvents(), newFakeTailnetEvents(),
		NewStatus(time.Minute), metrics, slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatal(err)
	}
	controller.configuration.InternetCapability.ProbeInterval = 10 * time.Millisecond
	controller.configuration.Runtime.EventDebounce = time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- controller.Run(ctx) }()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case trigger := <-metrics.triggers:
			if trigger == "capability_audit" {
				cancel()
				if err := <-result; err != nil {
					t.Fatalf("controller shutdown failed: %v", err)
				}
				return
			}
		case runErr := <-result:
			cancel()
			t.Fatalf("controller exited before a capability audit: %v", runErr)
		case <-deadline.C:
			cancel()
			<-result
			t.Fatal("configured capability audit did not schedule reconciliation")
		}
	}
}

func waitForFailedRuns(t *testing.T, status *Status, minimum uint64) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if status.HealthSnapshot().FailedRuns >= minimum {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("failed reconciliation count did not reach %d", minimum)
		case <-ticker.C:
		}
	}
}

func TestControllerEnforcesConfiguredReconcileTimeout(t *testing.T) {
	fixture := newReconcilerFixture(t)
	if err := fixture.reconciler.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 1)
	fixture.discovery.entered = entered
	fixture.discovery.release = make(chan struct{})
	fixture.configuration.Runtime.ReconcileTimeout = 20 * time.Millisecond

	status := NewStatus(time.Minute)
	controller, err := NewController(
		fixture.configuration,
		fixture.reconciler,
		newFakeNetworkEvents(),
		newFakeTailnetEvents(),
		status,
		newFakeMetrics(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- controller.Run(ctx) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("reconciliation did not enter blocked discovery")
	}
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for status.HealthSnapshot().FailedRuns == 0 {
		select {
		case <-deadline.C:
			cancel()
			t.Fatal("configured reconcile timeout did not fail the blocked pass")
		case <-time.After(time.Millisecond):
		}
	}
	if !strings.Contains(status.HealthSnapshot().LastError, context.DeadlineExceeded.Error()) {
		t.Fatalf("timeout failure was not reported: %#v", status.HealthSnapshot())
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatalf("controller shutdown failed: %v", err)
	}
}

func TestSupervisorPrepareUsesConfiguredReconcileTimeout(t *testing.T) {
	fixture := newReconcilerFixture(t)
	fixture.discovery.proxyTunnelEntered = make(chan struct{}, 1)
	fixture.discovery.proxyTunnelRelease = make(chan struct{})
	status := NewStatus(time.Minute)
	controller, err := NewController(
		fixture.configuration,
		fixture.reconciler,
		newFakeNetworkEvents(),
		newFakeTailnetEvents(),
		status,
		newFakeMetrics(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatal(err)
	}
	launcher := &fakeProcessLauncher{recorder: fixture.recorder}
	processSpecification := domain.NewProcessSpec("/usr/local/bin/containerboot", nil, []string{"PATH=/usr/local/bin:/usr/bin"})
	supervisor, err := NewSupervisor(fixture.configuration, SupervisorDependencies{
		Coordinator: directCoordinator{},
		Reconciler:  fixture.reconciler,
		Controller:  controller,
		Status:      status,
		Health:      blockingHealthServer{},
		Processes:   launcher,
		Process:     &processSpecification,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	supervisor.configuration.Runtime.ReconcileTimeout = 20 * time.Millisecond

	result := make(chan error, 1)
	go func() { result <- supervisor.runOwned(context.Background()) }()
	select {
	case <-fixture.discovery.proxyTunnelEntered:
	case <-time.After(time.Second):
		t.Fatal("startup preparation did not enter proxy tunnel discovery")
	}
	select {
	case runErr := <-result:
		if runErr == nil || !errors.Is(runErr, context.DeadlineExceeded) {
			t.Fatalf("startup preparation did not report its configured timeout: %v", runErr)
		}
	case <-time.After(time.Second):
		t.Fatal("startup preparation ignored its configured timeout")
	}
	if slices.Contains(fixture.recorder.snapshot(), "containerboot-started") {
		t.Fatal("containerboot started after preparation timed out")
	}
}

func waitForDirtyEpoch(t *testing.T, status *Status, minimum uint64) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		status.mutex.RLock()
		epoch := status.dirtyEpoch
		status.mutex.RUnlock()
		if epoch >= minimum {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("dirty epoch did not reach %d; got %d", minimum, epoch)
		case <-ticker.C:
		}
	}
}

func TestSupervisorShutdownOrderInSupervisedMode(t *testing.T) {
	fixture := newReconcilerFixture(t)
	status := NewStatus(time.Minute)
	metrics := newFakeMetrics()
	events := newFakeNetworkEvents()
	controller, err := NewController(fixture.configuration, fixture.reconciler, events, newFakeTailnetEvents(), status, metrics, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	launcher := &fakeProcessLauncher{recorder: fixture.recorder}
	processSpecification := domain.NewProcessSpec("/usr/local/bin/containerboot", nil, []string{"PATH=/usr/local/bin:/usr/bin"})
	supervisor, err := NewSupervisor(fixture.configuration, SupervisorDependencies{
		Coordinator: directCoordinator{},
		Reconciler:  fixture.reconciler,
		Controller:  controller,
		Status:      status,
		Health:      blockingHealthServer{},
		Processes:   launcher,
		Process:     &processSpecification,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- supervisor.Run(ctx) }()
	select {
	case <-metrics.ready:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("supervisor did not become ready")
	}
	startup := fixture.recorder.snapshot()
	quarantineIndex := slices.Index(startup, "nftables-closed")
	processIndex := slices.Index(startup, "containerboot-started")
	if quarantineIndex < 0 || processIndex < 0 || quarantineIndex > processIndex {
		cancel()
		t.Fatalf("supervised process started before quarantine: %v", startup)
	}

	fixture.recorder.reset()
	cancel()
	if err := <-result; err != nil {
		t.Fatalf("supervisor shutdown failed: %v", err)
	}
	want := []string{"nftables-closed", "routing", "advertisements-cleared", "containerboot-terminated"}
	if got := fixture.recorder.snapshot(); !slices.Equal(got, want) {
		t.Fatalf("unexpected shutdown order: got %v, want %v", got, want)
	}
}

func TestCoordinationLossFailsClosedBeforeTerminatingSupervisedProcess(t *testing.T) {
	fixture := newReconcilerFixture(t)
	status := NewStatus(time.Minute)
	metrics := newFakeMetrics()
	controller, err := NewController(fixture.configuration, fixture.reconciler, newFakeNetworkEvents(), newFakeTailnetEvents(), status, metrics, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	coordinator := &revocableCoordinator{revoke: make(chan struct{})}
	launcher := &fakeProcessLauncher{recorder: fixture.recorder}
	processSpecification := domain.NewProcessSpec("/usr/local/bin/containerboot", nil, []string{"PATH=/usr/local/bin:/usr/bin"})
	supervisor, err := NewSupervisor(fixture.configuration, SupervisorDependencies{
		Coordinator: coordinator,
		Reconciler:  fixture.reconciler,
		Controller:  controller,
		Status:      status,
		Health:      blockingHealthServer{},
		Processes:   launcher,
		Process:     &processSpecification,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() { result <- supervisor.Run(context.Background()) }()
	select {
	case <-metrics.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("supervisor did not become ready before coordination revocation")
	}
	fixture.recorder.reset()
	close(coordinator.revoke)
	select {
	case runErr := <-result:
		if !errors.Is(runErr, errTestCoordinationLost) {
			t.Fatalf("coordination loss was not propagated: %v", runErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("supervisor did not stop after coordination loss")
	}
	want := []string{"nftables-closed", "routing", "advertisements-cleared", "containerboot-terminated"}
	if got := fixture.recorder.snapshot(); !slices.Equal(got, want) {
		t.Fatalf("unexpected coordination-loss shutdown order: got %v, want %v", got, want)
	}
}

func TestSupervisorCancellationTakesOverAnActiveControllerFailClosedPass(t *testing.T) {
	fixture := newReconcilerFixture(t)
	fixture.configuration.Runtime.ShutdownTimeout = 5 * time.Second
	status := NewStatus(time.Minute)
	metrics := newFakeMetrics()
	events := newFakeNetworkEvents()
	controller, err := NewController(fixture.configuration, fixture.reconciler, events, newFakeTailnetEvents(), status, metrics, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	launcher := &fakeProcessLauncher{recorder: fixture.recorder}
	processSpecification := domain.NewProcessSpec("/usr/local/bin/containerboot", nil, []string{"PATH=/usr/local/bin:/usr/bin"})
	supervisor, err := NewSupervisor(fixture.configuration, SupervisorDependencies{
		Coordinator: directCoordinator{},
		Reconciler:  fixture.reconciler,
		Controller:  controller,
		Status:      status,
		Health:      blockingHealthServer{},
		Processes:   launcher,
		Process:     &processSpecification,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- supervisor.Run(ctx) }()
	select {
	case <-metrics.ready:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("supervisor did not become ready")
	}

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	fixture.packetFilter.blockNextApply(entered, release)
	fixture.discovery.mutex.Lock()
	fixture.discovery.err = errors.New("route discovery failed")
	fixture.discovery.mutex.Unlock()
	fixture.recorder.reset()
	events.events <- domain.NetworkEvent{Kind: domain.NetworkEventRoute}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		cancel()
		close(release)
		t.Fatal("Controller did not enter fail-closed handling")
	}

	// Cancel after Controller has crossed its live-failure check. Its fail-closed
	// context must be canceled so Supervisor can execute the one complete shutdown.
	cancel()
	select {
	case runErr := <-result:
		if runErr != nil {
			t.Fatalf("supervisor shutdown failed: %v", runErr)
		}
	case <-time.After(time.Second):
		close(release)
		<-result
		t.Fatal("Supervisor waited for Controller's independent shutdown timeout")
	}
	close(release)

	want := []string{"nftables-closed", "routing", "advertisements-cleared", "containerboot-terminated"}
	if got := fixture.recorder.snapshot(); !slices.Equal(got, want) {
		t.Fatalf("cancellation executed duplicate or misordered shutdown work: got %v, want %v", got, want)
	}
}

type fakeNetworkEvents struct {
	events chan domain.NetworkEvent
	errors chan error
	once   sync.Once
}

type fakeTailnetEvents struct {
	events chan domain.TailnetEvent
	errors chan error
	once   sync.Once
}

func newFakeTailnetEvents() *fakeTailnetEvents {
	return &fakeTailnetEvents{events: make(chan domain.TailnetEvent, 8), errors: make(chan error, 1)}
}

func (source *fakeTailnetEvents) Subscribe(ctx context.Context) (<-chan domain.TailnetEvent, <-chan error, error) {
	go func() {
		<-ctx.Done()
		source.once.Do(func() {
			close(source.events)
			close(source.errors)
		})
	}()
	return source.events, source.errors, nil
}

type recoveringTailnetEvents struct {
	mutex      sync.Mutex
	attempts   int
	subscribed chan int
}

func newRecoveringTailnetEvents() *recoveringTailnetEvents {
	return &recoveringTailnetEvents{subscribed: make(chan int, 4)}
}

func (source *recoveringTailnetEvents) Subscribe(ctx context.Context) (<-chan domain.TailnetEvent, <-chan error, error) {
	source.mutex.Lock()
	source.attempts++
	attempt := source.attempts
	source.mutex.Unlock()
	source.subscribed <- attempt
	if attempt == 1 {
		return nil, nil, errors.New("tailscale LocalAPI watch is temporarily unavailable")
	}
	events := make(chan domain.TailnetEvent)
	eventErrors := make(chan error)
	go func() {
		<-ctx.Done()
		close(events)
		close(eventErrors)
	}()
	return events, eventErrors, nil
}

func newFakeNetworkEvents() *fakeNetworkEvents {
	return &fakeNetworkEvents{events: make(chan domain.NetworkEvent, 8), errors: make(chan error, 1)}
}

func (source *fakeNetworkEvents) Subscribe(ctx context.Context) (<-chan domain.NetworkEvent, <-chan error, error) {
	go func() {
		<-ctx.Done()
		source.once.Do(func() {
			close(source.events)
			close(source.errors)
		})
	}()
	return source.events, source.errors, nil
}

type fakeMetrics struct {
	ready    chan struct{}
	triggers chan string
	once     sync.Once
}

func newFakeMetrics() *fakeMetrics {
	return &fakeMetrics{ready: make(chan struct{}), triggers: make(chan string, 64)}
}

func (metrics *fakeMetrics) RecordReconcile(trigger string, _ time.Duration, _ domain.ReconcileReport, _ error) {
	select {
	case metrics.triggers <- trigger:
	default:
	}
}

func (metrics *fakeMetrics) SetReady(ready bool) {
	if ready {
		metrics.once.Do(func() { close(metrics.ready) })
	}
}

type directCoordinator struct{}

func (directCoordinator) Run(ctx context.Context, owned func(context.Context) error) error {
	return owned(ctx)
}

var errTestCoordinationLost = errors.New("test coordination ownership lost")

type revocableCoordinator struct {
	revoke chan struct{}
}

func (coordinator *revocableCoordinator) Run(parent context.Context, owned func(context.Context) error) error {
	ownedContext, cancelOwned := context.WithCancelCause(context.WithoutCancel(parent))
	ownedResult := make(chan error, 1)
	go func() { ownedResult <- owned(ownedContext) }()
	select {
	case <-coordinator.revoke:
		cancelOwned(errTestCoordinationLost)
		return errors.Join(errTestCoordinationLost, <-ownedResult)
	case <-parent.Done():
		cancelOwned(parent.Err())
		return <-ownedResult
	case ownedErr := <-ownedResult:
		cancelOwned(ownedErr)
		return ownedErr
	}
}

type blockingHealthServer struct{}

func (blockingHealthServer) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

type fakeProcessLauncher struct {
	recorder *operationRecorder
}

func (launcher *fakeProcessLauncher) Start(domain.ProcessSpec) (port.ManagedProcess, error) {
	launcher.recorder.add("containerboot-started")
	return &fakeManagedProcess{done: make(chan struct{}), recorder: launcher.recorder}, nil
}

type fakeManagedProcess struct {
	done      chan struct{}
	recorder  *operationRecorder
	closeOnce sync.Once
}

func (process *fakeManagedProcess) Wait() error {
	<-process.done
	return errors.New("terminated")
}

func (process *fakeManagedProcess) Terminate(context.Context) error {
	process.recorder.add("containerboot-terminated")
	process.closeOnce.Do(func() { close(process.done) })
	return nil
}
