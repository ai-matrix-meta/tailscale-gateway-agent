package application

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/port"
)

type Runner struct {
	configuration            domain.Configuration
	controller               *Controller
	networkEvents            port.NetworkEventSource
	tailnetEvents            port.TailnetEventSource
	status                   *Status
	metrics                  port.MetricsRecorder
	logger                   *slog.Logger
	tailnetWatchInitialDelay time.Duration
	tailnetWatchMaximumDelay time.Duration
	activeMutex              sync.Mutex
	activeCancel             context.CancelFunc
}

func NewRunner(configuration domain.Configuration, controller *Controller, networkEvents port.NetworkEventSource, tailnetEvents port.TailnetEventSource, status *Status, metrics port.MetricsRecorder, logger *slog.Logger) (*Runner, error) {
	if controller == nil || networkEvents == nil || tailnetEvents == nil || status == nil || metrics == nil {
		return nil, errors.New("all runner dependencies are required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Runner{
		configuration: configuration, controller: controller, networkEvents: networkEvents, tailnetEvents: tailnetEvents,
		status: status, metrics: metrics, logger: logger,
		tailnetWatchInitialDelay: time.Second, tailnetWatchMaximumDelay: 30 * time.Second,
	}, nil
}

func (runner *Runner) Run(ctx context.Context) error {
	subscriptionContext, cancelSubscription := context.WithCancel(ctx)
	events, eventErrors, err := runner.networkEvents.Subscribe(subscriptionContext)
	if err != nil {
		cancelSubscription()
		return fmt.Errorf("subscribe to network events: %w", err)
	}
	if events == nil || eventErrors == nil {
		cancelSubscription()
		return errors.New("network event source returned nil channels")
	}

	triggers := make(chan string, 1)
	collectorErrors := make(chan error, 1)
	collectorDone := make(chan struct{})
	go runner.collectNetworkEvents(subscriptionContext, events, eventErrors, triggers, collectorErrors, collectorDone)
	tailnetCollectorDone := make(chan struct{})
	go runner.collectTailnetEvents(subscriptionContext, triggers, tailnetCollectorDone)
	defer func() {
		cancelSubscription()
		<-collectorDone
		<-tailnetCollectorDone
	}()

	auditTicker := time.NewTicker(runner.configuration.Runtime.AuditInterval)
	defer auditTicker.Stop()
	preferenceTicker := time.NewTicker(runner.configuration.Tailnet.PreferenceAuditInterval)
	defer preferenceTicker.Stop()
	var capabilityTicker *time.Ticker
	var capabilityTick <-chan time.Time
	if runner.configuration.Tailnet.AdvertiseExitNode {
		capabilityTicker = time.NewTicker(runner.configuration.InternetCapability.ProbeInterval)
		defer capabilityTicker.Stop()
		capabilityTick = capabilityTicker.C
	}

	var dnsTicker *time.Ticker
	var dnsTick <-chan time.Time
	if runner.configuration.PacketFilter.LocalEgress.Enabled {
		dnsTicker = time.NewTicker(runner.configuration.PacketFilter.LocalEgress.RefreshInterval)
		defer dnsTicker.Stop()
		dnsTick = dnsTicker.C
	}

	retryTimer := time.NewTimer(time.Hour)
	stopTimer(retryTimer)
	defer retryTimer.Stop()
	var retryTick <-chan time.Time
	retryDelay := time.Second

	debounceTimer := time.NewTimer(time.Hour)
	stopTimer(debounceTimer)
	defer debounceTimer.Stop()
	var debounceTick <-chan time.Time
	pendingTrigger := ""
	schedule := func(trigger string) {
		if pendingTrigger == "" {
			pendingTrigger = trigger
		} else if pendingTrigger != trigger {
			pendingTrigger = "coalesced"
		}
		if debounceTick == nil {
			resetTimer(debounceTimer, runner.configuration.Runtime.EventDebounce)
			debounceTick = debounceTimer.C
		}
	}

	runner.status.MarkDirty()
	runner.metrics.SetReady(false)
	retryDelay, retryTick = runner.execute(ctx, "startup", retryTimer, retryDelay)

	for {
		select {
		case <-ctx.Done():
			return nil
		case trigger := <-triggers:
			schedule(trigger)
		case eventErr := <-collectorErrors:
			if eventErr != nil {
				return fmt.Errorf("network event source: %w", eventErr)
			}
		case <-debounceTick:
			debounceTick = nil
			trigger := pendingTrigger
			pendingTrigger = ""
			retryDelay, retryTick = runner.execute(ctx, trigger, retryTimer, retryDelay)
		case <-auditTicker.C:
			schedule("audit")
		case <-preferenceTicker.C:
			schedule("tailnet_audit")
		case <-capabilityTick:
			schedule("capability_audit")
		case <-dnsTick:
			schedule("dns_refresh")
		case <-retryTick:
			retryDelay, retryTick = runner.execute(ctx, "retry", retryTimer, retryDelay)
		}
	}
}

func (runner *Runner) collectTailnetEvents(ctx context.Context, triggers chan<- string, done chan<- struct{}) {
	defer close(done)
	retryDelay := runner.tailnetWatchInitialDelay
	for ctx.Err() == nil {
		events, eventErrors, err := runner.tailnetEvents.Subscribe(ctx)
		observedEvent := false
		if err == nil {
			if events == nil || eventErrors == nil {
				err = errors.New("tailnet event source returned nil channels")
			} else {
				observedEvent, err = runner.consumeTailnetEvents(ctx, events, eventErrors, triggers)
			}
		}
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			err = errors.New("tailnet event stream closed unexpectedly")
		}
		if observedEvent {
			retryDelay = runner.tailnetWatchInitialDelay
		}
		runner.logger.WarnContext(ctx, "tailscale event watch unavailable; authoritative polling remains active", "error", err, "retry_in", retryDelay)
		if !waitForTailnetWatchRetry(ctx, retryDelay) {
			return
		}
		retryDelay = nextTailnetWatchDelay(retryDelay, runner.tailnetWatchMaximumDelay)
	}
}

func (runner *Runner) consumeTailnetEvents(ctx context.Context, events <-chan domain.TailnetEvent, eventErrors <-chan error, triggers chan<- string) (bool, error) {
	observed := false
	for events != nil || eventErrors != nil {
		select {
		case <-ctx.Done():
			return observed, nil
		case event, open := <-events:
			if !open {
				events = nil
				continue
			}
			if err := event.Validate(); err != nil {
				return observed, fmt.Errorf("validate Tailnet event: %w", err)
			}
			observed = true
			runner.status.MarkDirty()
			runner.metrics.SetReady(false)
			runner.cancelActiveReconcile()
			select {
			case triggers <- "tailnet_event":
			default:
			}
		case eventErr, open := <-eventErrors:
			if !open {
				eventErrors = nil
				continue
			}
			if eventErr != nil {
				return observed, eventErr
			}
		}
	}
	return observed, nil
}

func waitForTailnetWatchRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func nextTailnetWatchDelay(current, maximum time.Duration) time.Duration {
	if current >= maximum || current > maximum/2 {
		return maximum
	}
	return current * 2
}

func (runner *Runner) collectNetworkEvents(ctx context.Context, events <-chan domain.NetworkEvent, eventErrors <-chan error, triggers chan<- string, failures chan<- error, done chan<- struct{}) {
	defer close(done)
	for events != nil || eventErrors != nil {
		select {
		case <-ctx.Done():
			return
		case _, open := <-events:
			if !open {
				events = nil
				if ctx.Err() == nil {
					sendFailure(ctx, failures, errors.New("network event stream closed unexpectedly"))
				}
				continue
			}
			runner.status.MarkDirty()
			runner.metrics.SetReady(false)
			runner.cancelActiveReconcile()
			select {
			case triggers <- "network_event":
			default:
			}
		case eventErr, open := <-eventErrors:
			if !open {
				eventErrors = nil
				continue
			}
			if eventErr != nil {
				sendFailure(ctx, failures, eventErr)
				return
			}
		}
	}
}

func sendFailure(ctx context.Context, failures chan<- error, err error) {
	select {
	case failures <- err:
	case <-ctx.Done():
	}
}

func (runner *Runner) execute(ctx context.Context, trigger string, retryTimer *time.Timer, retryDelay time.Duration) (time.Duration, <-chan time.Time) {
	observedEpoch := runner.status.BeginReconcile()
	runner.metrics.SetReady(runner.status.HealthSnapshot().Ready)
	started := time.Now()
	reconcileContext, cancelReconcile := context.WithTimeout(ctx, runner.configuration.Runtime.ReconcileTimeout)
	runner.setActiveReconcile(cancelReconcile)
	if !runner.status.isCurrent(observedEpoch) {
		cancelReconcile()
	}
	report, reconcileErr := runner.controller.Reconcile(reconcileContext)
	runner.clearActiveReconcile()
	cancelReconcile()
	if reconcileErr == nil {
		if reportErr := report.Validate(); reportErr != nil {
			reconcileErr = fmt.Errorf("validate reconciliation report: %w", reportErr)
		}
	}
	// Runtime owns the complete shutdown transaction after parent cancellation.
	// Keeping this pass cancellation-aware transfers ownership immediately when
	// termination races with live failure handling.
	if reconcileErr != nil && ctx.Err() == nil {
		failClosedContext, cancel := context.WithTimeout(ctx, runner.configuration.Runtime.ShutdownTimeout)
		failClosedReport, failClosedErr := runner.controller.FailClosed(failClosedContext)
		cancel()
		report.RoutingWrites += failClosedReport.RoutingWrites
		report.PacketFilterWrites += failClosedReport.PacketFilterWrites
		report.TailnetWrites += failClosedReport.TailnetWrites
		report.Changed = report.Changed || failClosedReport.Changed
		reconcileErr = errors.Join(reconcileErr, wrapOptional("enforce fail-closed state", failClosedErr))
	}
	duration := time.Since(started)
	if reconcileErr != nil {
		runner.status.RecordFailure(time.Now(), reconcileErr)
		runner.metrics.RecordReconcile(trigger, duration, report, reconcileErr)
		runner.metrics.SetReady(false)
		runner.logger.ErrorContext(ctx, "gateway reconciliation failed", "trigger", trigger, "duration", duration, "error", reconcileErr)
		resetTimer(retryTimer, retryDelay)
		return min(retryDelay*2, 30*time.Second), retryTimer.C
	}
	ready := runner.status.RecordSuccess(time.Now(), observedEpoch, report)
	runner.metrics.RecordReconcile(trigger, duration, report, nil)
	runner.metrics.SetReady(ready)
	// An event can arrive between RecordSuccess and the metric update. Re-read
	// status after publishing true so either ordering ends with a false gauge.
	ready = ready && runner.status.HealthSnapshot().Ready
	if !ready {
		runner.metrics.SetReady(false)
	}
	for _, condition := range report.Conditions {
		runner.logger.WarnContext(ctx, "gateway reconciliation has an unmet operational condition",
			"trigger", trigger, "condition", condition.Kind, "family", conditionFamily(condition.Family), "prefix", conditionPrefix(condition.Prefix))
	}
	runner.logger.InfoContext(ctx, "gateway reconciliation completed", "trigger", trigger, "duration", duration, "changed", report.Changed, "ready", ready, "conditions", len(report.Conditions), "routing_writes", report.RoutingWrites, "nftables_writes", report.PacketFilterWrites, "tailnet_writes", report.TailnetWrites)
	stopTimer(retryTimer)
	return time.Second, nil
}

func conditionFamily(family domain.AddressFamily) string {
	switch family {
	case domain.IPv4:
		return "ipv4"
	case domain.IPv6:
		return "ipv6"
	default:
		return "none"
	}
}

func conditionPrefix(prefix netip.Prefix) string {
	if !prefix.IsValid() {
		return ""
	}
	return prefix.String()
}

func (runner *Runner) setActiveReconcile(cancel context.CancelFunc) {
	runner.activeMutex.Lock()
	defer runner.activeMutex.Unlock()
	runner.activeCancel = cancel
}

func (runner *Runner) clearActiveReconcile() {
	runner.activeMutex.Lock()
	defer runner.activeMutex.Unlock()
	runner.activeCancel = nil
}

func (runner *Runner) cancelActiveReconcile() {
	runner.activeMutex.Lock()
	cancel := runner.activeCancel
	runner.activeMutex.Unlock()
	if cancel != nil {
		cancel()
	}
}

func resetTimer(timer *time.Timer, duration time.Duration) {
	stopTimer(timer)
	timer.Reset(duration)
}

func stopTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}
