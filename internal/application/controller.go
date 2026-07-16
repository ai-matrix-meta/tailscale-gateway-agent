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

type Controller struct {
	configuration            domain.Configuration
	reconciler               *Reconciler
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

func NewController(configuration domain.Configuration, reconciler *Reconciler, networkEvents port.NetworkEventSource, tailnetEvents port.TailnetEventSource, status *Status, metrics port.MetricsRecorder, logger *slog.Logger) (*Controller, error) {
	if reconciler == nil || networkEvents == nil || tailnetEvents == nil || status == nil || metrics == nil {
		return nil, errors.New("all controller dependencies are required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Controller{
		configuration: configuration, reconciler: reconciler, networkEvents: networkEvents, tailnetEvents: tailnetEvents,
		status: status, metrics: metrics, logger: logger,
		tailnetWatchInitialDelay: time.Second, tailnetWatchMaximumDelay: 30 * time.Second,
	}, nil
}

func (controller *Controller) Run(ctx context.Context) error {
	subscriptionContext, cancelSubscription := context.WithCancel(ctx)
	events, eventErrors, err := controller.networkEvents.Subscribe(subscriptionContext)
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
	go controller.collectNetworkEvents(subscriptionContext, events, eventErrors, triggers, collectorErrors, collectorDone)
	tailnetCollectorDone := make(chan struct{})
	go controller.collectTailnetEvents(subscriptionContext, triggers, tailnetCollectorDone)
	defer func() {
		cancelSubscription()
		<-collectorDone
		<-tailnetCollectorDone
	}()

	auditTicker := time.NewTicker(controller.configuration.Runtime.AuditInterval)
	defer auditTicker.Stop()
	preferenceTicker := time.NewTicker(controller.configuration.Tailnet.PreferenceAuditInterval)
	defer preferenceTicker.Stop()
	var capabilityTicker *time.Ticker
	var capabilityTick <-chan time.Time
	if controller.configuration.Tailnet.AdvertiseExitNode {
		capabilityTicker = time.NewTicker(controller.configuration.InternetCapability.ProbeInterval)
		defer capabilityTicker.Stop()
		capabilityTick = capabilityTicker.C
	}

	var dnsTicker *time.Ticker
	var dnsTick <-chan time.Time
	if controller.configuration.PacketFilter.LocalEgress.Enabled {
		dnsTicker = time.NewTicker(controller.configuration.PacketFilter.LocalEgress.RefreshInterval)
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
			resetTimer(debounceTimer, controller.configuration.Runtime.EventDebounce)
			debounceTick = debounceTimer.C
		}
	}

	controller.status.MarkDirty()
	controller.metrics.SetReady(false)
	retryDelay, retryTick = controller.execute(ctx, "startup", retryTimer, retryDelay)

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
			retryDelay, retryTick = controller.execute(ctx, trigger, retryTimer, retryDelay)
		case <-auditTicker.C:
			schedule("audit")
		case <-preferenceTicker.C:
			schedule("tailnet_audit")
		case <-capabilityTick:
			schedule("capability_audit")
		case <-dnsTick:
			schedule("dns_refresh")
		case <-retryTick:
			retryDelay, retryTick = controller.execute(ctx, "retry", retryTimer, retryDelay)
		}
	}
}

func (controller *Controller) collectTailnetEvents(ctx context.Context, triggers chan<- string, done chan<- struct{}) {
	defer close(done)
	retryDelay := controller.tailnetWatchInitialDelay
	for ctx.Err() == nil {
		events, eventErrors, err := controller.tailnetEvents.Subscribe(ctx)
		observedEvent := false
		if err == nil {
			if events == nil || eventErrors == nil {
				err = errors.New("tailnet event source returned nil channels")
			} else {
				observedEvent, err = controller.consumeTailnetEvents(ctx, events, eventErrors, triggers)
			}
		}
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			err = errors.New("tailnet event stream closed unexpectedly")
		}
		if observedEvent {
			retryDelay = controller.tailnetWatchInitialDelay
		}
		controller.logger.WarnContext(ctx, "tailscale event watch unavailable; authoritative polling remains active", "error", err, "retry_in", retryDelay)
		if !waitForTailnetWatchRetry(ctx, retryDelay) {
			return
		}
		retryDelay = nextTailnetWatchDelay(retryDelay, controller.tailnetWatchMaximumDelay)
	}
}

func (controller *Controller) consumeTailnetEvents(ctx context.Context, events <-chan domain.TailnetEvent, eventErrors <-chan error, triggers chan<- string) (bool, error) {
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
			controller.status.MarkDirty()
			controller.metrics.SetReady(false)
			controller.cancelActiveReconcile()
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

func (controller *Controller) collectNetworkEvents(ctx context.Context, events <-chan domain.NetworkEvent, eventErrors <-chan error, triggers chan<- string, failures chan<- error, done chan<- struct{}) {
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
			controller.status.MarkDirty()
			controller.metrics.SetReady(false)
			controller.cancelActiveReconcile()
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

func (controller *Controller) execute(ctx context.Context, trigger string, retryTimer *time.Timer, retryDelay time.Duration) (time.Duration, <-chan time.Time) {
	observedEpoch := controller.status.BeginReconcile()
	controller.metrics.SetReady(controller.status.HealthSnapshot().Ready)
	started := time.Now()
	reconcileContext, cancelReconcile := context.WithTimeout(ctx, controller.configuration.Runtime.ReconcileTimeout)
	controller.setActiveReconcile(cancelReconcile)
	if !controller.status.isCurrent(observedEpoch) {
		cancelReconcile()
	}
	report, reconcileErr := controller.reconciler.Reconcile(reconcileContext)
	controller.clearActiveReconcile()
	cancelReconcile()
	if reconcileErr == nil {
		if reportErr := report.Validate(); reportErr != nil {
			reconcileErr = fmt.Errorf("validate reconciliation report: %w", reportErr)
		}
	}
	// Supervisor owns the complete shutdown transaction after parent cancellation.
	// Keeping this pass cancellation-aware transfers ownership immediately when
	// termination races with live failure handling.
	if reconcileErr != nil && ctx.Err() == nil {
		failClosedContext, cancel := context.WithTimeout(ctx, controller.configuration.Runtime.ShutdownTimeout)
		failClosedReport, failClosedErr := controller.reconciler.FailClosed(failClosedContext)
		cancel()
		report.RoutingWrites += failClosedReport.RoutingWrites
		report.PacketFilterWrites += failClosedReport.PacketFilterWrites
		report.TailnetWrites += failClosedReport.TailnetWrites
		report.Changed = report.Changed || failClosedReport.Changed
		reconcileErr = errors.Join(reconcileErr, wrapOptional("enforce fail-closed state", failClosedErr))
	}
	duration := time.Since(started)
	if reconcileErr != nil {
		controller.status.RecordFailure(time.Now(), reconcileErr)
		controller.metrics.RecordReconcile(trigger, duration, report, reconcileErr)
		controller.metrics.SetReady(false)
		controller.logger.ErrorContext(ctx, "gateway reconciliation failed", "trigger", trigger, "duration", duration, "error", reconcileErr)
		resetTimer(retryTimer, retryDelay)
		return min(retryDelay*2, 30*time.Second), retryTimer.C
	}
	ready := controller.status.RecordSuccess(time.Now(), observedEpoch, report)
	controller.metrics.RecordReconcile(trigger, duration, report, nil)
	controller.metrics.SetReady(ready)
	// An event can arrive between RecordSuccess and the metric update. Re-read
	// status after publishing true so either ordering ends with a false gauge.
	ready = ready && controller.status.HealthSnapshot().Ready
	if !ready {
		controller.metrics.SetReady(false)
	}
	for _, condition := range report.Conditions {
		controller.logger.WarnContext(ctx, "gateway reconciliation has an unmet operational condition",
			"trigger", trigger, "condition", condition.Kind, "family", conditionFamily(condition.Family), "prefix", conditionPrefix(condition.Prefix))
	}
	controller.logger.InfoContext(ctx, "gateway reconciliation completed", "trigger", trigger, "duration", duration, "changed", report.Changed, "ready", ready, "conditions", len(report.Conditions), "routing_writes", report.RoutingWrites, "nftables_writes", report.PacketFilterWrites, "tailnet_writes", report.TailnetWrites)
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

func (controller *Controller) setActiveReconcile(cancel context.CancelFunc) {
	controller.activeMutex.Lock()
	defer controller.activeMutex.Unlock()
	controller.activeCancel = cancel
}

func (controller *Controller) clearActiveReconcile() {
	controller.activeMutex.Lock()
	defer controller.activeMutex.Unlock()
	controller.activeCancel = nil
}

func (controller *Controller) cancelActiveReconcile() {
	controller.activeMutex.Lock()
	cancel := controller.activeCancel
	controller.activeMutex.Unlock()
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
