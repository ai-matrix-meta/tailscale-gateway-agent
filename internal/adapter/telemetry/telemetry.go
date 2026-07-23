package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/port"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Telemetry struct {
	listenAddress       string
	listener            net.Listener
	status              port.StatusProvider
	logger              *slog.Logger
	registry            *prometheus.Registry
	reconciles          *prometheus.CounterVec
	duration            *prometheus.HistogramVec
	writes              *prometheus.CounterVec
	drift               *prometheus.CounterVec
	ready               prometheus.Gauge
	dataPlaneAvailable  prometheus.Gauge
	conditions          *prometheus.GaugeVec
	routeApproved       *prometheus.GaugeVec
	approvalReady       prometheus.Gauge
	capabilityAvailable *prometheus.GaugeVec
	capabilityProbe     *prometheus.CounterVec
	capabilityAge       *prometheus.GaugeVec
}

func New(listenAddress string, status port.StatusProvider, logger *slog.Logger) (*Telemetry, error) {
	if listenAddress == "" || status == nil {
		return nil, errors.New("telemetry listen address and status provider are required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	telemetry := &Telemetry{
		listenAddress: listenAddress,
		status:        status,
		logger:        logger,
		registry:      prometheus.NewRegistry(),
		reconciles: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "tailscale_gateway_agent", Name: "reconcile_total", Help: "Total reconciliation attempts.",
		}, []string{"trigger", "result"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "tailscale_gateway_agent", Name: "reconcile_duration_seconds", Help: "Reconciliation duration in seconds.",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
		}, []string{"trigger"}),
		writes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "tailscale_gateway_agent", Name: "write_total", Help: "Total state-changing operations by resource class.",
		}, []string{"resource"}),
		drift: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "tailscale_gateway_agent", Name: "drift_total", Help: "Total reconciliations that observed drift.",
		}, []string{"trigger"}),
		ready: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "tailscale_gateway_agent", Name: "ready", Help: "Whether Kubernetes readiness is currently true.",
		}),
		dataPlaneAvailable: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "tailscale_gateway_agent", Name: "data_plane_available", Help: "Whether the latest completed reconciliation verified a traffic-serving data plane.",
		}),
		conditions: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "tailscale_gateway_agent", Name: "condition_active", Help: "Whether a bounded operational condition is active.",
		}, []string{"kind", "family", "prefix"}),
		routeApproved: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "tailscale_gateway_agent", Name: "route_approved", Help: "Whether a configured advertised prefix is approved by the Tailscale control plane.",
		}, []string{"prefix"}),
		approvalReady: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "tailscale_gateway_agent", Name: "route_approval_observation_available", Help: "Whether the latest reconciliation obtained a complete route approval observation.",
		}),
		capabilityAvailable: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "tailscale_gateway_agent", Name: "internet_capability_available", Help: "Whether the Internet capability snapshot is currently fresh and available.",
		}, []string{"family"}),
		capabilityProbe: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "tailscale_gateway_agent", Name: "internet_capability_probe_total", Help: "Internet capability probe attempts by bounded result.",
		}, []string{"family", "result"}),
		capabilityAge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "tailscale_gateway_agent", Name: "internet_capability_snapshot_age_seconds", Help: "Age of the latest conclusive Internet capability observation.",
		}, []string{"family"}),
	}
	if err := telemetry.registry.Register(telemetry.reconciles); err != nil {
		return nil, err
	}
	for _, collector := range []prometheus.Collector{telemetry.duration, telemetry.writes, telemetry.drift, telemetry.ready, telemetry.dataPlaneAvailable, telemetry.conditions, telemetry.routeApproved, telemetry.approvalReady, telemetry.capabilityAvailable, telemetry.capabilityProbe, telemetry.capabilityAge, collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})} {
		if err := telemetry.registry.Register(collector); err != nil {
			return nil, err
		}
	}
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return nil, fmt.Errorf("reserve telemetry listener %s: %w", listenAddress, err)
	}
	telemetry.listener = listener
	return telemetry, nil
}

func (telemetry *Telemetry) Close() error {
	if telemetry.listener == nil {
		return nil
	}
	if err := telemetry.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

func (telemetry *Telemetry) RecordReconcile(trigger string, duration time.Duration, report domain.ReconcileReport, reconcileErr error) {
	result := "success"
	if reconcileErr != nil {
		result = "error"
	}
	telemetry.reconciles.WithLabelValues(trigger, result).Inc()
	telemetry.duration.WithLabelValues(trigger).Observe(duration.Seconds())
	telemetry.writes.WithLabelValues("routing").Add(float64(report.RoutingWrites))
	telemetry.writes.WithLabelValues("nftables").Add(float64(report.PacketFilterWrites))
	telemetry.writes.WithLabelValues("tailnet_preferences").Add(float64(report.TailnetWrites))
	if report.Changed {
		telemetry.drift.WithLabelValues(trigger).Inc()
	}
	dataPlaneAvailable := float64(0)
	if reconcileErr == nil && report.DataPlaneAvailable {
		dataPlaneAvailable = 1
	}
	telemetry.dataPlaneAvailable.Set(dataPlaneAvailable)
	telemetry.conditions.Reset()
	for _, condition := range report.Conditions {
		prefix := ""
		if condition.Prefix.IsValid() {
			prefix = condition.Prefix.String()
		}
		telemetry.conditions.WithLabelValues(string(condition.Kind), metricFamily(condition.Family), prefix).Set(1)
	}
	telemetry.routeApproved.Reset()
	if report.ApprovalObserved {
		telemetry.approvalReady.Set(1)
		for _, approval := range report.RouteApprovals {
			value := float64(0)
			if approval.Approved {
				value = 1
			}
			telemetry.routeApproved.WithLabelValues(approval.Prefix.String()).Set(value)
		}
	} else {
		telemetry.approvalReady.Set(0)
	}
}

func metricFamily(family domain.AddressFamily) string {
	switch family {
	case domain.IPv4:
		return "ipv4"
	case domain.IPv6:
		return "ipv6"
	default:
		return "none"
	}
}

func (telemetry *Telemetry) RecordInternetCapabilityProbe(family domain.AddressFamily, result port.InternetCapabilityProbeResult) {
	telemetry.capabilityProbe.WithLabelValues(metricFamily(family), metricCapabilityProbeResult(result)).Inc()
}

func metricCapabilityProbeResult(result port.InternetCapabilityProbeResult) string {
	switch result {
	case port.InternetCapabilityProbeSucceeded, port.InternetCapabilityProbeFailed, port.InternetCapabilityProbeCanceled:
		return string(result)
	default:
		return "invalid"
	}
}

func (telemetry *Telemetry) RecordInternetCapabilitySnapshot(snapshot domain.InternetCapabilitySnapshot, now time.Time) {
	for _, item := range []struct {
		family     domain.AddressFamily
		capability domain.InternetFamilyCapability
	}{
		{family: domain.IPv4, capability: snapshot.IPv4},
		{family: domain.IPv6, capability: snapshot.IPv6},
	} {
		available := float64(0)
		if item.capability.Fresh(now) {
			available = 1
		}
		family := metricFamily(item.family)
		telemetry.capabilityAvailable.WithLabelValues(family).Set(available)
		age := float64(0)
		if item.capability.Initialized && !now.Before(item.capability.ObservedAt) {
			age = now.Sub(item.capability.ObservedAt).Seconds()
		}
		telemetry.capabilityAge.WithLabelValues(family).Set(age)
	}
}

func (telemetry *Telemetry) SetReady(ready bool) {
	if ready {
		telemetry.ready.Set(1)
		return
	}
	telemetry.ready.Set(0)
}

func (telemetry *Telemetry) Run(ctx context.Context) error {
	server := &http.Server{
		Addr:              telemetry.listenAddress,
		Handler:           telemetry.handler(),
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 * 1024,
	}
	result := make(chan error, 1)
	go func() {
		result <- server.Serve(telemetry.listener)
	}()
	telemetry.logger.InfoContext(ctx, "health server started", "address", telemetry.listener.Addr().String())

	select {
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("health server: %w", err)
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("shutdown health server: %w", err)
		}
		return nil
	}
}

func (telemetry *Telemetry) handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", getOnly(promhttp.HandlerFor(telemetry.registry, promhttp.HandlerOpts{})))
	mux.Handle("/livez", getOnly(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if !telemetry.status.HealthSnapshot().Live {
			writeStatus(writer, http.StatusServiceUnavailable, "not live\n")
			return
		}
		writeStatus(writer, http.StatusOK, "ok\n")
	})))
	mux.Handle("/readyz", getOnly(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		snapshot := telemetry.status.HealthSnapshot()
		statusCode := http.StatusOK
		if !snapshot.Ready {
			statusCode = http.StatusServiceUnavailable
		}
		writeReadinessStatus(writer, statusCode, snapshot)
	})))
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(writer, request)
	})
}

func getOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			writeStatus(writer, http.StatusMethodNotAllowed, "method not allowed\n")
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func writeStatus(writer http.ResponseWriter, status int, body string) {
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.WriteHeader(status)
	_, _ = writer.Write([]byte(body))
}

type readinessStatus struct {
	SchemaVersion      int                  `json:"schemaVersion"`
	Code               readinessCode        `json:"code"`
	Ready              bool                 `json:"ready"`
	Phase              domain.RuntimePhase  `json:"phase"`
	DataPlaneAvailable bool                 `json:"dataPlaneAvailable"`
	Conditions         []readinessCondition `json:"conditions"`
}

type readinessCondition struct {
	Code   domain.ReconcileConditionKind `json:"code"`
	Family string                        `json:"family,omitempty"`
	Prefix string                        `json:"prefix,omitempty"`
}

type readinessCode string

const (
	readinessCodeReady                readinessCode = "ready"
	readinessCodeReadyDegraded        readinessCode = "ready_degraded"
	readinessCodeNotLive              readinessCode = "not_live"
	readinessCodeReconciliationFailed readinessCode = "reconciliation_failed"
	readinessCodeDataPlaneUnavailable readinessCode = "data_plane_unavailable"
	readinessCodeStale                readinessCode = "stale"
)

func writeReadinessStatus(writer http.ResponseWriter, statusCode int, snapshot domain.HealthSnapshot) {
	conditions := make([]readinessCondition, 0, len(snapshot.Conditions))
	for _, condition := range snapshot.Conditions {
		item := readinessCondition{Code: condition.Kind}
		if condition.Family != 0 {
			item.Family = metricFamily(condition.Family)
		}
		if condition.Prefix.IsValid() {
			item.Prefix = condition.Prefix.String()
		}
		conditions = append(conditions, item)
	}
	payload := readinessStatus{
		SchemaVersion:      1,
		Code:               readinessStatusCode(snapshot),
		Ready:              snapshot.Ready,
		Phase:              snapshot.Phase,
		DataPlaneAvailable: snapshot.DataPlaneAvailable,
		Conditions:         conditions,
	}
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(statusCode)
	_ = json.NewEncoder(writer).Encode(payload)
}

func readinessStatusCode(snapshot domain.HealthSnapshot) readinessCode {
	if snapshot.Ready {
		if len(snapshot.Conditions) != 0 {
			return readinessCodeReadyDegraded
		}
		return readinessCodeReady
	}
	if !snapshot.Live {
		return readinessCodeNotLive
	}
	if snapshot.LastError != "" {
		return readinessCodeReconciliationFailed
	}
	switch snapshot.Phase {
	case domain.RuntimeStarting, domain.RuntimeQuarantined, domain.RuntimeReconciling, domain.RuntimeStopping:
		return readinessCode(snapshot.Phase)
	}
	if !snapshot.DataPlaneAvailable {
		return readinessCodeDataPlaneUnavailable
	}
	return readinessCodeStale
}
