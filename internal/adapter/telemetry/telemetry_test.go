package telemetry

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/port"
)

func TestReadinessEndpointUsesApplicationStatus(t *testing.T) {
	status := &fakeStatus{}
	telemetry, err := New("127.0.0.1:0", status, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = telemetry.Close() })

	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()
	telemetry.handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unexpected initial status: %d", response.Code)
	}

	status.ready = true
	response = httptest.NewRecorder()
	telemetry.handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected ready status: %d", response.Code)
	}
}

func TestHealthEndpointRejectsStateChangingMethods(t *testing.T) {
	telemetry, err := New("127.0.0.1:0", &fakeStatus{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = telemetry.Close() })
	response := httptest.NewRecorder()
	telemetry.handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/livez", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unexpected response status: %d", response.Code)
	}
}

func TestNewReservesTheListenerBeforeRuntimeSideEffects(t *testing.T) {
	telemetry, err := New("127.0.0.1:0", &fakeStatus{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = telemetry.Close() })
	conflict, err := New(telemetry.listener.Addr().String(), &fakeStatus{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		_ = conflict.Close()
		t.Fatal("a conflicting telemetry listener was accepted")
	}
}

func TestRouteApprovalMetricsAreBoundedAndRemoveStaleSeries(t *testing.T) {
	telemetry, err := New("127.0.0.1:0", &fakeStatus{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = telemetry.Close() })

	approvedPrefix := netip.MustParsePrefix("10.0.8.0/24")
	unapprovedPrefix := netip.MustParsePrefix("::/0")
	report := domain.ReconcileReport{
		ApprovalObserved: true,
		RouteApprovals: []domain.RouteApproval{
			{Prefix: approvedPrefix, Approved: true},
			{Prefix: unapprovedPrefix, Approved: false},
		},
		Conditions: []domain.ReconcileCondition{{
			Kind: domain.ConditionRouteNotApproved, Family: domain.IPv6, Prefix: unapprovedPrefix,
		}},
	}
	telemetry.RecordReconcile("test", time.Millisecond, report, nil)

	if got := gatheredMetricValues(t, telemetry, "tailscale_gateway_agent_route_approval_observation_available")[""]; got != 1 {
		t.Fatalf("approval observation gauge = %v, want 1", got)
	}
	if got := gatheredMetricValues(t, telemetry, "tailscale_gateway_agent_route_approved")["prefix="+approvedPrefix.String()]; got != 1 {
		t.Fatalf("approved route gauge = %v, want 1", got)
	}
	if got := gatheredMetricValues(t, telemetry, "tailscale_gateway_agent_route_approved")["prefix="+unapprovedPrefix.String()]; got != 0 {
		t.Fatalf("unapproved route gauge = %v, want 0", got)
	}
	conditionLabels := "family=ipv6,kind=" + string(domain.ConditionRouteNotApproved) + ",prefix=" + unapprovedPrefix.String()
	if got := gatheredMetricValues(t, telemetry, "tailscale_gateway_agent_condition_active")[conditionLabels]; got != 1 {
		t.Fatalf("route condition gauge = %v, want 1", got)
	}

	telemetry.RecordReconcile("test", time.Millisecond, domain.ReconcileReport{}, nil)
	if got := gatheredMetricValues(t, telemetry, "tailscale_gateway_agent_route_approval_observation_available")[""]; got != 0 {
		t.Fatalf("unavailable approval observation gauge = %v, want 0", got)
	}
	if got := gatheredMetricValues(t, telemetry, "tailscale_gateway_agent_route_approved"); len(got) != 0 {
		t.Fatalf("stale route approval series remain: %v", got)
	}
	if got := gatheredMetricValues(t, telemetry, "tailscale_gateway_agent_condition_active"); len(got) != 0 {
		t.Fatalf("stale condition series remain: %v", got)
	}
}

func TestInternetCapabilityMetricsUseOnlyBoundedLabels(t *testing.T) {
	telemetry, err := New("127.0.0.1:0", &fakeStatus{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = telemetry.Close() })
	now := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	telemetry.RecordInternetCapabilityProbe(domain.IPv4, port.InternetCapabilityProbeSucceeded)
	telemetry.RecordInternetCapabilityProbe(domain.IPv6, port.InternetCapabilityProbeFailed)
	telemetry.RecordInternetCapabilityProbe(domain.AddressFamily(99), port.InternetCapabilityProbeResult("unbounded-value"))
	telemetry.RecordInternetCapabilitySnapshot(domain.InternetCapabilitySnapshot{
		ProxyLink: domain.LinkIdentity{Index: 7, Name: "proxy-test"},
		IPv4: domain.InternetFamilyCapability{
			Initialized: true, Available: true, ObservedAt: now.Add(-5 * time.Second), ValidUntil: now.Add(time.Minute),
		},
		IPv6: domain.InternetFamilyCapability{Initialized: true, ObservedAt: now.Add(-10 * time.Second)},
	}, now)

	available := gatheredMetricValues(t, telemetry, "tailscale_gateway_agent_internet_capability_available")
	if available["family=ipv4"] != 1 || available["family=ipv6"] != 0 || len(available) != 2 {
		t.Fatalf("unexpected capability availability metrics: %v", available)
	}
	age := gatheredMetricValues(t, telemetry, "tailscale_gateway_agent_internet_capability_snapshot_age_seconds")
	if age["family=ipv4"] != 5 || age["family=ipv6"] != 10 || len(age) != 2 {
		t.Fatalf("unexpected capability age metrics: %v", age)
	}
	attempts := gatheredMetricValues(t, telemetry, "tailscale_gateway_agent_internet_capability_probe_total")
	if attempts["family=ipv4,result=success"] != 1 || attempts["family=ipv6,result=failure"] != 1 || attempts["family=none,result=invalid"] != 1 || len(attempts) != 3 {
		t.Fatalf("unexpected capability probe metrics: %v", attempts)
	}
}

func gatheredMetricValues(t *testing.T, telemetry *Telemetry, metricName string) map[string]float64 {
	t.Helper()
	families, err := telemetry.registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	values := make(map[string]float64)
	for _, family := range families {
		if family.GetName() != metricName {
			continue
		}
		for _, metric := range family.GetMetric() {
			labels := make([]string, 0, len(metric.GetLabel()))
			for _, label := range metric.GetLabel() {
				labels = append(labels, label.GetName()+"="+label.GetValue())
			}
			slices.Sort(labels)
			value := metric.GetGauge().GetValue()
			if metric.Counter != nil {
				value = metric.GetCounter().GetValue()
			}
			values[strings.Join(labels, ",")] = value
		}
	}
	return values
}

type fakeStatus struct{ ready bool }

func (f *fakeStatus) HealthSnapshot() domain.HealthSnapshot {
	return domain.HealthSnapshot{Live: true, Ready: f.ready}
}
