package application

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/port"
)

func TestDesiredRoutingEnforcesProxyDefaultsAndDirectBypasses(t *testing.T) {
	configuration := applicationTestConfiguration()
	snapshot := applicationTestSnapshot()
	state := buildDesiredRouting(configuration, snapshot, domain.AllExitDefaultRoutes())
	for _, route := range state.Routes {
		if route.Disposition == domain.RouteUnicast && route.Metric != configuration.Network.ActiveRouteMetric {
			t.Fatalf("active route does not use the configured metric: %#v", route)
		}
	}

	for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
		route := requireRoute(t, state, family, configuration.Network.ExitRouteTable, domain.DefaultPrefix(family), domain.RouteUnicast)
		if route.Link != snapshot.ProxyTunnelLink {
			t.Fatalf("family %d exit default does not use the proxy tunnel: %#v", family, route)
		}
		blackhole := requireRoute(t, state, family, configuration.Network.ExitRouteTable, domain.DefaultPrefix(family), domain.RouteBlackhole)
		if blackhole.Metric != configuration.Network.FailClosedRouteMetric {
			t.Fatalf("family %d fail-closed route has the wrong metric: %#v", family, blackhole)
		}
	}

	advertised := requireRoute(t, state, domain.IPv4, configuration.Network.ExitRouteTable, configuration.Tailnet.AdvertiseRoutes[0], domain.RouteUnicast)
	if advertised.Link.Name != "internal-path" || advertised.Gateway.String() != "10.42.0.1" {
		t.Fatalf("advertised route does not preserve the direct kernel projection: %#v", advertised)
	}

	dnsIPv4 := netip.MustParseAddr("10.43.0.10")
	dnsIPv6 := netip.MustParseAddr("fd00:43::a")
	if route := requireRoute(t, state, domain.IPv4, configuration.Network.ExitRouteTable, netip.PrefixFrom(dnsIPv4, 32), domain.RouteUnicast); route.Link.Name != "dns-path-v4" {
		t.Fatalf("IPv4 DNS host route uses the wrong link: %#v", route)
	}
	if route := requireRoute(t, state, domain.IPv6, configuration.Network.ExitRouteTable, netip.PrefixFrom(dnsIPv6, 128), domain.RouteUnicast); route.Link.Name != "dns-path-v6" {
		t.Fatalf("IPv6 DNS host route uses the wrong link: %#v", route)
	}
}

func TestDesiredRoutingKeepsUnavailableExitFamiliesBlackholed(t *testing.T) {
	configuration := applicationTestConfiguration()
	snapshot := applicationTestSnapshot()
	tests := []struct {
		name                    string
		activeExitDefaultRoutes domain.ExitDefaultRouteSet
		active                  domain.AddressFamily
		blackholed              domain.AddressFamily
	}{
		{name: "ipv4 only", activeExitDefaultRoutes: domain.ExitDefaultRouteSet{IPv4: true}, active: domain.IPv4, blackholed: domain.IPv6},
		{name: "ipv6 only", activeExitDefaultRoutes: domain.ExitDefaultRouteSet{IPv6: true}, active: domain.IPv6, blackholed: domain.IPv4},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := buildDesiredRouting(configuration, snapshot, test.activeExitDefaultRoutes)
			active := requireRoute(t, state, test.active, configuration.Network.ExitRouteTable, domain.DefaultPrefix(test.active), domain.RouteUnicast)
			if active.Link != snapshot.ProxyTunnelLink {
				t.Fatalf("active family %d does not use the proxy tunnel: %#v", test.active, active)
			}
			requireRoute(t, state, test.blackholed, configuration.Network.ExitRouteTable, domain.DefaultPrefix(test.blackholed), domain.RouteBlackhole)
			assertRouteAbsent(t, state, test.blackholed, configuration.Network.ExitRouteTable, domain.DefaultPrefix(test.blackholed), domain.RouteUnicast)
			for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
				requireRule(t, state, family, configuration.Network.ExitRulePriority)
			}
		})
	}
}

func TestReconcilerPublishesAtomicExitNodeAdvertisementWhenAnyFamilyIsAvailable(t *testing.T) {
	tests := []struct {
		name                       string
		availableExitDefaultRoutes domain.ExitDefaultRouteSet
	}{
		{name: "ipv4 only", availableExitDefaultRoutes: domain.ExitDefaultRouteSet{IPv4: true}},
		{name: "ipv6 only", availableExitDefaultRoutes: domain.ExitDefaultRouteSet{IPv6: true}},
		{name: "neither family"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newReconcilerFixture(t)
			now := time.Now()
			fixture.capability.set(capabilitySnapshotForActiveExitDefaultRoutes(fixture.discovery.snapshot.ProxyTunnelLink, now, test.availableExitDefaultRoutes))
			if err := fixture.reconciler.Prepare(context.Background()); err != nil {
				t.Fatal(err)
			}
			report, err := fixture.reconciler.Reconcile(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			wantPreferences := tailnetPreferencesForActiveExitRoutes(fixture.configuration.Tailnet.AdvertiseRoutes, test.availableExitDefaultRoutes)
			if got := fixture.tailnet.currentPreferences(); !got.Equal(wantPreferences) {
				t.Fatalf("initial preferences = %v, want %v", got.AdvertiseRoutes, wantPreferences.AdvertiseRoutes)
			}
			if report.TailnetWrites != 1 || fixture.tailnet.writeCalls() != 1 {
				t.Fatalf("initial atomic advertisement was not one verified write: %#v", report)
			}
			state := fixture.routing.currentState()
			for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
				if test.availableExitDefaultRoutes.Contains(family) {
					requireRoute(t, state, family, fixture.configuration.Network.ExitRouteTable, domain.DefaultPrefix(family), domain.RouteUnicast)
				} else {
					assertRouteAbsent(t, state, family, fixture.configuration.Network.ExitRouteTable, domain.DefaultPrefix(family), domain.RouteUnicast)
				}
			}
			for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
				prefix := domain.DefaultPrefix(family)
				observed := slices.ContainsFunc(report.RouteApprovals, func(approval domain.RouteApproval) bool {
					return approval.Prefix == prefix
				})
				if observed != !test.availableExitDefaultRoutes.Empty() {
					t.Fatalf("family %d approval scope mismatch: active=%#v approvals=%#v", family, test.availableExitDefaultRoutes, report.RouteApprovals)
				}
			}
		})
	}
}

func TestReconcilerClearsRestoredAdvertisementsBeforeOpeningDataPlane(t *testing.T) {
	fixture := newReconcilerFixture(t)
	desiredPreferences := domain.NewTailnetExitNodePreferences(fixture.configuration.Tailnet.AdvertiseRoutes)
	fixture.tailnet.state.Preferences = desiredPreferences

	if err := fixture.reconciler.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.recorder.reset()
	report, err := fixture.reconciler.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	wantOrder := []string{"advertisements-cleared", "nftables-closed", "routing", "nftables-open", "advertisements-published"}
	if got := fixture.recorder.snapshot(); !slices.Equal(got, wantOrder) {
		t.Fatalf("unexpected startup write order: got %v, want %v", got, wantOrder)
	}
	if report.RoutingWrites == 0 || report.PacketFilterWrites != 2 || report.TailnetWrites != 2 || !report.Changed {
		t.Fatalf("unexpected startup report: %#v", report)
	}
}

func TestReconcilerNoDriftProducesStrictlyZeroWrites(t *testing.T) {
	fixture := newReconcilerFixture(t)
	if err := fixture.reconciler.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.routing.resetWrites()
	fixture.packetFilter.resetWrites()
	fixture.tailnet.resetWrites()
	fixture.recorder.reset()

	report, err := fixture.reconciler.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Changed || report.RoutingWrites != 0 || report.PacketFilterWrites != 0 || report.TailnetWrites != 0 {
		t.Fatalf("no-drift reconciliation reported writes: %#v", report)
	}
	if fixture.routing.writeCalls() != 0 || fixture.packetFilter.writeCalls() != 0 || fixture.tailnet.writeCalls() != 0 {
		t.Fatalf("no-drift reconciliation invoked a writer: routing=%d nftables=%d tailnet=%d", fixture.routing.writeCalls(), fixture.packetFilter.writeCalls(), fixture.tailnet.writeCalls())
	}
	if got := fixture.recorder.snapshot(); len(got) != 0 {
		t.Fatalf("no-drift reconciliation changed state: %v", got)
	}
}

func TestReconcilerDisabledLocalEgressProducesCanonicalPolicy(t *testing.T) {
	fixture := newReconcilerFixture(t)
	fixture.configuration.PacketFilter.LocalEgress.Enabled = false
	fixture.configuration.PacketFilter.LocalEgress.Domains = nil
	fixture.reconciler.configuration = fixture.configuration
	if err := fixture.configuration.Validate(); err != nil {
		t.Fatalf("disabled local-egress configuration was rejected: %v", err)
	}
	if err := fixture.reconciler.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.reconciler.Reconcile(context.Background()); err != nil {
		t.Fatalf("disabled local-egress reconciliation failed: %v", err)
	}

	local := fixture.packetFilter.lastPolicy().LocalEgress
	if local.Enabled || len(local.IPv4) != 0 || len(local.IPv6) != 0 || len(local.Protocols) != 0 || len(local.Ports) != 0 || local.Mark != 0 {
		t.Fatalf("disabled local-egress policy is not canonical: %#v", local)
	}
}

func TestReconcilerReportsRouteApprovalLossAndRecoveryWithoutPreferenceWrites(t *testing.T) {
	for _, missing := range []netip.Prefix{
		netip.MustParsePrefix("10.0.8.0/24"),
		domain.DefaultPrefix(domain.IPv4),
		domain.DefaultPrefix(domain.IPv6),
	} {
		t.Run(missing.String(), func(t *testing.T) {
			fixture := newReconcilerFixture(t)
			if err := fixture.reconciler.Prepare(context.Background()); err != nil {
				t.Fatal(err)
			}
			if report, err := fixture.reconciler.Reconcile(context.Background()); err != nil || len(report.Conditions) != 0 {
				t.Fatalf("initial approved reconciliation failed: report=%#v err=%v", report, err)
			}
			fixture.tailnet.resetWrites()
			fixture.tailnet.setApprovedRoutes(slices.DeleteFunc(
				domain.NewTailnetExitNodePreferences(fixture.configuration.Tailnet.AdvertiseRoutes).AdvertiseRoutes,
				func(prefix netip.Prefix) bool { return prefix == missing },
			))

			report, err := fixture.reconciler.Reconcile(context.Background())
			if err != nil {
				t.Fatalf("explicit non-approval became a technical error: %v", err)
			}
			wantCondition := domain.ReconcileCondition{Kind: domain.ConditionRouteNotApproved, Family: domain.FamilyOfPrefix(missing), Prefix: missing}
			if !slices.Equal(report.Conditions, []domain.ReconcileCondition{wantCondition}) || !report.ApprovalObserved {
				t.Fatalf("missing approval was not reported exactly: %#v", report)
			}
			if !report.DataPlaneAvailable {
				t.Fatalf("explicit route non-approval incorrectly made the verified data plane unavailable: %#v", report)
			}
			if fixture.tailnet.writeCalls() != 0 || report.TailnetWrites != 0 {
				t.Fatalf("explicit non-approval rewrote preferences: calls=%d report=%#v", fixture.tailnet.writeCalls(), report)
			}

			fixture.tailnet.setApprovedRoutes(domain.NewTailnetExitNodePreferences(fixture.configuration.Tailnet.AdvertiseRoutes).AdvertiseRoutes)
			recovered, err := fixture.reconciler.Reconcile(context.Background())
			if err != nil || len(recovered.Conditions) != 0 || !recovered.ApprovalObserved {
				t.Fatalf("approval recovery did not become healthy: report=%#v err=%v", recovered, err)
			}
			if fixture.tailnet.writeCalls() != 0 || recovered.TailnetWrites != 0 {
				t.Fatalf("approval recovery rewrote preferences: calls=%d report=%#v", fixture.tailnet.writeCalls(), recovered)
			}
		})
	}
}

func TestReconcilerIsolatesSingleFamilyCapabilityLossAndRecovery(t *testing.T) {
	for _, unavailableFamily := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
		t.Run(fmt.Sprintf("ipv%d", unavailableFamily), func(t *testing.T) {
			fixture := newReconcilerFixture(t)
			if err := fixture.reconciler.Prepare(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.reconciler.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}

			now := time.Now()
			link := fixture.discovery.snapshot.ProxyTunnelLink
			fresh := domain.InternetFamilyCapability{Initialized: true, Available: true, ObservedAt: now, ValidUntil: now.Add(time.Minute)}
			unavailable := domain.InternetFamilyCapability{Initialized: true, ObservedAt: now}
			snapshot := domain.InternetCapabilitySnapshot{ProxyLink: link, IPv4: fresh, IPv6: fresh}
			expectedActiveExitDefaultRoutes := domain.AllExitDefaultRoutes()
			if unavailableFamily == domain.IPv4 {
				snapshot.IPv4 = unavailable
				expectedActiveExitDefaultRoutes.IPv4 = false
			} else {
				snapshot.IPv6 = unavailable
				expectedActiveExitDefaultRoutes.IPv6 = false
			}

			fixture.tailnet.resetWrites()
			fixture.routing.resetWrites()
			fixture.packetFilter.resetWrites()
			fixture.recorder.reset()
			fixture.routing.recordReads = true
			fixture.packetFilter.recordReads = true
			fixture.capability.set(snapshot)
			lost, err := fixture.reconciler.Reconcile(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			wantCondition := domain.ReconcileCondition{Kind: domain.ConditionInternetCapabilityUnavailable, Family: unavailableFamily}
			if !slices.Contains(lost.Conditions, wantCondition) || lost.TailnetWrites != 0 || fixture.tailnet.writeCalls() != 0 {
				t.Fatalf("single-family loss changed the atomic Exit Node advertisement: %#v", lost)
			}
			if !lost.DataPlaneAvailable {
				t.Fatalf("single-family loss made the remaining healthy Exit path unavailable: %#v", lost)
			}
			if lost.RoutingWrites == 0 || fixture.routing.writeCalls() != 1 || lost.PacketFilterWrites != 0 || fixture.packetFilter.writeCalls() != 0 {
				t.Fatalf("single-family loss touched unrelated data-plane state: report=%#v routing_calls=%d nftables_calls=%d", lost, fixture.routing.writeCalls(), fixture.packetFilter.writeCalls())
			}
			operations := fixture.recorder.snapshot()
			routingWrite := lastValueIndex(operations, "routing")
			lastRoutingRead := lastValueIndex(operations, "routing-read")
			lastPacketRead := lastValueIndex(operations, "nftables-read")
			if routingWrite < 0 || lastRoutingRead < routingWrite || lastPacketRead < routingWrite ||
				slices.Contains(operations, "exit-node-withdrawn") || slices.Contains(operations, "advertisements-cleared") ||
				slices.Contains(operations, "advertisements-published") || slices.Contains(operations, "nftables-closed") || slices.Contains(operations, "nftables-open") {
				t.Fatalf("single-family loss violated isolated transaction ordering: %v", operations)
			}
			wantPreferences := tailnetPreferencesForActiveExitRoutes(fixture.configuration.Tailnet.AdvertiseRoutes, expectedActiveExitDefaultRoutes)
			if got := fixture.tailnet.currentPreferences(); !got.Equal(wantPreferences) {
				t.Fatalf("single-family loss changed healthy advertisements: got %v, want %v", got.AdvertiseRoutes, wantPreferences.AdvertiseRoutes)
			}
			state := fixture.routing.currentState()
			for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
				if expectedActiveExitDefaultRoutes.Contains(family) {
					requireRoute(t, state, family, fixture.configuration.Network.ExitRouteTable, domain.DefaultPrefix(family), domain.RouteUnicast)
				} else {
					assertRouteAbsent(t, state, family, fixture.configuration.Network.ExitRouteTable, domain.DefaultPrefix(family), domain.RouteUnicast)
				}
			}
			for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
				if !slices.ContainsFunc(lost.RouteApprovals, func(approval domain.RouteApproval) bool {
					return approval.Prefix == domain.DefaultPrefix(family)
				}) {
					t.Fatalf("atomic Exit Node approval omitted family %d: %#v", family, lost.RouteApprovals)
				}
			}

			fixture.tailnet.resetWrites()
			fixture.routing.resetWrites()
			fixture.packetFilter.resetWrites()
			fixture.recorder.reset()
			fixture.capability.set(domain.InternetCapabilitySnapshot{ProxyLink: link, IPv4: fresh, IPv6: fresh})
			recovered, err := fixture.reconciler.Reconcile(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(recovered.Conditions) != 0 || recovered.TailnetWrites != 0 || fixture.tailnet.writeCalls() != 0 {
				t.Fatalf("single-family recovery changed the atomic Exit Node advertisement: %#v", recovered)
			}
			if recovered.PacketFilterWrites != 0 || fixture.packetFilter.writeCalls() != 0 {
				t.Fatalf("single-family recovery touched the global forwarding gate: report=%#v calls=%d", recovered, fixture.packetFilter.writeCalls())
			}
			operations = fixture.recorder.snapshot()
			lastRoutingWrite := lastValueIndex(operations, "routing")
			lastRoutingRead = lastValueIndex(operations, "routing-read")
			lastPacketRead = lastValueIndex(operations, "nftables-read")
			if lastRoutingWrite < 0 || lastRoutingRead < lastRoutingWrite || lastPacketRead < lastRoutingWrite ||
				slices.Contains(operations, "advertisements-cleared") || slices.Contains(operations, "advertisements-published") || slices.Contains(operations, "nftables-closed") {
				t.Fatalf("recovered route was not fully verified without preference churn: %v", operations)
			}
			wantAll := domain.NewTailnetExitNodePreferences(fixture.configuration.Tailnet.AdvertiseRoutes)
			if got := fixture.tailnet.currentPreferences(); !got.Equal(wantAll) {
				t.Fatalf("capability recovery did not restore both Exit defaults: %#v", got)
			}
		})
	}
}

func TestReconcilerWithdrawsAtomicExitNodeAdvertisementBeforeDeactivatingFinalRoute(t *testing.T) {
	fixture := newReconcilerFixture(t)
	fixture.capability.set(capabilitySnapshotForActiveExitDefaultRoutes(
		fixture.discovery.snapshot.ProxyTunnelLink,
		time.Now(),
		domain.ExitDefaultRouteSet{IPv4: true},
	))
	if err := fixture.reconciler.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	fixture.tailnet.resetWrites()
	fixture.routing.resetWrites()
	fixture.packetFilter.resetWrites()
	fixture.recorder.reset()
	fixture.routing.recordReads = true
	fixture.packetFilter.recordReads = true
	fixture.capability.set(capabilitySnapshotForActiveExitDefaultRoutes(
		fixture.discovery.snapshot.ProxyTunnelLink,
		time.Now(),
		domain.ExitDefaultRouteSet{},
	))

	report, err := fixture.reconciler.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.TailnetWrites != 1 || fixture.tailnet.writeCalls() != 1 || report.RoutingWrites == 0 || fixture.routing.writeCalls() != 1 {
		t.Fatalf("final capability loss was not a bounded withdrawal: report=%#v tailnet=%d routing=%d", report, fixture.tailnet.writeCalls(), fixture.routing.writeCalls())
	}
	if report.PacketFilterWrites != 0 || fixture.packetFilter.writeCalls() != 0 {
		t.Fatalf("final capability loss touched the global forwarding gate: report=%#v calls=%d", report, fixture.packetFilter.writeCalls())
	}
	operations := fixture.recorder.snapshot()
	withdrawal := slices.Index(operations, "exit-node-withdrawn")
	routingWrite := slices.Index(operations, "routing")
	if withdrawal < 0 || routingWrite <= withdrawal ||
		slices.Contains(operations, "advertisements-cleared") || slices.Contains(operations, "advertisements-published") ||
		slices.Contains(operations, "nftables-closed") || slices.Contains(operations, "nftables-open") {
		t.Fatalf("Exit Node advertisement was not withdrawn before final-route deactivation: %v", operations)
	}
	plans := fixture.routing.appliedChanges()
	if len(plans) != 1 || len(plans[0].UpsertRoutes) != 0 || len(plans[0].DeleteRoutes) != 1 ||
		plans[0].DeleteRoutes[0].Family != domain.IPv4 {
		t.Fatalf("final-route deactivation plan is not limited to the last active default: %#v", plans)
	}
	wantPreferences := domain.NewTailnetPreferences(fixture.configuration.Tailnet.AdvertiseRoutes)
	if got := fixture.tailnet.currentPreferences(); !got.Equal(wantPreferences) {
		t.Fatalf("final capability loss produced %v, want %v", got.AdvertiseRoutes, wantPreferences.AdvertiseRoutes)
	}
	state := fixture.routing.currentState()
	for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
		assertRouteAbsent(t, state, family, fixture.configuration.Network.ExitRouteTable, domain.DefaultPrefix(family), domain.RouteUnicast)
		requireRoute(t, state, family, fixture.configuration.Network.ExitRouteTable, domain.DefaultPrefix(family), domain.RouteBlackhole)
	}
}

func TestReconcilerPublishesAtomicExitNodeAdvertisementAfterFirstActiveRouteVerification(t *testing.T) {
	fixture := newReconcilerFixture(t)
	link := fixture.discovery.snapshot.ProxyTunnelLink
	fixture.capability.set(capabilitySnapshotForActiveExitDefaultRoutes(link, time.Now(), domain.ExitDefaultRouteSet{}))
	if err := fixture.reconciler.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fixture.tailnet.currentPreferences().HasExitDefaultRoutes() {
		t.Fatal("Exit Node was advertised without an active Exit route")
	}

	fixture.tailnet.resetWrites()
	fixture.routing.resetWrites()
	fixture.packetFilter.resetWrites()
	fixture.recorder.reset()
	fixture.routing.recordReads = true
	fixture.packetFilter.recordReads = true
	fixture.capability.set(capabilitySnapshotForActiveExitDefaultRoutes(link, time.Now(), domain.ExitDefaultRouteSet{IPv4: true}))

	report, err := fixture.reconciler.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.TailnetWrites != 1 || fixture.tailnet.writeCalls() != 1 || report.RoutingWrites == 0 || fixture.routing.writeCalls() != 1 {
		t.Fatalf("first-family recovery was not a bounded publication: report=%#v tailnet=%d routing=%d", report, fixture.tailnet.writeCalls(), fixture.routing.writeCalls())
	}
	if report.PacketFilterWrites != 0 || fixture.packetFilter.writeCalls() != 0 {
		t.Fatalf("first-family recovery touched the global forwarding gate: report=%#v calls=%d", report, fixture.packetFilter.writeCalls())
	}
	operations := fixture.recorder.snapshot()
	publication := slices.Index(operations, "advertisements-published")
	lastRoutingRead := lastValueIndex(operations, "routing-read")
	lastPacketFilterRead := lastValueIndex(operations, "nftables-read")
	if publication < 0 || lastRoutingRead < 0 || lastPacketFilterRead < 0 || publication <= lastRoutingRead || publication <= lastPacketFilterRead ||
		slices.Contains(operations, "exit-node-withdrawn") || slices.Contains(operations, "advertisements-cleared") ||
		slices.Contains(operations, "nftables-closed") || slices.Contains(operations, "nftables-open") {
		t.Fatalf("atomic Exit Node advertisement preceded final data-plane verification: %v", operations)
	}
	wantPreferences := domain.NewTailnetExitNodePreferences(fixture.configuration.Tailnet.AdvertiseRoutes)
	if got := fixture.tailnet.currentPreferences(); !got.Equal(wantPreferences) {
		t.Fatalf("first-family recovery produced %v, want %v", got.AdvertiseRoutes, wantPreferences.AdvertiseRoutes)
	}
	state := fixture.routing.currentState()
	requireRoute(t, state, domain.IPv4, fixture.configuration.Network.ExitRouteTable, domain.DefaultPrefix(domain.IPv4), domain.RouteUnicast)
	assertRouteAbsent(t, state, domain.IPv6, fixture.configuration.Network.ExitRouteTable, domain.DefaultPrefix(domain.IPv6), domain.RouteUnicast)
	requireRoute(t, state, domain.IPv6, fixture.configuration.Network.ExitRouteTable, domain.DefaultPrefix(domain.IPv6), domain.RouteBlackhole)
	for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
		if !slices.ContainsFunc(report.RouteApprovals, func(approval domain.RouteApproval) bool {
			return approval.Prefix == domain.DefaultPrefix(family)
		}) {
			t.Fatalf("atomic Exit Node approval omitted family %d: %#v", family, report.RouteApprovals)
		}
	}
}

func TestReconcilerMigratesPartialDefaultAdvertisementToAtomicExitNodeContract(t *testing.T) {
	fixture := newReconcilerFixture(t)
	link := fixture.discovery.snapshot.ProxyTunnelLink
	fixture.capability.set(capabilitySnapshotForActiveExitDefaultRoutes(link, time.Now(), domain.ExitDefaultRouteSet{IPv4: true}))
	if err := fixture.reconciler.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	partialRoutes := append(slices.Clone(fixture.configuration.Tailnet.AdvertiseRoutes), domain.DefaultPrefix(domain.IPv4))
	fixture.tailnet.setPreferences(domain.NormalizeTailnetPreferences(partialRoutes))

	fixture.tailnet.resetWrites()
	fixture.routing.resetWrites()
	fixture.packetFilter.resetWrites()
	fixture.recorder.reset()
	fixture.routing.recordReads = true
	fixture.packetFilter.recordReads = true

	report, err := fixture.reconciler.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.TailnetWrites != 1 || fixture.tailnet.writeCalls() != 1 || report.RoutingWrites != 0 || fixture.routing.writeCalls() != 0 ||
		report.PacketFilterWrites != 0 || fixture.packetFilter.writeCalls() != 0 {
		t.Fatalf("partial-advertisement migration touched unrelated state: report=%#v tailnet=%d routing=%d nftables=%d", report, fixture.tailnet.writeCalls(), fixture.routing.writeCalls(), fixture.packetFilter.writeCalls())
	}
	operations := fixture.recorder.snapshot()
	publication := slices.Index(operations, "advertisements-published")
	lastRoutingRead := lastValueIndex(operations, "routing-read")
	lastPacketFilterRead := lastValueIndex(operations, "nftables-read")
	if publication < 0 || publication <= lastRoutingRead || publication <= lastPacketFilterRead ||
		slices.Contains(operations, "routing") || slices.Contains(operations, "nftables-closed") || slices.Contains(operations, "nftables-open") {
		t.Fatalf("partial advertisement migrated without prior data-plane verification: %v", operations)
	}
	wantPreferences := domain.NewTailnetExitNodePreferences(fixture.configuration.Tailnet.AdvertiseRoutes)
	if got := fixture.tailnet.currentPreferences(); !got.Equal(wantPreferences) {
		t.Fatalf("partial advertisement migrated to %v, want %v", got.AdvertiseRoutes, wantPreferences.AdvertiseRoutes)
	}
}

func TestReconcilerTransitionsBetweenSingleFamilyExitRoutesWithoutGlobalQuarantine(t *testing.T) {
	fixture := newReconcilerFixture(t)
	if err := fixture.reconciler.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	link := fixture.discovery.snapshot.ProxyTunnelLink
	fixture.capability.set(capabilitySnapshotForActiveExitDefaultRoutes(link, now, domain.ExitDefaultRouteSet{IPv4: true}))
	if _, err := fixture.reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.routing.injectObservedRoute(activeRoute(
		fixture.configuration.Network,
		domain.IPv6,
		fixture.configuration.Network.ExitRouteTable,
		domain.DefaultPrefix(domain.IPv6),
		netip.Addr{},
		domain.LinkIdentity{Index: 77, Name: "stale-proxy-path"},
		false,
	))

	fixture.tailnet.resetWrites()
	fixture.routing.resetWrites()
	fixture.packetFilter.resetWrites()
	fixture.recorder.reset()
	fixture.routing.recordReads = true
	fixture.packetFilter.recordReads = true
	fixture.capability.set(capabilitySnapshotForActiveExitDefaultRoutes(link, time.Now(), domain.ExitDefaultRouteSet{IPv6: true}))
	report, err := fixture.reconciler.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.TailnetWrites != 0 || fixture.tailnet.writeCalls() != 0 || report.RoutingWrites == 0 || fixture.routing.writeCalls() != 2 {
		t.Fatalf("cross-family transition was not bounded: report=%#v tailnet=%d routing=%d", report, fixture.tailnet.writeCalls(), fixture.routing.writeCalls())
	}
	if report.PacketFilterWrites != 0 || fixture.packetFilter.writeCalls() != 0 {
		t.Fatalf("cross-family transition touched the global forwarding gate: report=%#v calls=%d", report, fixture.packetFilter.writeCalls())
	}
	operations := fixture.recorder.snapshot()
	firstRoutingWrite := slices.Index(operations, "routing")
	lastRoutingWrite := lastValueIndex(operations, "routing")
	lastRoutingRead := lastValueIndex(operations, "routing-read")
	lastPacketRead := lastValueIndex(operations, "nftables-read")
	intermediateReadback := -1
	if firstRoutingWrite >= 0 && lastRoutingWrite > firstRoutingWrite {
		intermediateReadback = slices.Index(operations[firstRoutingWrite+1:lastRoutingWrite], "routing-read")
	}
	if firstRoutingWrite < 0 || lastRoutingWrite <= firstRoutingWrite || intermediateReadback < 0 || lastRoutingRead < lastRoutingWrite || lastPacketRead < lastRoutingWrite ||
		slices.Contains(operations, "exit-node-withdrawn") || slices.Contains(operations, "advertisements-cleared") ||
		slices.Contains(operations, "advertisements-published") || slices.Contains(operations, "nftables-closed") || slices.Contains(operations, "nftables-open") {
		t.Fatalf("cross-family transition violated deactivate/activate/readback ordering: %v", operations)
	}
	plans := fixture.routing.appliedChanges()
	if len(plans) != 2 || len(plans[0].DeleteRoutes) != 1 || len(plans[0].UpsertRoutes) != 0 ||
		plans[0].DeleteRoutes[0].Family != domain.IPv4 || len(plans[1].UpsertRoutes) != 1 ||
		len(plans[1].DeleteRoutes) != 0 || plans[1].UpsertRoutes[0].Family != domain.IPv6 {
		t.Fatalf("cross-family route plans were not delete-before-upsert: %#v", plans)
	}
	wantPreferences := domain.NewTailnetExitNodePreferences(fixture.configuration.Tailnet.AdvertiseRoutes)
	if got := fixture.tailnet.currentPreferences(); !got.Equal(wantPreferences) {
		t.Fatalf("cross-family transition produced %v, want %v", got.AdvertiseRoutes, wantPreferences.AdvertiseRoutes)
	}
	state := fixture.routing.currentState()
	assertRouteAbsent(t, state, domain.IPv4, fixture.configuration.Network.ExitRouteTable, domain.DefaultPrefix(domain.IPv4), domain.RouteUnicast)
	activeIPv6Route := requireRoute(t, state, domain.IPv6, fixture.configuration.Network.ExitRouteTable, domain.DefaultPrefix(domain.IPv6), domain.RouteUnicast)
	if activeIPv6Route.Link != link {
		t.Fatalf("cross-family transition retained stale IPv6 route: %#v", activeIPv6Route)
	}
}

func TestReconcilerStopsCrossFamilyActivationAfterUnexpectedDeactivationReadback(t *testing.T) {
	fixture := newReconcilerFixture(t)
	link := fixture.discovery.snapshot.ProxyTunnelLink
	fixture.capability.set(capabilitySnapshotForActiveExitDefaultRoutes(link, time.Now(), domain.ExitDefaultRouteSet{IPv4: true}))
	if err := fixture.reconciler.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	fixture.tailnet.resetWrites()
	fixture.routing.resetWrites()
	fixture.packetFilter.resetWrites()
	fixture.recorder.reset()
	fixture.routing.mutateAfterNextApply(func(state *domain.RoutingState) {
		state.Routes = append(state.Routes, domain.Route{
			Family:      domain.IPv4,
			Disposition: domain.RouteBlackhole,
			Table:       fixture.configuration.Network.ExitRouteTable,
			Prefix:      netip.MustParsePrefix("192.0.2.0/24"),
			Metric:      fixture.configuration.Network.FailClosedRouteMetric,
		})
	})
	fixture.capability.set(capabilitySnapshotForActiveExitDefaultRoutes(link, time.Now(), domain.ExitDefaultRouteSet{IPv6: true}))

	report, err := fixture.reconciler.Reconcile(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unexpected pending changes") {
		t.Fatalf("unexpected deactivation readback did not stop activation: report=%#v err=%v", report, err)
	}
	if report.TailnetWrites != 0 || fixture.tailnet.writeCalls() != 0 || report.PacketFilterWrites != 0 || fixture.packetFilter.writeCalls() != 0 {
		t.Fatalf("failed deactivation readback touched Tailnet or nftables: report=%#v tailnet=%d nftables=%d", report, fixture.tailnet.writeCalls(), fixture.packetFilter.writeCalls())
	}
	plans := fixture.routing.appliedChanges()
	if len(plans) != 1 || len(plans[0].DeleteRoutes) != 1 || plans[0].DeleteRoutes[0].Family != domain.IPv4 || len(plans[0].UpsertRoutes) != 0 {
		t.Fatalf("activation continued after failed deactivation readback: %#v", plans)
	}
	if got := fixture.tailnet.currentPreferences(); !got.AdvertisesExitNode() {
		t.Fatalf("failed route transaction rewrote the atomic Exit Node advertisement: %v", got.AdvertiseRoutes)
	}
	state := fixture.routing.currentState()
	for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
		assertRouteAbsent(t, state, family, fixture.configuration.Network.ExitRouteTable, domain.DefaultPrefix(family), domain.RouteUnicast)
		requireRoute(t, state, family, fixture.configuration.Network.ExitRouteTable, domain.DefaultPrefix(family), domain.RouteBlackhole)
	}
}

func TestReconcilerUsesGlobalQuarantineWhenCapabilityChangeCoincidesWithUnrelatedDrift(t *testing.T) {
	fixture := newReconcilerFixture(t)
	if err := fixture.reconciler.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	fixture.packetFilter.mutex.Lock()
	fixture.packetFilter.observation.FilterRevision = "externally-modified"
	fixture.packetFilter.mutex.Unlock()
	fixture.tailnet.resetWrites()
	fixture.routing.resetWrites()
	fixture.packetFilter.resetWrites()
	fixture.recorder.reset()
	fixture.capability.set(capabilitySnapshotForActiveExitDefaultRoutes(
		fixture.discovery.snapshot.ProxyTunnelLink,
		time.Now(),
		domain.ExitDefaultRouteSet{IPv4: true},
	))

	report, err := fixture.reconciler.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	wantOrder := []string{
		"nftables-closed",
		"advertisements-cleared",
		"routing",
		"nftables-open",
		"advertisements-published",
	}
	if got := fixture.recorder.snapshot(); !slices.Equal(got, wantOrder) {
		t.Fatalf("unrelated drift bypassed global quarantine: got %v, want %v", got, wantOrder)
	}
	if report.TailnetWrites != 2 || report.RoutingWrites == 0 || report.PacketFilterWrites != 2 {
		t.Fatalf("global fallback transaction reported unexpected writes: %#v", report)
	}
	wantPreferences := domain.NewTailnetExitNodePreferences(fixture.configuration.Tailnet.AdvertiseRoutes)
	if got := fixture.tailnet.currentPreferences(); !got.Equal(wantPreferences) {
		t.Fatalf("global fallback did not restore the atomic Exit Node target: got %v, want %v", got.AdvertiseRoutes, wantPreferences.AdvertiseRoutes)
	}
}

func TestReconcilerUsesOneGlobalTransactionWhenFinalCapabilityLossCoincidesWithUnrelatedDrift(t *testing.T) {
	fixture := newReconcilerFixture(t)
	if err := fixture.reconciler.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}

	fixture.packetFilter.mutex.Lock()
	fixture.packetFilter.observation.FilterRevision = "externally-modified"
	fixture.packetFilter.mutex.Unlock()
	fixture.tailnet.resetWrites()
	fixture.routing.resetWrites()
	fixture.packetFilter.resetWrites()
	fixture.recorder.reset()
	fixture.capability.set(capabilitySnapshotForActiveExitDefaultRoutes(
		fixture.discovery.snapshot.ProxyTunnelLink,
		time.Now(),
		domain.ExitDefaultRouteSet{},
	))

	report, err := fixture.reconciler.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	wantOrder := []string{
		"nftables-closed",
		"advertisements-cleared",
		"routing",
		"nftables-open",
		"advertisements-published",
	}
	if got := fixture.recorder.snapshot(); !slices.Equal(got, wantOrder) {
		t.Fatalf("final capability loss fragmented the global transaction: got %v, want %v", got, wantOrder)
	}
	if report.TailnetWrites != 2 || fixture.tailnet.writeCalls() != 2 || report.RoutingWrites == 0 || report.PacketFilterWrites != 2 {
		t.Fatalf("global final-loss transaction reported unexpected writes: report=%#v tailnet=%d", report, fixture.tailnet.writeCalls())
	}
	wantPreferences := domain.NewTailnetPreferences(fixture.configuration.Tailnet.AdvertiseRoutes)
	if got := fixture.tailnet.currentPreferences(); !got.Equal(wantPreferences) {
		t.Fatalf("global final-loss transaction produced %v, want %v", got.AdvertiseRoutes, wantPreferences.AdvertiseRoutes)
	}
	state := fixture.routing.currentState()
	for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
		assertRouteAbsent(t, state, family, fixture.configuration.Network.ExitRouteTable, domain.DefaultPrefix(family), domain.RouteUnicast)
		requireRoute(t, state, family, fixture.configuration.Network.ExitRouteTable, domain.DefaultPrefix(family), domain.RouteBlackhole)
	}
}

func TestReconcilerReconcilesOperationalCapabilityStatesPerAddressFamily(t *testing.T) {
	tests := []struct {
		name                            string
		snapshot                        func(domain.LinkIdentity, time.Time) domain.InternetCapabilitySnapshot
		expectedActiveExitDefaultRoutes domain.ExitDefaultRouteSet
	}{
		{
			name: "initializing",
			snapshot: func(link domain.LinkIdentity, _ time.Time) domain.InternetCapabilitySnapshot {
				return domain.InternetCapabilitySnapshot{ProxyLink: link}
			},
		},
		{
			name:                            "ipv4 unavailable",
			expectedActiveExitDefaultRoutes: domain.ExitDefaultRouteSet{IPv6: true},
			snapshot: func(link domain.LinkIdentity, now time.Time) domain.InternetCapabilitySnapshot {
				fresh := domain.InternetFamilyCapability{Initialized: true, Available: true, ObservedAt: now, ValidUntil: now.Add(time.Minute)}
				return domain.InternetCapabilitySnapshot{
					ProxyLink: link,
					IPv4:      domain.InternetFamilyCapability{Initialized: true, ObservedAt: now},
					IPv6:      fresh,
				}
			},
		},
		{
			name:                            "ipv6 unavailable",
			expectedActiveExitDefaultRoutes: domain.ExitDefaultRouteSet{IPv4: true},
			snapshot: func(link domain.LinkIdentity, now time.Time) domain.InternetCapabilitySnapshot {
				fresh := domain.InternetFamilyCapability{Initialized: true, Available: true, ObservedAt: now, ValidUntil: now.Add(time.Minute)}
				return domain.InternetCapabilitySnapshot{
					ProxyLink: link,
					IPv4:      fresh,
					IPv6:      domain.InternetFamilyCapability{Initialized: true, ObservedAt: now},
				}
			},
		},
		{
			name: "both unavailable",
			snapshot: func(link domain.LinkIdentity, now time.Time) domain.InternetCapabilitySnapshot {
				unavailable := domain.InternetFamilyCapability{Initialized: true, ObservedAt: now}
				return domain.InternetCapabilitySnapshot{ProxyLink: link, IPv4: unavailable, IPv6: unavailable}
			},
		},
		{
			name:                            "stale",
			expectedActiveExitDefaultRoutes: domain.ExitDefaultRouteSet{IPv6: true},
			snapshot: func(link domain.LinkIdentity, now time.Time) domain.InternetCapabilitySnapshot {
				fresh := domain.InternetFamilyCapability{Initialized: true, Available: true, ObservedAt: now, ValidUntil: now.Add(time.Minute)}
				stale := domain.InternetFamilyCapability{Initialized: true, Available: true, ObservedAt: now.Add(-2 * time.Minute), ValidUntil: now.Add(-time.Minute)}
				return domain.InternetCapabilitySnapshot{ProxyLink: link, IPv4: stale, IPv6: fresh}
			},
		},
		{
			name: "link mismatch",
			snapshot: func(_ domain.LinkIdentity, now time.Time) domain.InternetCapabilitySnapshot {
				fresh := domain.InternetFamilyCapability{Initialized: true, Available: true, ObservedAt: now, ValidUntil: now.Add(time.Minute)}
				return domain.InternetCapabilitySnapshot{
					ProxyLink: domain.LinkIdentity{Index: 99, Name: "proxy-replaced"}, IPv4: fresh, IPv6: fresh,
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newReconcilerFixture(t)
			if err := fixture.reconciler.Prepare(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.reconciler.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			fixture.tailnet.resetWrites()
			fixture.routing.resetWrites()
			fixture.packetFilter.resetWrites()
			fixture.recorder.reset()
			fixture.capability.set(test.snapshot(fixture.discovery.snapshot.ProxyTunnelLink, time.Now()))

			reconciled, err := fixture.reconciler.Reconcile(context.Background())
			if err != nil {
				t.Fatalf("operational capability state became a technical error: %v", err)
			}
			expectedTailnetWrites := 0
			if test.expectedActiveExitDefaultRoutes.Empty() {
				expectedTailnetWrites = 1
			}
			if len(reconciled.Conditions) == 0 || reconciled.TailnetWrites != expectedTailnetWrites || fixture.tailnet.writeCalls() != expectedTailnetWrites {
				t.Fatalf("capability state changed the atomic advertisement unexpectedly: %#v", reconciled)
			}
			if reconciled.DataPlaneAvailable == test.expectedActiveExitDefaultRoutes.Empty() {
				t.Fatalf("data-plane availability does not match active Exit families: report=%#v active=%#v", reconciled, test.expectedActiveExitDefaultRoutes)
			}
			if reconciled.RoutingWrites == 0 || fixture.routing.writeCalls() != 1 || reconciled.PacketFilterWrites != 0 || fixture.packetFilter.writeCalls() != 0 {
				t.Fatalf("capability state did not remain isolated to Exit defaults: report=%#v routing_calls=%d nftables_calls=%d", reconciled, fixture.routing.writeCalls(), fixture.packetFilter.writeCalls())
			}
			wantPreferences := tailnetPreferencesForActiveExitRoutes(fixture.configuration.Tailnet.AdvertiseRoutes, test.expectedActiveExitDefaultRoutes)
			if got := fixture.tailnet.currentPreferences(); !got.Equal(wantPreferences) {
				t.Fatalf("capability state produced wrong atomic Exit Node preferences: got %v, want %v", got.AdvertiseRoutes, wantPreferences.AdvertiseRoutes)
			}
			state := fixture.routing.currentState()
			for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
				if test.expectedActiveExitDefaultRoutes.Contains(family) {
					requireRoute(t, state, family, fixture.configuration.Network.ExitRouteTable, domain.DefaultPrefix(family), domain.RouteUnicast)
				} else {
					assertRouteAbsent(t, state, family, fixture.configuration.Network.ExitRouteTable, domain.DefaultPrefix(family), domain.RouteUnicast)
				}
			}

			fixture.tailnet.resetWrites()
			fixture.routing.resetWrites()
			fixture.packetFilter.resetWrites()
			fixture.recorder.reset()
			steady, err := fixture.reconciler.Reconcile(context.Background())
			if err != nil || steady.Changed || steady.TailnetWrites != 0 || steady.RoutingWrites != 0 || steady.PacketFilterWrites != 0 ||
				fixture.tailnet.writeCalls() != 0 || fixture.routing.writeCalls() != 0 || fixture.packetFilter.writeCalls() != 0 {
				t.Fatalf("steady capability state repeated writes: report=%#v tailnet=%d routing=%d nftables=%d err=%v", steady, fixture.tailnet.writeCalls(), fixture.routing.writeCalls(), fixture.packetFilter.writeCalls(), err)
			}
		})
	}
}

func TestReconcilerRejectsUnavailableTailnetControlObservations(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*domain.TailnetControlObservation)
		fragment string
	}{
		{name: "missing Self", mutate: func(observation *domain.TailnetControlObservation) {
			*observation = domain.TailnetControlObservation{ObservedAt: time.Now()}
		}, fragment: "no self node"},
		{name: "missing netmap", mutate: func(observation *domain.TailnetControlObservation) {
			observation.InNetworkMap = false
		}, fragment: "absent from the current network map"},
		{name: "offline control", mutate: func(observation *domain.TailnetControlObservation) {
			observation.Online = false
		}, fragment: "control poll is offline"},
		{name: "nil AllowedIPs", mutate: func(observation *domain.TailnetControlObservation) {
			observation.AllowedIPsAvailable = false
			observation.ApprovedRoutes = nil
		}, fragment: "AllowedIPs is unavailable"},
		{name: "stale observation", mutate: func(observation *domain.TailnetControlObservation) {
			observation.ObservedAt = time.Now().Add(-time.Minute)
		}, fragment: "outside the freshness window"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newReconcilerFixture(t)
			test.mutate(&fixture.tailnet.state.Control)
			if _, err := fixture.reconciler.Reconcile(context.Background()); err == nil || !strings.Contains(err.Error(), test.fragment) {
				t.Fatalf("expected %q error, got %v", test.fragment, err)
			}
			if fixture.tailnet.writeCalls() != 0 {
				t.Fatal("invalid control observation caused a preference write")
			}
		})
	}
}

func TestReconcilerUsesOneResolverSnapshotPerReconcile(t *testing.T) {
	fixture := newReconcilerFixture(t)
	if err := fixture.reconciler.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.resolver.snapshots = 0
	if _, err := fixture.reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fixture.resolver.snapshots != 1 {
		t.Fatalf("reconcile read %d resolver snapshots, want exactly one", fixture.resolver.snapshots)
	}
}

func TestReconcilerRouteChangeIsQuarantinedBeforeApplyingDifferences(t *testing.T) {
	fixture := newReconcilerFixture(t)
	if err := fixture.reconciler.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.routing.resetWrites()
	fixture.packetFilter.resetWrites()
	fixture.tailnet.resetWrites()
	fixture.recorder.reset()

	fixture.discovery.snapshot.AdvertisedRoutes[0].Link = domain.LinkIdentity{Index: 14, Name: "internal-next"}
	fixture.discovery.snapshot.DNSEgressPaths[0].Link = domain.LinkIdentity{Index: 15, Name: "dns-v4-next"}
	report, err := fixture.reconciler.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.RoutingWrites == 0 || report.PacketFilterWrites != 2 || report.TailnetWrites != 2 {
		t.Fatalf("unexpected drift report: %#v", report)
	}
	if got := fixture.recorder.snapshot(); !slices.Equal(got, []string{"nftables-closed", "advertisements-cleared", "routing", "nftables-open", "advertisements-published"}) {
		t.Fatalf("unexpected drift write order: %v", got)
	}
	policy := fixture.packetFilter.lastPolicy()
	target := findDNSTarget(t, policy, netip.MustParseAddr("10.43.0.10"))
	if target.OutputInterface != "dns-v4-next" {
		t.Fatalf("DNS policy retained a stale output interface: %#v", target)
	}
}

func TestReconcilerPrepareRoutesLocalControlTrafficBeforeManagedProcessStartup(t *testing.T) {
	fixture := newReconcilerFixture(t)
	if err := fixture.reconciler.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	state := fixture.routing.currentState()
	for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
		route := requireRoute(t, state, family, fixture.configuration.Network.LocalEgressRouteTable, domain.DefaultPrefix(family), domain.RouteUnicast)
		if route.Link != fixture.discovery.snapshot.ProxyTunnelLink {
			t.Fatalf("family %d local control route does not use the proxy tunnel: %#v", family, route)
		}
		requireRule(t, state, family, fixture.configuration.Network.LocalEgressRulePriority)
	}
	policy := fixture.packetFilter.lastPolicy()
	if !policy.GateClosed || !policy.LocalEgress.Enabled || len(policy.LocalEgress.IPv4) == 0 || len(policy.LocalEgress.IPv6) == 0 {
		t.Fatalf("startup quarantine did not prepare local control marking: %#v", policy)
	}
	if fixture.tailnet.writeCalls() != 0 {
		t.Fatal("preparation wrote Tailscale preferences before containerboot startup")
	}
}

func TestReconcilerPrepareClosesForwardingBeforeRoutingMutations(t *testing.T) {
	fixture := newReconcilerFixture(t)
	if err := fixture.reconciler.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	operations := fixture.recorder.snapshot()
	quarantineIndex := slices.Index(operations, "nftables-closed")
	routingIndex := slices.Index(operations, "routing")
	if quarantineIndex < 0 || routingIndex < 0 || quarantineIndex > routingIndex {
		t.Fatalf("startup routing changed before forwarding quarantine: %v", operations)
	}
}

func TestReconcilerPrepareRejectsInvalidProxyTunnelIdentity(t *testing.T) {
	fixture := newReconcilerFixture(t)
	fixture.discovery.snapshot.ProxyTunnelLink = domain.LinkIdentity{Index: 3, Name: "invalid:name"}
	if err := fixture.reconciler.Prepare(context.Background()); err == nil || !strings.Contains(err.Error(), "validate proxy tunnel") {
		t.Fatalf("invalid startup proxy tunnel identity was accepted: %v", err)
	}
}

func TestReconcilerLiveFailClosedRetainsVerifiedLocalControlEgressDuringTailnetBootstrap(t *testing.T) {
	fixture := newReconcilerFixture(t)
	if err := fixture.reconciler.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.recorder.reset()
	fixture.tailnet.mutex.Lock()
	fixture.tailnet.state.Control.InNetworkMap = false
	fixture.tailnet.mutex.Unlock()

	if _, err := fixture.reconciler.Reconcile(context.Background()); err == nil || !strings.Contains(err.Error(), "absent from the current network map") {
		t.Fatalf("unavailable bootstrap state was accepted: %v", err)
	}
	report, err := fixture.reconciler.FailClosed(context.Background())
	if err == nil || !strings.Contains(err.Error(), "absent from the current network map") {
		t.Fatalf("live fail-closed state did not report unavailable Tailnet control: %v", err)
	}
	if report.Changed || len(fixture.recorder.snapshot()) != 0 {
		t.Fatalf("verified startup recovery path was rewritten: report=%#v operations=%v", report, fixture.recorder.snapshot())
	}

	state := fixture.routing.currentState()
	proxyLink := fixture.discovery.snapshot.ProxyTunnelLink
	for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
		active := requireRoute(t, state, family, fixture.configuration.Network.LocalEgressRouteTable, domain.DefaultPrefix(family), domain.RouteUnicast)
		if active.Link != proxyLink {
			t.Fatalf("family %d local recovery route uses %#v, want %#v", family, active.Link, proxyLink)
		}
		requireRoute(t, state, family, fixture.configuration.Network.LocalEgressRouteTable, domain.DefaultPrefix(family), domain.RouteBlackhole)
		requireRoute(t, state, family, fixture.configuration.Network.ExitRouteTable, domain.DefaultPrefix(family), domain.RouteBlackhole)
	}
	policy := fixture.packetFilter.lastPolicy()
	if !policy.GateClosed || !policy.LocalEgress.Enabled || len(policy.LocalEgress.IPv4) == 0 || len(policy.LocalEgress.IPv6) == 0 {
		t.Fatalf("live fail-closed policy lost bounded local-control marking: %#v", policy)
	}

	fixture.tailnet.mutex.Lock()
	fixture.tailnet.state.Control.InNetworkMap = true
	fixture.tailnet.state.Control.ObservedAt = time.Now()
	fixture.tailnet.mutex.Unlock()
	if recovered, err := fixture.reconciler.Reconcile(context.Background()); err != nil || len(recovered.Conditions) != 0 {
		t.Fatalf("Tailnet bootstrap did not recover through the retained control path: report=%#v err=%v", recovered, err)
	}
}

func TestReconcilerLiveFailClosedBlackholesUnverifiedLocalControlEgress(t *testing.T) {
	tests := []struct {
		name              string
		breakRecoveryPath func(*reconcilerFixture)
	}{
		{name: "kernel", breakRecoveryPath: func(fixture *reconcilerFixture) {
			fixture.kernel.err = errors.New("kernel prerequisites unavailable")
		}},
		{name: "resolver", breakRecoveryPath: func(fixture *reconcilerFixture) {
			fixture.resolver.err = errors.New("resolver snapshot unavailable")
		}},
		{name: "proxy tunnel", breakRecoveryPath: func(fixture *reconcilerFixture) {
			fixture.discovery.err = errors.New("proxy tunnel is ambiguous")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newReconcilerFixture(t)
			if err := fixture.reconciler.Prepare(context.Background()); err != nil {
				t.Fatal(err)
			}
			test.breakRecoveryPath(fixture)

			report, err := fixture.reconciler.FailClosed(context.Background())
			if err == nil || !strings.Contains(err.Error(), "verify local control-plane recovery path") {
				t.Fatalf("unverified recovery path was not reported: %v", err)
			}
			if report.RoutingWrites == 0 {
				t.Fatalf("unverified recovery path did not converge to strict routing: %#v", report)
			}
			state := fixture.routing.currentState()
			for _, route := range state.Routes {
				if route.Table == fixture.configuration.Network.LocalEgressRouteTable && route.Disposition == domain.RouteUnicast {
					t.Fatalf("unverified local recovery route remained active: %#v", route)
				}
			}
			for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
				requireRoute(t, state, family, fixture.configuration.Network.LocalEgressRouteTable, domain.DefaultPrefix(family), domain.RouteBlackhole)
			}
		})
	}
}

func TestReconcilerLiveFailClosedRestoresStrictRoutingAfterFinalKernelFailure(t *testing.T) {
	fixture := newReconcilerFixture(t)
	if err := fixture.reconciler.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.kernel.failOnCheck(2, errors.New("kernel prerequisites drifted after recovery convergence"))

	report, err := fixture.reconciler.FailClosed(context.Background())
	if err == nil || !strings.Contains(err.Error(), "reverify kernel prerequisites for local control-plane recovery") {
		t.Fatalf("final recovery-path failure was not reported: %v", err)
	}
	if report.RoutingWrites == 0 {
		t.Fatalf("final recovery-path failure did not restore strict routing: %#v", report)
	}
	state := fixture.routing.currentState()
	for _, route := range state.Routes {
		if route.Table == fixture.configuration.Network.LocalEgressRouteTable && route.Disposition == domain.RouteUnicast {
			t.Fatalf("late recovery-path failure left local egress active: %#v", route)
		}
	}
	for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
		requireRoute(t, state, family, fixture.configuration.Network.LocalEgressRouteTable, domain.DefaultPrefix(family), domain.RouteBlackhole)
		requireRoute(t, state, family, fixture.configuration.Network.ExitRouteTable, domain.DefaultPrefix(family), domain.RouteBlackhole)
	}
}

func TestReconcilerShutdownAlwaysBlackholesLocalControlEgress(t *testing.T) {
	fixture := newReconcilerFixture(t)
	if err := fixture.reconciler.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.kernel.err = errors.New("kernel recovery check must not run during shutdown")
	fixture.resolver.err = errors.New("resolver recovery check must not run during shutdown")
	fixture.discovery.err = errors.New("proxy recovery check must not run during shutdown")
	if err := fixture.reconciler.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	state := fixture.routing.currentState()
	for _, route := range state.Routes {
		if route.Table == fixture.configuration.Network.LocalEgressRouteTable && route.Disposition == domain.RouteUnicast {
			t.Fatalf("shutdown retained local recovery route: %#v", route)
		}
	}
	for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
		requireRoute(t, state, family, fixture.configuration.Network.LocalEgressRouteTable, domain.DefaultPrefix(family), domain.RouteBlackhole)
	}
}

func TestReconcilerDiscoveryFailureClosesGateBeforeClearingAdvertisements(t *testing.T) {
	fixture := newReconcilerFixture(t)
	if err := fixture.reconciler.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.recorder.reset()
	fixture.discovery.err = errors.New("kernel route is no longer deterministic")
	if _, err := fixture.reconciler.Reconcile(context.Background()); err == nil {
		t.Fatal("discovery failure was accepted")
	}
	if _, err := fixture.reconciler.FailClosed(context.Background()); err == nil || !strings.Contains(err.Error(), "verify local control-plane recovery path") {
		t.Fatalf("unverified recovery path was not reported: %v", err)
	}
	if got := fixture.recorder.snapshot(); !slices.Equal(got, []string{"nftables-closed", "routing", "advertisements-cleared"}) {
		t.Fatalf("unexpected fail-closed order: %v", got)
	}
}

func TestFailClosedRoutingKeepsSelectorsBoundToBlackholeTables(t *testing.T) {
	configuration := applicationTestConfiguration()
	state := buildFailClosedRouting(configuration, applicationTestSnapshot().TailnetLink, domain.LinkIdentity{})
	for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
		exitRule := requireRule(t, state, family, configuration.Network.ExitRulePriority)
		if exitRule.IncomingInterface == "" || exitRule.Table != configuration.Network.ExitRouteTable {
			t.Fatalf("family %d exit selector escaped fail-closed table: %#v", family, exitRule)
		}
		localRule := requireRule(t, state, family, configuration.Network.LocalEgressRulePriority)
		if localRule.Mark != configuration.Network.LocalEgressPacketMark || localRule.Mask != domain.LocalEgressPacketMarkMask || localRule.Table != configuration.Network.LocalEgressRouteTable {
			t.Fatalf("family %d marked traffic escaped fail-closed table: %#v", family, localRule)
		}
		requireRoute(t, state, family, configuration.Network.ExitRouteTable, domain.DefaultPrefix(family), domain.RouteBlackhole)
		requireRoute(t, state, family, configuration.Network.LocalEgressRouteTable, domain.DefaultPrefix(family), domain.RouteBlackhole)
	}
}

func TestRecoverableFailClosedRoutingKeepsExitClosedAndLocalControlOnVerifiedProxy(t *testing.T) {
	configuration := applicationTestConfiguration()
	snapshot := applicationTestSnapshot()
	state := buildFailClosedRouting(configuration, snapshot.TailnetLink, snapshot.ProxyTunnelLink)
	for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
		requireRoute(t, state, family, configuration.Network.ExitRouteTable, domain.DefaultPrefix(family), domain.RouteBlackhole)
		local := requireRoute(t, state, family, configuration.Network.LocalEgressRouteTable, domain.DefaultPrefix(family), domain.RouteUnicast)
		if local.Link != snapshot.ProxyTunnelLink {
			t.Fatalf("family %d recovery route uses %#v, want %#v", family, local.Link, snapshot.ProxyTunnelLink)
		}
		requireRoute(t, state, family, configuration.Network.LocalEgressRouteTable, domain.DefaultPrefix(family), domain.RouteBlackhole)
	}
}

func TestReconcilerRejectsForwardingDrift(t *testing.T) {
	fixture := newReconcilerFixture(t)
	if err := fixture.reconciler.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.reconciler.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.kernel.mutex.Lock()
	fixture.kernel.err = errors.New("IPv6 forwarding is disabled")
	fixture.kernel.mutex.Unlock()
	if _, err := fixture.reconciler.Reconcile(context.Background()); err == nil || !strings.Contains(err.Error(), "IPv6 forwarding") {
		t.Fatalf("forwarding drift was accepted: %v", err)
	}
}

func TestReconcilerRejectsUnverifiedTailnetPreferenceWrite(t *testing.T) {
	fixture := newReconcilerFixture(t)
	fixture.tailnet.ignoreWrites = true
	if err := fixture.reconciler.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err := fixture.reconciler.Reconcile(context.Background())
	if err == nil || !strings.Contains(err.Error(), "did not converge") {
		t.Fatalf("unverified LocalAPI write was accepted: %v", err)
	}
}

func TestStatusDoesNotOverwriteAnEventThatArrivesDuringReconciliation(t *testing.T) {
	status := NewStatus(time.Minute)
	now := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	status.now = func() time.Time { return now }
	epoch := status.BeginReconcile()
	status.MarkDirty()
	if status.RecordSuccess(now, epoch, domain.ReconcileReport{DataPlaneAvailable: true}) {
		t.Fatal("superseded reconciliation was marked ready")
	}
	if snapshot := status.HealthSnapshot(); snapshot.Ready || snapshot.DataPlaneAvailable {
		t.Fatalf("superseded reconciliation overwrote the newer network event: %#v", snapshot)
	}
	nextEpoch := status.BeginReconcile()
	if !status.RecordSuccess(now, nextEpoch, domain.ReconcileReport{DataPlaneAvailable: true}) || !status.HealthSnapshot().Ready {
		t.Fatal("latest successful reconciliation did not become ready")
	}
}

func TestStatusKeepsAnAvailableDataPlaneReadyWhileReportingDegradation(t *testing.T) {
	status := NewStatus(time.Minute)
	now := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	status.now = func() time.Time { return now }
	condition := domain.ReconcileCondition{
		Kind: domain.ConditionRouteNotApproved, Family: domain.IPv4, Prefix: netip.MustParsePrefix("10.0.8.0/24"),
	}
	if !status.RecordSuccess(now, status.BeginReconcile(), domain.ReconcileReport{
		DataPlaneAvailable: true,
		Conditions:         []domain.ReconcileCondition{condition},
	}) {
		t.Fatal("available data plane with a warning was marked not ready")
	}
	snapshot := status.HealthSnapshot()
	if !snapshot.Ready || !snapshot.DataPlaneAvailable || snapshot.Phase != domain.RuntimeDegraded || snapshot.LastError != "" || !slices.Equal(snapshot.Conditions, []domain.ReconcileCondition{condition}) {
		t.Fatalf("operational degradation was not preserved: %#v", snapshot)
	}
}

func TestStatusRejectsUnavailableDataPlaneAndPreservesRoutineAuditReadiness(t *testing.T) {
	status := NewStatus(time.Minute)
	now := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	status.now = func() time.Time { return now }
	if !status.RecordSuccess(now, status.BeginReconcile(), domain.ReconcileReport{DataPlaneAvailable: true}) {
		t.Fatal("initial verified data plane was not ready")
	}

	auditEpoch := status.BeginReconcile()
	if !status.HealthSnapshot().Ready {
		t.Fatal("routine audit revoked a still-current verified data plane")
	}
	condition := domain.ReconcileCondition{Kind: domain.ConditionInternetCapabilityUnavailable, Family: domain.IPv4}
	if status.RecordSuccess(now, auditEpoch, domain.ReconcileReport{Conditions: []domain.ReconcileCondition{condition}}) {
		t.Fatal("unavailable data plane was marked ready")
	}
	snapshot := status.HealthSnapshot()
	if snapshot.Ready || snapshot.DataPlaneAvailable || snapshot.Phase != domain.RuntimeDegraded {
		t.Fatalf("unavailable data plane status is inconsistent: %#v", snapshot)
	}
}

type reconcilerFixture struct {
	configuration domain.Configuration
	reconciler    *Reconciler
	discovery     *fakeDiscovery
	routing       *fakeRoutingStore
	packetFilter  *fakePacketFilterStore
	resolver      *fakeDNSResolver
	tailnet       *fakeTailnetControl
	capability    *fakeInternetCapability
	kernel        *fakeKernelPrerequisites
	recorder      *operationRecorder
}

func newReconcilerFixture(t *testing.T) *reconcilerFixture {
	t.Helper()
	configuration := applicationTestConfiguration()
	recorder := &operationRecorder{}
	discovery := &fakeDiscovery{snapshot: applicationTestSnapshot()}
	routing := &fakeRoutingStore{recorder: recorder}
	packetFilter := &fakePacketFilterStore{recorder: recorder}
	resolver := &fakeDNSResolver{
		nameServers: []netip.Addr{netip.MustParseAddr("10.43.0.10"), netip.MustParseAddr("fd00:43::a")},
		resolved:    []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")},
	}
	tailnet := &fakeTailnetControl{
		recorder: recorder,
		state: domain.TailnetState{
			Running: true, KernelTunnel: true,
			SelfAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.8"), netip.MustParseAddr("fd7a:115c:a1e0::8")},
			Preferences:   domain.NewTailnetPreferences(nil),
			Control: domain.TailnetControlObservation{
				SelfPresent: true, InNetworkMap: true, Online: true, AllowedIPsAvailable: true,
				ApprovedRoutes: domain.NewTailnetExitNodePreferences(configuration.Tailnet.AdvertiseRoutes).AdvertiseRoutes,
				ObservedAt:     time.Now(),
			},
		},
	}
	now := time.Now()
	freshCapability := domain.InternetFamilyCapability{Initialized: true, Available: true, ObservedAt: now, ValidUntil: now.Add(time.Minute)}
	capability := &fakeInternetCapability{snapshot: domain.InternetCapabilitySnapshot{
		ProxyLink: discovery.snapshot.ProxyTunnelLink, IPv4: freshCapability, IPv6: freshCapability,
	}}
	kernel := &fakeKernelPrerequisites{}
	reconciler, err := NewReconciler(configuration, ReconcilerDependencies{
		Kernel: kernel, ProxyTunnel: discovery, Network: discovery, Routing: routing, PacketFilter: packetFilter, Resolver: resolver, Tailnet: tailnet,
		InternetCapability: capability,
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &reconcilerFixture{
		configuration: configuration, reconciler: reconciler, discovery: discovery, routing: routing,
		packetFilter: packetFilter, resolver: resolver, tailnet: tailnet, capability: capability, kernel: kernel, recorder: recorder,
	}
}

func applicationTestConfiguration() domain.Configuration {
	configuration := domain.DefaultConfiguration()
	configuration.Network.ProxyTunnelAddresses = []netip.Prefix{
		netip.MustParsePrefix("198.18.0.1/15"),
		netip.MustParsePrefix("fd88:baba:fafa::1/126"),
	}
	configuration.Coordination.Backend = domain.CoordinationFileLock
	configuration.Tailnet.AdvertiseRoutes = []netip.Prefix{netip.MustParsePrefix("10.0.8.0/24")}
	configuration.Tailnet.AdvertiseExitNode = true
	configuration.InternetCapability.IPv4ProbeURL = "https://ipv4.probe.example.com/status"
	configuration.InternetCapability.IPv6ProbeURL = "https://ipv6.probe.example.com/status"
	configuration.PacketFilter.LocalEgress.Enabled = true
	configuration.PacketFilter.LocalEgress.Domains = []string{"control.example.com"}
	return configuration
}

func applicationTestSnapshot() domain.NetworkSnapshot {
	return domain.NetworkSnapshot{
		TailnetLink:     domain.LinkIdentity{Index: 2, Name: "tailnet-in"},
		ProxyTunnelLink: domain.LinkIdentity{Index: 3, Name: "proxy-path"},
		AdvertisedRoutes: []domain.DirectRouteProjection{{
			Prefix: netip.MustParsePrefix("10.0.8.0/24"), Gateway: netip.MustParseAddr("10.42.0.1"), Link: domain.LinkIdentity{Index: 4, Name: "internal-path"},
		}},
		DNSEgressPaths: []domain.DNSEgressPath{
			{NameServer: netip.MustParseAddr("10.43.0.10"), Gateway: netip.MustParseAddr("10.42.0.1"), Link: domain.LinkIdentity{Index: 5, Name: "dns-path-v4"}},
			{NameServer: netip.MustParseAddr("fd00:43::a"), Gateway: netip.MustParseAddr("fd00:42::1"), Link: domain.LinkIdentity{Index: 6, Name: "dns-path-v6"}},
		},
	}
}

func capabilitySnapshotForActiveExitDefaultRoutes(link domain.LinkIdentity, now time.Time, availableRoutes domain.ExitDefaultRouteSet) domain.InternetCapabilitySnapshot {
	fresh := domain.InternetFamilyCapability{
		Initialized: true,
		Available:   true,
		ObservedAt:  now,
		ValidUntil:  now.Add(time.Minute),
	}
	unavailable := domain.InternetFamilyCapability{Initialized: true, ObservedAt: now}
	snapshot := domain.InternetCapabilitySnapshot{ProxyLink: link, IPv4: unavailable, IPv6: unavailable}
	if availableRoutes.IPv4 {
		snapshot.IPv4 = fresh
	}
	if availableRoutes.IPv6 {
		snapshot.IPv6 = fresh
	}
	return snapshot
}

func tailnetPreferencesForActiveExitRoutes(advertisedRoutes []netip.Prefix, activeRoutes domain.ExitDefaultRouteSet) domain.TailnetPreferences {
	if activeRoutes.Empty() {
		return domain.NewTailnetPreferences(advertisedRoutes)
	}
	return domain.NewTailnetExitNodePreferences(advertisedRoutes)
}

func requireRoute(t *testing.T, state domain.RoutingState, family domain.AddressFamily, table int, prefix netip.Prefix, disposition domain.RouteDisposition) domain.Route {
	t.Helper()
	for _, route := range state.Routes {
		if route.Family == family && route.Table == table && route.Prefix == prefix && route.Disposition == disposition {
			return route
		}
	}
	t.Fatalf("route family=%d table=%d prefix=%s disposition=%s not found in %#v", family, table, prefix, disposition, state.Routes)
	return domain.Route{}
}

func assertRouteAbsent(t *testing.T, state domain.RoutingState, family domain.AddressFamily, table int, prefix netip.Prefix, disposition domain.RouteDisposition) {
	t.Helper()
	for _, route := range state.Routes {
		if route.Family == family && route.Table == table && route.Prefix == prefix && route.Disposition == disposition {
			t.Fatalf("unexpected route family=%d table=%d prefix=%s disposition=%s found in %#v", family, table, prefix, disposition, state.Routes)
		}
	}
}

func requireRule(t *testing.T, state domain.RoutingState, family domain.AddressFamily, priority int) domain.Rule {
	t.Helper()
	for _, rule := range state.Rules {
		if rule.Family == family && rule.Priority == priority {
			return rule
		}
	}
	t.Fatalf("rule family=%d priority=%d not found in %#v", family, priority, state.Rules)
	return domain.Rule{}
}

func findDNSTarget(t *testing.T, policy domain.PacketFilterPolicy, address netip.Addr) domain.DNSMasqueradeTarget {
	t.Helper()
	for _, target := range policy.DNSTargets {
		if target.Address == address {
			return target
		}
	}
	t.Fatalf("DNS target %s not found", address)
	return domain.DNSMasqueradeTarget{}
}

func lastValueIndex(values []string, target string) int {
	for index := len(values) - 1; index >= 0; index-- {
		if values[index] == target {
			return index
		}
	}
	return -1
}

type operationRecorder struct {
	mutex  sync.Mutex
	values []string
}

func (recorder *operationRecorder) add(value string) {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()
	recorder.values = append(recorder.values, value)
}

func (recorder *operationRecorder) snapshot() []string {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()
	return slices.Clone(recorder.values)
}

func (recorder *operationRecorder) reset() {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()
	recorder.values = nil
}

type fakeDiscovery struct {
	mutex              sync.Mutex
	snapshot           domain.NetworkSnapshot
	err                error
	calls              int
	entered            chan struct{}
	release            <-chan struct{}
	proxyTunnelEntered chan struct{}
	proxyTunnelRelease <-chan struct{}
}

type fakeKernelPrerequisites struct {
	mutex      sync.Mutex
	err        error
	calls      int
	failAtCall int
	failErr    error
}

func (checker *fakeKernelPrerequisites) Check(context.Context) error {
	checker.mutex.Lock()
	defer checker.mutex.Unlock()
	checker.calls++
	if checker.calls == checker.failAtCall {
		return checker.failErr
	}
	return checker.err
}

func (checker *fakeKernelPrerequisites) failOnCheck(call int, err error) {
	checker.mutex.Lock()
	defer checker.mutex.Unlock()
	checker.calls = 0
	checker.failAtCall = call
	checker.failErr = err
}

func (discovery *fakeDiscovery) Discover(ctx context.Context, _ domain.DiscoveryRequest) (domain.NetworkSnapshot, error) {
	discovery.mutex.Lock()
	discovery.calls++
	snapshot, err := discovery.snapshot, discovery.err
	entered, release := discovery.entered, discovery.release
	discovery.mutex.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return domain.NetworkSnapshot{}, ctx.Err()
		}
	}
	return snapshot, err
}

func (discovery *fakeDiscovery) DiscoverProxyTunnel(ctx context.Context, request domain.ProxyTunnelDiscoveryRequest) (domain.LinkIdentity, error) {
	if err := request.Validate(); err != nil {
		return domain.LinkIdentity{}, err
	}
	discovery.mutex.Lock()
	link, err := discovery.snapshot.ProxyTunnelLink, discovery.err
	entered, release := discovery.proxyTunnelEntered, discovery.proxyTunnelRelease
	discovery.mutex.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return domain.LinkIdentity{}, ctx.Err()
		}
	}
	if err := ctx.Err(); err != nil {
		return domain.LinkIdentity{}, err
	}
	return link, err
}

type fakeRoutingStore struct {
	mutex                  sync.Mutex
	state                  domain.RoutingState
	writes                 int
	applyCount             int
	applied                []domain.RoutingChanges
	recorder               *operationRecorder
	recordReads            bool
	mutationAfterNextApply func(*domain.RoutingState)
}

func (store *fakeRoutingStore) ReadRouting(context.Context, domain.RoutingOwnership) (domain.RoutingState, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.recordReads {
		store.recorder.add("routing-read")
	}
	return cloneRoutingState(store.state), nil
}

func (store *fakeRoutingStore) ApplyRouting(_ context.Context, changes domain.RoutingChanges) (int, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.applyCount++
	store.applied = append(store.applied, cloneRoutingChanges(changes))
	store.recorder.add("routing")
	store.state = applyRoutingChanges(store.state, changes)
	if store.mutationAfterNextApply != nil {
		mutation := store.mutationAfterNextApply
		store.mutationAfterNextApply = nil
		mutation(&store.state)
	}
	writes := len(changes.UpsertRoutes) + len(changes.DeleteRules) + len(changes.AddRules) + len(changes.DeleteRoutes)
	store.writes += writes
	return writes, nil
}

func (store *fakeRoutingStore) resetWrites() {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.writes = 0
	store.applyCount = 0
	store.applied = nil
}

func (store *fakeRoutingStore) writeCalls() int {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	return store.applyCount
}

func (store *fakeRoutingStore) appliedChanges() []domain.RoutingChanges {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	result := make([]domain.RoutingChanges, len(store.applied))
	for index := range store.applied {
		result[index] = cloneRoutingChanges(store.applied[index])
	}
	return result
}

func (store *fakeRoutingStore) currentState() domain.RoutingState {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	return cloneRoutingState(store.state)
}

func (store *fakeRoutingStore) injectObservedRoute(route domain.Route) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.state.Routes = removeRouteIdentity(store.state.Routes, route)
	store.state.Routes = append(store.state.Routes, route)
}

func (store *fakeRoutingStore) mutateAfterNextApply(mutation func(*domain.RoutingState)) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.mutationAfterNextApply = mutation
}

type fakePacketFilterStore struct {
	mutex        sync.Mutex
	observation  domain.PacketFilterObservation
	writes       int
	last         domain.PacketFilterPolicy
	recorder     *operationRecorder
	recordReads  bool
	applyEntered chan<- struct{}
	applyRelease <-chan struct{}
}

func (store *fakePacketFilterStore) Observe(context.Context, domain.PacketFilterPolicy) (domain.PacketFilterObservation, error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.recordReads {
		store.recorder.add("nftables-read")
	}
	return store.observation, nil
}

func (store *fakePacketFilterStore) Apply(ctx context.Context, policy domain.PacketFilterPolicy, _ domain.PacketFilterObservation) error {
	store.mutex.Lock()
	entered, release := store.applyEntered, store.applyRelease
	store.applyEntered = nil
	store.applyRelease = nil
	store.mutex.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.writes++
	store.last = policy
	label := "nftables-open"
	if policy.GateClosed {
		label = "nftables-closed"
	}
	store.recorder.add(label)
	store.observation = domain.PacketFilterObservation{
		FilterTableExists: true,
		FilterRevision:    policy.FilterRevision(),
		NATTableExists:    len(policy.DNSTargets) > 0,
	}
	if len(policy.DNSTargets) > 0 {
		store.observation.NATRevision = policy.NATRevision()
	}
	return nil
}

func (store *fakePacketFilterStore) blockNextApply(entered chan<- struct{}, release <-chan struct{}) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.applyEntered = entered
	store.applyRelease = release
}

func (store *fakePacketFilterStore) resetWrites() {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.writes = 0
}

func (store *fakePacketFilterStore) writeCalls() int {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	return store.writes
}

func (store *fakePacketFilterStore) lastPolicy() domain.PacketFilterPolicy {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	return store.last
}

type fakeDNSResolver struct {
	nameServers []netip.Addr
	resolved    []netip.Addr
	err         error
	snapshots   int
}

func (resolver *fakeDNSResolver) Snapshot(context.Context) (port.DNSResolverSnapshot, error) {
	resolver.snapshots++
	if resolver.err != nil {
		return nil, resolver.err
	}
	return fakeDNSResolverSnapshot{
		nameServers: slices.Clone(resolver.nameServers), resolved: slices.Clone(resolver.resolved),
	}, nil
}

type fakeDNSResolverSnapshot struct {
	nameServers []netip.Addr
	resolved    []netip.Addr
}

func (snapshot fakeDNSResolverSnapshot) NameServers() []netip.Addr {
	return slices.Clone(snapshot.nameServers)
}

func (snapshot fakeDNSResolverSnapshot) Resolve(context.Context, string) ([]netip.Addr, error) {
	return slices.Clone(snapshot.resolved), nil
}

type fakeTailnetControl struct {
	mutex        sync.Mutex
	state        domain.TailnetState
	writes       int
	ignoreWrites bool
	recorder     *operationRecorder
}

func (control *fakeTailnetControl) ReadState(context.Context) (domain.TailnetState, error) {
	control.mutex.Lock()
	defer control.mutex.Unlock()
	state := control.state
	state.SelfAddresses = slices.Clone(state.SelfAddresses)
	state.Preferences.AdvertiseRoutes = slices.Clone(state.Preferences.AdvertiseRoutes)
	state.Control.ApprovedRoutes = slices.Clone(state.Control.ApprovedRoutes)
	return state, nil
}

func (control *fakeTailnetControl) WritePreferences(_ context.Context, preferences domain.TailnetPreferences) error {
	control.mutex.Lock()
	defer control.mutex.Unlock()
	control.writes++
	switch {
	case len(preferences.AdvertiseRoutes) == 0:
		control.recorder.add("advertisements-cleared")
	case control.state.Preferences.HasExitDefaultRoutes() && !preferences.AdvertisesExitNode():
		control.recorder.add("exit-node-withdrawn")
	default:
		control.recorder.add("advertisements-published")
	}
	if !control.ignoreWrites {
		control.state.Preferences = domain.TailnetPreferences{AdvertiseRoutes: slices.Clone(preferences.AdvertiseRoutes)}
	}
	return nil
}

func (control *fakeTailnetControl) resetWrites() {
	control.mutex.Lock()
	defer control.mutex.Unlock()
	control.writes = 0
}

func (control *fakeTailnetControl) writeCalls() int {
	control.mutex.Lock()
	defer control.mutex.Unlock()
	return control.writes
}

func (control *fakeTailnetControl) setApprovedRoutes(routes []netip.Prefix) {
	control.mutex.Lock()
	defer control.mutex.Unlock()
	control.state.Control.ApprovedRoutes = slices.Clone(routes)
	control.state.Control.ObservedAt = time.Now()
}

func (control *fakeTailnetControl) setPreferences(preferences domain.TailnetPreferences) {
	control.mutex.Lock()
	defer control.mutex.Unlock()
	control.state.Preferences = domain.TailnetPreferences{AdvertiseRoutes: slices.Clone(preferences.AdvertiseRoutes)}
}

func (control *fakeTailnetControl) currentPreferences() domain.TailnetPreferences {
	control.mutex.Lock()
	defer control.mutex.Unlock()
	return domain.TailnetPreferences{AdvertiseRoutes: slices.Clone(control.state.Preferences.AdvertiseRoutes)}
}

type fakeInternetCapability struct {
	mutex    sync.Mutex
	snapshot domain.InternetCapabilitySnapshot
	err      error
}

func (capability *fakeInternetCapability) Observe(context.Context, domain.LinkIdentity) (domain.InternetCapabilitySnapshot, error) {
	capability.mutex.Lock()
	defer capability.mutex.Unlock()
	return capability.snapshot, capability.err
}

func (capability *fakeInternetCapability) set(snapshot domain.InternetCapabilitySnapshot) {
	capability.mutex.Lock()
	defer capability.mutex.Unlock()
	capability.snapshot = snapshot
}

func cloneRoutingState(state domain.RoutingState) domain.RoutingState {
	return domain.RoutingState{Routes: slices.Clone(state.Routes), Rules: slices.Clone(state.Rules)}
}

func cloneRoutingChanges(changes domain.RoutingChanges) domain.RoutingChanges {
	return domain.RoutingChanges{
		UpsertRoutes: slices.Clone(changes.UpsertRoutes),
		DeleteRules:  slices.Clone(changes.DeleteRules),
		AddRules:     slices.Clone(changes.AddRules),
		DeleteRoutes: slices.Clone(changes.DeleteRoutes),
	}
}

func applyRoutingChanges(state domain.RoutingState, changes domain.RoutingChanges) domain.RoutingState {
	for _, route := range changes.UpsertRoutes {
		state.Routes = removeRouteIdentity(state.Routes, route)
		state.Routes = append(state.Routes, route)
	}
	for _, rule := range changes.DeleteRules {
		state.Rules = slices.DeleteFunc(state.Rules, func(candidate domain.Rule) bool {
			return candidate.Family == rule.Family && candidate.Priority == rule.Priority
		})
	}
	for _, rule := range changes.AddRules {
		state.Rules = slices.DeleteFunc(state.Rules, func(candidate domain.Rule) bool {
			return candidate.Family == rule.Family && candidate.Priority == rule.Priority
		})
		state.Rules = append(state.Rules, rule)
	}
	for _, route := range changes.DeleteRoutes {
		state.Routes = removeRouteIdentity(state.Routes, route)
	}
	return state
}

func removeRouteIdentity(routes []domain.Route, target domain.Route) []domain.Route {
	return slices.DeleteFunc(routes, func(candidate domain.Route) bool {
		return candidate.Family == target.Family && candidate.Disposition == target.Disposition && candidate.Table == target.Table && candidate.Prefix == target.Prefix && candidate.Metric == target.Metric
	})
}
