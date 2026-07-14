package application

import (
	"context"
	"errors"
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
	state := buildDesiredRouting(configuration, snapshot)
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

func TestControllerClearsRestoredAdvertisementsBeforeOpeningDataPlane(t *testing.T) {
	fixture := newControllerFixture(t)
	desiredPreferences := domain.NewTailnetPreferences(fixture.configuration.Tailnet.AdvertiseRoutes, true)
	fixture.tailnet.state.Preferences = desiredPreferences

	if err := fixture.controller.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.recorder.reset()
	report, err := fixture.controller.Reconcile(context.Background())
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

func TestControllerNoDriftProducesStrictlyZeroWrites(t *testing.T) {
	fixture := newControllerFixture(t)
	if err := fixture.controller.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.controller.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.routing.resetWrites()
	fixture.packetFilter.resetWrites()
	fixture.tailnet.resetWrites()
	fixture.recorder.reset()

	report, err := fixture.controller.Reconcile(context.Background())
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

func TestControllerDisabledLocalEgressProducesCanonicalPolicy(t *testing.T) {
	fixture := newControllerFixture(t)
	fixture.configuration.PacketFilter.LocalEgress.Enabled = false
	fixture.configuration.PacketFilter.LocalEgress.Domains = nil
	fixture.controller.configuration = fixture.configuration
	if err := fixture.configuration.Validate(); err != nil {
		t.Fatalf("disabled local-egress configuration was rejected: %v", err)
	}
	if err := fixture.controller.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.controller.Reconcile(context.Background()); err != nil {
		t.Fatalf("disabled local-egress reconciliation failed: %v", err)
	}

	local := fixture.packetFilter.lastPolicy().LocalEgress
	if local.Enabled || len(local.IPv4) != 0 || len(local.IPv6) != 0 || len(local.Protocols) != 0 || len(local.Ports) != 0 || local.Mark != 0 {
		t.Fatalf("disabled local-egress policy is not canonical: %#v", local)
	}
}

func TestControllerReportsRouteApprovalLossAndRecoveryWithoutPreferenceWrites(t *testing.T) {
	for _, missing := range []netip.Prefix{
		netip.MustParsePrefix("10.0.8.0/24"),
		domain.DefaultPrefix(domain.IPv4),
		domain.DefaultPrefix(domain.IPv6),
	} {
		t.Run(missing.String(), func(t *testing.T) {
			fixture := newControllerFixture(t)
			if err := fixture.controller.Prepare(context.Background()); err != nil {
				t.Fatal(err)
			}
			if report, err := fixture.controller.Reconcile(context.Background()); err != nil || len(report.Conditions) != 0 {
				t.Fatalf("initial approved reconciliation failed: report=%#v err=%v", report, err)
			}
			fixture.tailnet.resetWrites()
			fixture.tailnet.setApprovedRoutes(slices.DeleteFunc(
				domain.NewTailnetPreferences(fixture.configuration.Tailnet.AdvertiseRoutes, true).AdvertiseRoutes,
				func(prefix netip.Prefix) bool { return prefix == missing },
			))

			report, err := fixture.controller.Reconcile(context.Background())
			if err != nil {
				t.Fatalf("explicit non-approval became a technical error: %v", err)
			}
			wantCondition := domain.ReconcileCondition{Kind: domain.ConditionRouteNotApproved, Family: domain.FamilyOfPrefix(missing), Prefix: missing}
			if !slices.Equal(report.Conditions, []domain.ReconcileCondition{wantCondition}) || !report.ApprovalObserved {
				t.Fatalf("missing approval was not reported exactly: %#v", report)
			}
			if fixture.tailnet.writeCalls() != 0 || report.TailnetWrites != 0 {
				t.Fatalf("explicit non-approval rewrote preferences: calls=%d report=%#v", fixture.tailnet.writeCalls(), report)
			}

			fixture.tailnet.setApprovedRoutes(domain.NewTailnetPreferences(fixture.configuration.Tailnet.AdvertiseRoutes, true).AdvertiseRoutes)
			recovered, err := fixture.controller.Reconcile(context.Background())
			if err != nil || len(recovered.Conditions) != 0 || !recovered.ApprovalObserved {
				t.Fatalf("approval recovery did not become healthy: report=%#v err=%v", recovered, err)
			}
			if fixture.tailnet.writeCalls() != 0 || recovered.TailnetWrites != 0 {
				t.Fatalf("approval recovery rewrote preferences: calls=%d report=%#v", fixture.tailnet.writeCalls(), recovered)
			}
		})
	}
}

func TestControllerCapabilityLossAndRecoveryUseSinglePreferenceTransactions(t *testing.T) {
	fixture := newControllerFixture(t)
	if err := fixture.controller.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.controller.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.tailnet.resetWrites()
	fixture.routing.resetWrites()
	fixture.packetFilter.resetWrites()

	now := time.Now()
	link := fixture.discovery.snapshot.ProxyTunnelLink
	fresh := domain.InternetFamilyCapability{Initialized: true, Available: true, ObservedAt: now, ValidUntil: now.Add(time.Minute)}
	fixture.capability.set(domain.InternetCapabilitySnapshot{
		ProxyLink: link,
		IPv4:      fresh,
		IPv6:      domain.InternetFamilyCapability{Initialized: true, ObservedAt: now},
	})
	lost, err := fixture.controller.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	wantCondition := domain.ReconcileCondition{Kind: domain.ConditionInternetCapabilityUnavailable, Family: domain.IPv6}
	if !slices.Contains(lost.Conditions, wantCondition) || lost.TailnetWrites != 1 || fixture.tailnet.writeCalls() != 1 {
		t.Fatalf("capability loss did not perform one bounded withdrawal: %#v", lost)
	}
	if fixture.routing.writeCalls() != 0 || fixture.packetFilter.writeCalls() != 0 {
		t.Fatalf("capability loss changed the data plane: routing=%d nftables=%d", fixture.routing.writeCalls(), fixture.packetFilter.writeCalls())
	}
	wantSubnets := domain.NewTailnetPreferences(fixture.configuration.Tailnet.AdvertiseRoutes, false)
	if got := fixture.tailnet.currentPreferences(); !got.Equal(wantSubnets) {
		t.Fatalf("capability loss removed subnet intent or retained Exit routes: %#v", got)
	}

	fixture.tailnet.resetWrites()
	fixture.recorder.reset()
	fixture.routing.recordReads = true
	fixture.packetFilter.recordReads = true
	fixture.capability.set(domain.InternetCapabilitySnapshot{ProxyLink: link, IPv4: fresh, IPv6: fresh})
	recovered, err := fixture.controller.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered.Conditions) != 0 || recovered.TailnetWrites != 1 || fixture.tailnet.writeCalls() != 1 {
		t.Fatalf("capability recovery did not perform one bounded publication: %#v", recovered)
	}
	operations := fixture.recorder.snapshot()
	published := slices.Index(operations, "advertisements-published")
	lastRoutingRead := lastValueIndex(operations, "routing-read")
	lastPacketRead := lastValueIndex(operations, "nftables-read")
	if published < 0 || lastRoutingRead < 0 || lastPacketRead < 0 || published < lastRoutingRead || published < lastPacketRead {
		t.Fatalf("Exit routes were published before final data-plane readback: %v", operations)
	}
	wantExit := domain.NewTailnetPreferences(fixture.configuration.Tailnet.AdvertiseRoutes, true)
	if got := fixture.tailnet.currentPreferences(); !got.Equal(wantExit) {
		t.Fatalf("capability recovery did not restore both Exit defaults: %#v", got)
	}
}

func TestControllerWithdrawsExitOnceForEveryUnusableCapabilityState(t *testing.T) {
	tests := []struct {
		name     string
		snapshot func(domain.LinkIdentity, time.Time) domain.InternetCapabilitySnapshot
	}{
		{
			name: "initializing",
			snapshot: func(link domain.LinkIdentity, _ time.Time) domain.InternetCapabilitySnapshot {
				return domain.InternetCapabilitySnapshot{ProxyLink: link}
			},
		},
		{
			name: "ipv4 unavailable",
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
			name: "ipv6 unavailable",
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
			name: "stale",
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
			fixture := newControllerFixture(t)
			if err := fixture.controller.Prepare(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.controller.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			fixture.tailnet.resetWrites()
			fixture.capability.set(test.snapshot(fixture.discovery.snapshot.ProxyTunnelLink, time.Now()))

			withdrawn, err := fixture.controller.Reconcile(context.Background())
			if err != nil {
				t.Fatalf("operational capability state became a technical error: %v", err)
			}
			if len(withdrawn.Conditions) == 0 || withdrawn.TailnetWrites != 1 || fixture.tailnet.writeCalls() != 1 {
				t.Fatalf("capability state did not perform one bounded withdrawal: %#v", withdrawn)
			}
			wantSubnets := domain.NewTailnetPreferences(fixture.configuration.Tailnet.AdvertiseRoutes, false)
			if got := fixture.tailnet.currentPreferences(); !got.Equal(wantSubnets) {
				t.Fatalf("capability state changed subnet intent: %#v", got)
			}

			fixture.tailnet.resetWrites()
			steady, err := fixture.controller.Reconcile(context.Background())
			if err != nil || steady.TailnetWrites != 0 || fixture.tailnet.writeCalls() != 0 {
				t.Fatalf("steady capability loss repeated preference writes: report=%#v calls=%d err=%v", steady, fixture.tailnet.writeCalls(), err)
			}
		})
	}
}

func TestControllerRejectsUnavailableTailnetControlObservations(t *testing.T) {
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
			fixture := newControllerFixture(t)
			test.mutate(&fixture.tailnet.state.Control)
			if _, err := fixture.controller.Reconcile(context.Background()); err == nil || !strings.Contains(err.Error(), test.fragment) {
				t.Fatalf("expected %q error, got %v", test.fragment, err)
			}
			if fixture.tailnet.writeCalls() != 0 {
				t.Fatal("invalid control observation caused a preference write")
			}
		})
	}
}

func TestControllerUsesOneResolverSnapshotPerReconcile(t *testing.T) {
	fixture := newControllerFixture(t)
	if err := fixture.controller.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.resolver.snapshots = 0
	if _, err := fixture.controller.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fixture.resolver.snapshots != 1 {
		t.Fatalf("reconcile read %d resolver snapshots, want exactly one", fixture.resolver.snapshots)
	}
}

func TestControllerRouteChangeIsQuarantinedBeforeApplyingDifferences(t *testing.T) {
	fixture := newControllerFixture(t)
	if err := fixture.controller.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.controller.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.routing.resetWrites()
	fixture.packetFilter.resetWrites()
	fixture.tailnet.resetWrites()
	fixture.recorder.reset()

	fixture.discovery.snapshot.AdvertisedRoutes[0].Link = domain.LinkIdentity{Index: 14, Name: "internal-next"}
	fixture.discovery.snapshot.DNSEgressPaths[0].Link = domain.LinkIdentity{Index: 15, Name: "dns-v4-next"}
	report, err := fixture.controller.Reconcile(context.Background())
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

func TestControllerPrepareRoutesLocalControlTrafficBeforeManagedProcessStartup(t *testing.T) {
	fixture := newControllerFixture(t)
	if err := fixture.controller.Prepare(context.Background()); err != nil {
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

func TestControllerPrepareClosesForwardingBeforeRoutingMutations(t *testing.T) {
	fixture := newControllerFixture(t)
	if err := fixture.controller.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	operations := fixture.recorder.snapshot()
	quarantineIndex := slices.Index(operations, "nftables-closed")
	routingIndex := slices.Index(operations, "routing")
	if quarantineIndex < 0 || routingIndex < 0 || quarantineIndex > routingIndex {
		t.Fatalf("startup routing changed before forwarding quarantine: %v", operations)
	}
}

func TestControllerPrepareRejectsInvalidProxyTunnelIdentity(t *testing.T) {
	fixture := newControllerFixture(t)
	fixture.discovery.snapshot.ProxyTunnelLink = domain.LinkIdentity{Index: 3, Name: "invalid:name"}
	if err := fixture.controller.Prepare(context.Background()); err == nil || !strings.Contains(err.Error(), "validate proxy tunnel") {
		t.Fatalf("invalid startup proxy tunnel identity was accepted: %v", err)
	}
}

func TestControllerLiveFailClosedRetainsVerifiedLocalControlEgressDuringTailnetBootstrap(t *testing.T) {
	fixture := newControllerFixture(t)
	if err := fixture.controller.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.recorder.reset()
	fixture.tailnet.mutex.Lock()
	fixture.tailnet.state.Control.InNetworkMap = false
	fixture.tailnet.mutex.Unlock()

	if _, err := fixture.controller.Reconcile(context.Background()); err == nil || !strings.Contains(err.Error(), "absent from the current network map") {
		t.Fatalf("unavailable bootstrap state was accepted: %v", err)
	}
	report, err := fixture.controller.FailClosed(context.Background())
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
	if recovered, err := fixture.controller.Reconcile(context.Background()); err != nil || len(recovered.Conditions) != 0 {
		t.Fatalf("Tailnet bootstrap did not recover through the retained control path: report=%#v err=%v", recovered, err)
	}
}

func TestControllerLiveFailClosedBlackholesUnverifiedLocalControlEgress(t *testing.T) {
	tests := []struct {
		name              string
		breakRecoveryPath func(*controllerFixture)
	}{
		{name: "kernel", breakRecoveryPath: func(fixture *controllerFixture) {
			fixture.kernel.err = errors.New("kernel prerequisites unavailable")
		}},
		{name: "resolver", breakRecoveryPath: func(fixture *controllerFixture) {
			fixture.resolver.err = errors.New("resolver snapshot unavailable")
		}},
		{name: "proxy tunnel", breakRecoveryPath: func(fixture *controllerFixture) {
			fixture.discovery.err = errors.New("proxy tunnel is ambiguous")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newControllerFixture(t)
			if err := fixture.controller.Prepare(context.Background()); err != nil {
				t.Fatal(err)
			}
			test.breakRecoveryPath(fixture)

			report, err := fixture.controller.FailClosed(context.Background())
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

func TestControllerLiveFailClosedRestoresStrictRoutingAfterFinalKernelFailure(t *testing.T) {
	fixture := newControllerFixture(t)
	if err := fixture.controller.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.kernel.failOnCheck(2, errors.New("kernel prerequisites drifted after recovery convergence"))

	report, err := fixture.controller.FailClosed(context.Background())
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

func TestControllerShutdownAlwaysBlackholesLocalControlEgress(t *testing.T) {
	fixture := newControllerFixture(t)
	if err := fixture.controller.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.kernel.err = errors.New("kernel recovery check must not run during shutdown")
	fixture.resolver.err = errors.New("resolver recovery check must not run during shutdown")
	fixture.discovery.err = errors.New("proxy recovery check must not run during shutdown")
	if err := fixture.controller.Shutdown(context.Background()); err != nil {
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

func TestControllerDiscoveryFailureClosesGateBeforeClearingAdvertisements(t *testing.T) {
	fixture := newControllerFixture(t)
	if err := fixture.controller.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.controller.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.recorder.reset()
	fixture.discovery.err = errors.New("kernel route is no longer deterministic")
	if _, err := fixture.controller.Reconcile(context.Background()); err == nil {
		t.Fatal("discovery failure was accepted")
	}
	if _, err := fixture.controller.FailClosed(context.Background()); err == nil || !strings.Contains(err.Error(), "verify local control-plane recovery path") {
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

func TestControllerRejectsForwardingDrift(t *testing.T) {
	fixture := newControllerFixture(t)
	if err := fixture.controller.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.controller.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	fixture.kernel.mutex.Lock()
	fixture.kernel.err = errors.New("IPv6 forwarding is disabled")
	fixture.kernel.mutex.Unlock()
	if _, err := fixture.controller.Reconcile(context.Background()); err == nil || !strings.Contains(err.Error(), "IPv6 forwarding") {
		t.Fatalf("forwarding drift was accepted: %v", err)
	}
}

func TestControllerRejectsUnverifiedTailnetPreferenceWrite(t *testing.T) {
	fixture := newControllerFixture(t)
	fixture.tailnet.ignoreWrites = true
	if err := fixture.controller.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err := fixture.controller.Reconcile(context.Background())
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
	if status.RecordSuccess(now, epoch, nil) {
		t.Fatal("superseded reconciliation was marked ready")
	}
	if status.HealthSnapshot().Ready {
		t.Fatal("readiness ignored a newer network event")
	}
	nextEpoch := status.BeginReconcile()
	if !status.RecordSuccess(now, nextEpoch, nil) || !status.HealthSnapshot().Ready {
		t.Fatal("latest successful reconciliation did not become ready")
	}
}

func TestStatusRecordsOperationalConditionsAsDegradedWithoutAnError(t *testing.T) {
	status := NewStatus(time.Minute)
	now := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	status.now = func() time.Time { return now }
	condition := domain.ReconcileCondition{
		Kind: domain.ConditionRouteNotApproved, Family: domain.IPv4, Prefix: netip.MustParsePrefix("10.0.8.0/24"),
	}
	if status.RecordSuccess(now, status.BeginReconcile(), []domain.ReconcileCondition{condition}) {
		t.Fatal("reconciliation with an operational condition was marked ready")
	}
	snapshot := status.HealthSnapshot()
	if snapshot.Ready || snapshot.Phase != domain.RuntimeDegraded || snapshot.LastError != "" || !slices.Equal(snapshot.Conditions, []domain.ReconcileCondition{condition}) {
		t.Fatalf("operational degradation was not preserved: %#v", snapshot)
	}
}

type controllerFixture struct {
	configuration domain.Configuration
	controller    *Controller
	discovery     *fakeDiscovery
	routing       *fakeRoutingStore
	packetFilter  *fakePacketFilterStore
	resolver      *fakeDNSResolver
	tailnet       *fakeTailnetControl
	capability    *fakeInternetCapability
	kernel        *fakeKernelPrerequisites
	recorder      *operationRecorder
}

func newControllerFixture(t *testing.T) *controllerFixture {
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
			Preferences:   domain.NewTailnetPreferences(nil, false),
			Control: domain.TailnetControlObservation{
				SelfPresent: true, InNetworkMap: true, Online: true, AllowedIPsAvailable: true,
				ApprovedRoutes: domain.NewTailnetPreferences(configuration.Tailnet.AdvertiseRoutes, true).AdvertiseRoutes,
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
	controller, err := NewController(configuration, ControllerDependencies{
		Kernel: kernel, ProxyTunnel: discovery, Network: discovery, Routing: routing, PacketFilter: packetFilter, Resolver: resolver, Tailnet: tailnet,
		InternetCapability: capability,
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &controllerFixture{
		configuration: configuration, controller: controller, discovery: discovery, routing: routing,
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

func findDNSTarget(t *testing.T, policy domain.PacketFilterPolicy, address netip.Addr) domain.DNSSNATTarget {
	t.Helper()
	for _, target := range policy.DNSTargets {
		if target.Address == address {
			return target
		}
	}
	t.Fatalf("DNS target %s not found", address)
	return domain.DNSSNATTarget{}
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
	mutex       sync.Mutex
	state       domain.RoutingState
	writes      int
	applyCount  int
	recorder    *operationRecorder
	recordReads bool
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
	store.recorder.add("routing")
	store.state = applyRoutingChanges(store.state, changes)
	writes := len(changes.UpsertRoutes) + len(changes.DeleteRules) + len(changes.AddRules) + len(changes.DeleteRoutes)
	store.writes += writes
	return writes, nil
}

func (store *fakeRoutingStore) resetWrites() {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	store.writes = 0
	store.applyCount = 0
}

func (store *fakeRoutingStore) writeCalls() int {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	return store.applyCount
}

func (store *fakeRoutingStore) currentState() domain.RoutingState {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	return cloneRoutingState(store.state)
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
	if len(preferences.AdvertiseRoutes) == 0 {
		control.recorder.add("advertisements-cleared")
	} else {
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
