//go:build linux

package netlink

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	vnetlink "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestDiscoverResolvesEveryDNSAddressToItsOwnOutputLink(t *testing.T) {
	kernel := testKernel()
	adapter := &Adapter{kernel: kernel}
	request := testDiscoveryRequest()
	snapshot, err := adapter.Discover(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.DNSEgressPaths) != 2 {
		t.Fatalf("unexpected DNS path count: %d", len(snapshot.DNSEgressPaths))
	}
	if snapshot.DNSEgressPaths[0].Link.Name != "dns-path-v4" || snapshot.DNSEgressPaths[1].Link.Name != "dns-path-v6" {
		t.Fatalf("address-family-specific DNS links were lost: %#v", snapshot.DNSEgressPaths)
	}
	if !kernel.fibMatchObserved {
		t.Fatal("route discovery did not request kernel FIB-match semantics")
	}
}

func TestResolveRouteSupportsDirectGatewayAndOnLinkRoutes(t *testing.T) {
	tests := []struct {
		name   string
		target string
		route  vnetlink.Route
		assert func(*testing.T, domain.RouteResolution)
	}{
		{
			name:   "IPv4 direct",
			target: "10.0.8.1",
			route:  testRoute("10.0.8.0/24", 4, "", vnetlink.SCOPE_LINK, 0),
			assert: func(t *testing.T, resolution domain.RouteResolution) {
				if resolution.Gateway.IsValid() || resolution.OnLink {
					t.Fatalf("direct route gained gateway semantics: %#v", resolution)
				}
			},
		},
		{
			name:   "IPv6 direct universe scope",
			target: "fd00:8::1",
			route:  testRoute("fd00:8::/64", 6, "", vnetlink.SCOPE_UNIVERSE, 0),
			assert: func(t *testing.T, resolution domain.RouteResolution) {
				if resolution.Gateway.IsValid() || resolution.OnLink {
					t.Fatalf("IPv6 direct route gained gateway semantics: %#v", resolution)
				}
			},
		},
		{
			name:   "gateway",
			target: "10.0.8.1",
			route:  testRoute("10.0.8.0/24", 4, "10.42.0.1", vnetlink.SCOPE_UNIVERSE, 0),
			assert: func(t *testing.T, resolution domain.RouteResolution) {
				if resolution.Gateway.String() != "10.42.0.1" || resolution.OnLink {
					t.Fatalf("gateway route was not preserved: %#v", resolution)
				}
			},
		},
		{
			name:   "on-link gateway",
			target: "10.0.8.1",
			route:  testRoute("10.0.8.0/24", 4, "10.42.0.1", vnetlink.SCOPE_UNIVERSE, unix.RTNH_F_ONLINK),
			assert: func(t *testing.T, resolution domain.RouteResolution) {
				if !resolution.OnLink {
					t.Fatalf("on-link flag was not preserved: %#v", resolution)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kernel := testKernel()
			kernel.routesByTarget[test.target] = []vnetlink.Route{test.route}
			resolution, err := (&Adapter{kernel: kernel}).resolveRoute(context.Background(), netip.MustParseAddr(test.target))
			if err != nil {
				t.Fatal(err)
			}
			test.assert(t, resolution)
		})
	}
}

func TestManagedDirectRouteScopeUsesAddressFamilySemantics(t *testing.T) {
	adapter := &Adapter{kernel: testKernel()}
	for _, test := range []struct {
		family domain.AddressFamily
		link   domain.LinkIdentity
		want   vnetlink.Scope
	}{
		{family: domain.IPv4, link: domain.LinkIdentity{Index: 5, Name: "dns-path-v4"}, want: vnetlink.SCOPE_LINK},
		{family: domain.IPv6, link: domain.LinkIdentity{Index: 6, Name: "dns-path-v6"}, want: vnetlink.SCOPE_UNIVERSE},
	} {
		route, err := adapter.routeToNetlink(domain.Route{
			Family: test.family, Disposition: domain.RouteUnicast, Table: 100,
			Prefix: domain.DefaultPrefix(test.family), Link: test.link, Metric: 100,
		})
		if err != nil {
			t.Fatal(err)
		}
		if route.Scope != test.want {
			t.Fatalf("family %d direct route scope=%d, want %d", test.family, route.Scope, test.want)
		}
		if route.Priority != 100 {
			t.Fatalf("family %d direct route metric=%d, want 100", test.family, route.Priority)
		}
		if route.Dst == nil || prefixFromIPNet(route.Dst) != domain.DefaultPrefix(test.family) {
			t.Fatalf("family %d default route was not encoded explicitly: %#v", test.family, route.Dst)
		}
	}
}

func TestRouteObservationPreservesTheKernelMetric(t *testing.T) {
	kernel := testKernel()
	adapter := &Adapter{kernel: kernel}
	observed, err := adapter.routeFromNetlink(domain.IPv6, vnetlink.Route{
		Family: vnetlink.FAMILY_V6, Table: 100, Protocol: agentRouteProtocol,
		Type: unix.RTN_UNICAST, Scope: vnetlink.SCOPE_UNIVERSE,
		Dst:       ipNetFromPrefix(domain.DefaultPrefix(domain.IPv6)),
		LinkIndex: 3, Priority: 1_024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if observed.Metric != 1_024 {
		t.Fatalf("kernel route metric was not preserved: %#v", observed)
	}
}

func TestIPv6BlackholeObservationNormalizesOnlyAHealthyLoopbackLink(t *testing.T) {
	kernel := testKernel()
	adapter := &Adapter{kernel: kernel}
	route := vnetlink.Route{
		Family: vnetlink.FAMILY_V6, Table: 100, Protocol: agentRouteProtocol,
		Type: unix.RTN_BLACKHOLE, Scope: vnetlink.SCOPE_UNIVERSE,
		Dst: ipNetFromPrefix(domain.DefaultPrefix(domain.IPv6)), LinkIndex: 1, Priority: 32_760,
	}
	observed, err := adapter.routeFromNetlink(domain.IPv6, route)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Link != (domain.LinkIdentity{}) || observed.UnexpectedAttributes {
		t.Fatalf("kernel-derived loopback link was not canonically removed: %#v", observed)
	}

	for _, test := range []struct {
		name      string
		family    domain.AddressFamily
		linkIndex int
		flags     int
		fragment  string
	}{
		{name: "non-loopback", family: domain.IPv6, linkIndex: 4, fragment: "non-loopback"},
		{name: "missing link", family: domain.IPv6, linkIndex: 99, fragment: "resolve managed route link"},
		{name: "IPv4 loopback", family: domain.IPv4, linkIndex: 1, fragment: "refuse to normalize"},
		{name: "unexpected on-link flag", family: domain.IPv6, linkIndex: 1, flags: unix.RTNH_F_ONLINK, fragment: "refuse to normalize"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := route
			candidate.Family = linuxFamily(test.family)
			candidate.Dst = ipNetFromPrefix(domain.DefaultPrefix(test.family))
			candidate.LinkIndex = test.linkIndex
			candidate.Flags = test.flags
			_, err := adapter.routeFromNetlink(test.family, candidate)
			if err == nil || !strings.Contains(err.Error(), test.fragment) {
				t.Fatalf("expected %q error, got %v", test.fragment, err)
			}
		})
	}
}

func TestUnicastObservationPreservesStrictLinkIdentity(t *testing.T) {
	adapter := &Adapter{kernel: testKernel()}
	observed, err := adapter.routeFromNetlink(domain.IPv6, vnetlink.Route{
		Family: vnetlink.FAMILY_V6, Table: 100, Protocol: agentRouteProtocol,
		Type: unix.RTN_UNICAST, Scope: vnetlink.SCOPE_UNIVERSE,
		Dst: ipNetFromPrefix(netip.MustParsePrefix("2001:db8::/64")), LinkIndex: 3, Priority: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if observed.Link != (domain.LinkIdentity{Index: 3, Name: "proxy-path"}) {
		t.Fatalf("unicast link identity was not preserved: %#v", observed)
	}
	if _, err := adapter.routeFromNetlink(domain.IPv6, vnetlink.Route{
		Family: vnetlink.FAMILY_V6, Table: 100, Protocol: agentRouteProtocol,
		Type: unix.RTN_UNICAST, Scope: vnetlink.SCOPE_UNIVERSE,
		Dst: ipNetFromPrefix(netip.MustParsePrefix("2001:db8::/64")), LinkIndex: 99, Priority: 100,
	}); err == nil {
		t.Fatal("unresolvable unicast link was accepted")
	}
	if _, err := adapter.routeFromNetlink(domain.IPv6, vnetlink.Route{
		Family: vnetlink.FAMILY_V6, Table: 100, Protocol: agentRouteProtocol,
		Type: unix.RTN_UNICAST, Scope: vnetlink.SCOPE_UNIVERSE,
		Dst: ipNetFromPrefix(netip.MustParsePrefix("2001:db8::/64")), Priority: 100,
	}); err == nil {
		t.Fatal("unicast route without a link was accepted")
	}
}

func TestDefaultBlackholeRouteHasAnExplicitDestination(t *testing.T) {
	adapter := &Adapter{kernel: testKernel()}
	for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
		route, err := adapter.routeToNetlink(domain.Route{
			Family: family, Disposition: domain.RouteBlackhole, Table: 100,
			Prefix: domain.DefaultPrefix(family), Metric: 32_760,
		})
		if err != nil {
			t.Fatal(err)
		}
		if route.Dst == nil || prefixFromIPNet(route.Dst) != domain.DefaultPrefix(family) {
			t.Fatalf("family %d default blackhole was not encoded explicitly: %#v", family, route.Dst)
		}
	}
}

func TestResolveRouteFailsClosedForUnsafeKernelResults(t *testing.T) {
	base := testRoute("10.0.8.0/24", 4, "10.42.0.1", vnetlink.SCOPE_UNIVERSE, 0)
	tests := []struct {
		name   string
		routes []vnetlink.Route
		setup  func(*fakeKernel)
	}{
		{name: "no route", routes: nil},
		{name: "ambiguous candidates", routes: []vnetlink.Route{base, base}},
		{name: "blackhole", routes: []vnetlink.Route{withRouteType(base, unix.RTN_BLACKHOLE)}},
		{name: "unreachable", routes: []vnetlink.Route{withRouteType(base, unix.RTN_UNREACHABLE)}},
		{name: "prohibit", routes: []vnetlink.Route{withRouteType(base, unix.RTN_PROHIBIT)}},
		{name: "throw", routes: []vnetlink.Route{withRouteType(base, unix.RTN_THROW)}},
		{name: "multipath", routes: []vnetlink.Route{withMultipath(base)}},
		{name: "missing link index", routes: []vnetlink.Route{withLinkIndex(base, 0)}},
		{name: "interface disappeared", routes: []vnetlink.Route{base}, setup: func(kernel *fakeKernel) { delete(kernel.links, 4) }},
		{name: "interface down", routes: []vnetlink.Route{base}, setup: func(kernel *fakeKernel) { kernel.links[4].Attrs().Flags = 0 }},
		{name: "unsupported attributes", routes: []vnetlink.Route{withRouteFlags(base, unix.RTNH_F_PERVASIVE)}},
		{name: "locked MTU", routes: []vnetlink.Route{withRouteMTULock(base)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kernel := testKernel()
			kernel.routesByTarget["10.0.8.1"] = test.routes
			if test.setup != nil {
				test.setup(kernel)
			}
			if _, err := (&Adapter{kernel: kernel}).resolveRoute(context.Background(), netip.MustParseAddr("10.0.8.1")); err == nil {
				t.Fatal("unsafe route result was accepted")
			}
		})
	}
}

func TestResolveRouteAcceptsKernelMTUDiscoveryMetric(t *testing.T) {
	kernel := testKernel()
	kernel.routesByTarget["10.0.8.1"] = []vnetlink.Route{withRouteMTU(testRoute("10.0.8.0/24", 4, "10.42.0.1", vnetlink.SCOPE_UNIVERSE, 0), 1450)}
	resolution, err := (&Adapter{kernel: kernel}).resolveRoute(context.Background(), netip.MustParseAddr("10.0.8.1"))
	if err != nil {
		t.Fatal(err)
	}
	if resolution.Link != (domain.LinkIdentity{Index: 4, Name: "internal-path"}) || resolution.Gateway != netip.MustParseAddr("10.42.0.1") {
		t.Fatalf("route projection changed while accepting MTU: %#v", resolution)
	}
}

func TestManagedRouteObservationStillMarksMTUUnexpected(t *testing.T) {
	adapter := &Adapter{kernel: testKernel()}
	observed, err := adapter.routeFromNetlink(domain.IPv4, withRouteMTU(vnetlink.Route{
		Family: vnetlink.FAMILY_V4, Table: 100, Protocol: agentRouteProtocol,
		Type: unix.RTN_UNICAST, Scope: vnetlink.SCOPE_UNIVERSE,
		Dst: ipNetFromPrefix(netip.MustParsePrefix("10.0.8.0/24")), LinkIndex: 4, Priority: 100,
	}, 1450))
	if err != nil {
		t.Fatal(err)
	}
	if !observed.UnexpectedAttributes {
		t.Fatalf("managed route MTU was not treated as unexpected: %#v", observed)
	}
}

func TestDiscoverRejectsMoreSpecificRouteInsideAdvertisedPrefix(t *testing.T) {
	kernel := testKernel()
	kernel.routesByTable[254] = append(kernel.routesByTable[254], testRoute("10.0.8.128/25", 5, "10.42.0.2", vnetlink.SCOPE_UNIVERSE, 0))
	_, err := (&Adapter{kernel: kernel}).Discover(context.Background(), testDiscoveryRequest())
	if err == nil || !strings.Contains(err.Error(), "more-specific route") {
		t.Fatalf("non-uniform advertised prefix was accepted: %v", err)
	}
}

func TestDiscoverRequiresActualTUNLinksForManagedTunnelAddresses(t *testing.T) {
	t.Run("link type", func(t *testing.T) {
		kernel := testKernel()
		kernel.links[3] = &vnetlink.Device{LinkAttrs: *kernel.links[3].Attrs()}
		_, err := (&Adapter{kernel: kernel}).Discover(context.Background(), testDiscoveryRequest())
		if err == nil || !strings.Contains(err.Error(), "exactly one is required") {
			t.Fatalf("non-TUN proxy link was accepted: %v", err)
		}
	})
	t.Run("address prefix length", func(t *testing.T) {
		kernel := testKernel()
		kernel.addresses[3] = []vnetlink.Addr{testAddress("198.18.0.1/32"), testAddress("fd88:baba:fafa::1/128")}
		_, err := (&Adapter{kernel: kernel}).Discover(context.Background(), testDiscoveryRequest())
		if err == nil || !strings.Contains(err.Error(), "exactly one is required") {
			t.Fatalf("proxy TUN with mismatched address prefixes was accepted: %v", err)
		}
	})
}

func TestReadRoutingRejectsForeignObjectsInsideOwnedIdentities(t *testing.T) {
	ownership := domain.RoutingOwnership{Tables: []int{100}, RulePriorities: []int{99}}
	t.Run("route protocol", func(t *testing.T) {
		kernel := testKernel()
		route := testRoute("0.0.0.0/0", 4, "", vnetlink.SCOPE_LINK, 0)
		route.Table = 100
		route.Protocol = vnetlink.RouteProtocol(unix.RTPROT_STATIC)
		kernel.routesByTable[100] = []vnetlink.Route{route}
		if _, err := (&Adapter{kernel: kernel}).ReadRouting(context.Background(), ownership); err == nil || !strings.Contains(err.Error(), "foreign route") {
			t.Fatalf("foreign route ownership was accepted: %v", err)
		}
	})
	t.Run("rule protocol", func(t *testing.T) {
		kernel := testKernel()
		kernel.rules = []vnetlink.Rule{{Family: vnetlink.FAMILY_V4, Priority: 99, Table: 100, Protocol: unix.RTPROT_STATIC}}
		if _, err := (&Adapter{kernel: kernel}).ReadRouting(context.Background(), ownership); err == nil || !strings.Contains(err.Error(), "foreign rule") {
			t.Fatalf("foreign rule ownership was accepted: %v", err)
		}
	})
}

func TestRuleObservationRejectsNonUnicastAction(t *testing.T) {
	rule := *vnetlink.NewRule()
	rule.Family = vnetlink.FAMILY_V4
	rule.Priority = 99
	rule.Table = 100
	rule.IifName = "tailnet-in"
	rule.Protocol = uint8(agentRouteProtocol)
	rule.Type = unix.RTN_UNREACHABLE
	if observed := ruleFromNetlink(domain.IPv4, rule); !observed.UnexpectedMatch {
		t.Fatalf("non-unicast rule action was accepted: %#v", observed)
	}
}

func TestApplyRoutingInstallsReplacementRuleBeforeRemovingStalePriority(t *testing.T) {
	kernel := testKernel()
	stale := *vnetlink.NewRule()
	stale.Family = vnetlink.FAMILY_V4
	stale.Priority = 99
	stale.Table = 200
	stale.IifName = "tailnet-in"
	stale.Protocol = uint8(agentRouteProtocol)
	stale.Type = unix.RTN_UNICAST
	kernel.rules = []vnetlink.Rule{stale}
	desired := domain.Rule{Family: domain.IPv4, Priority: 99, Table: 100, IncomingInterface: "tailnet-in"}
	changes := domain.RoutingChanges{
		DeleteRules: []domain.Rule{ruleFromNetlink(domain.IPv4, stale)},
		AddRules:    []domain.Rule{desired},
	}
	writes, err := (&Adapter{kernel: kernel}).ApplyRouting(context.Background(), changes)
	if err != nil {
		t.Fatal(err)
	}
	if writes != 2 || !slices.Equal(kernel.ruleOperations, []string{"add", "delete"}) {
		t.Fatalf("replacement was not add-before-delete: writes=%d operations=%v", writes, kernel.ruleOperations)
	}
	if len(kernel.rules) != 1 || !managedRulesEqual(ruleFromNetlink(domain.IPv4, kernel.rules[0]), desired) {
		t.Fatalf("replacement rule did not converge: %#v", kernel.rules)
	}
}

func TestRouteProbeStaysInsideEveryPrefixShape(t *testing.T) {
	for _, value := range []string{"10.0.8.0/24", "10.0.8.7/32", "fd00:8::/64", "fd00:8::7/128"} {
		prefix := netip.MustParsePrefix(value)
		probe := routeProbe(prefix)
		if !prefix.Contains(probe) {
			t.Fatalf("probe %s escaped prefix %s", probe, prefix)
		}
	}
}

func TestEventForwardersStopOnContextWithoutUpstreamClosure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	linkUpdates := make(chan vnetlink.LinkUpdate)
	addressUpdates := make(chan vnetlink.AddrUpdate)
	routeUpdates := make(chan vnetlink.RouteUpdate)
	events := make(chan domain.NetworkEvent)
	var waitGroup sync.WaitGroup
	waitGroup.Add(3)
	go forwardLinkEvents(ctx, &waitGroup, linkUpdates, events)
	go forwardAddressEvents(ctx, &waitGroup, addressUpdates, events)
	go forwardRouteEvents(ctx, &waitGroup, routeUpdates, nil, events)

	cancel()
	done := make(chan struct{})
	go func() {
		waitGroup.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("event forwarders did not stop after context cancellation")
	}
}

func TestRouteEventForwarderAcknowledgesOnlyTheExpectedSelfMutation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tracker := &routeMutationTracker{}
	if err := tracker.activate(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tracker.deactivate(errRouteEventSubscriptionClosed) })

	route := vnetlink.Route{
		Family:   vnetlink.FAMILY_V4,
		Table:    31_999,
		Protocol: agentRouteProtocol,
		Type:     unix.RTN_BLACKHOLE,
		Dst:      ipNetFromPrefix(netip.MustParsePrefix("192.0.2.0/24")),
		Priority: 4_242,
		Scope:    vnetlink.SCOPE_UNIVERSE,
	}
	expectation, err := tracker.expect(unix.RTM_NEWROUTE, &route)
	if err != nil {
		t.Fatal(err)
	}
	updates := make(chan vnetlink.RouteUpdate, 2)
	events := make(chan domain.NetworkEvent, 2)
	var waitGroup sync.WaitGroup
	waitGroup.Add(1)
	go forwardRouteEvents(ctx, &waitGroup, updates, tracker, events)

	updates <- vnetlink.RouteUpdate{Type: unix.RTM_DELROUTE, Route: route}
	updates <- vnetlink.RouteUpdate{Type: unix.RTM_NEWROUTE, Route: route}
	close(updates)
	waitGroup.Wait()
	if err := tracker.wait(context.Background(), expectation); err != nil {
		t.Fatalf("expected self notification was not acknowledged: %v", err)
	}

	select {
	case event := <-events:
		if event.Kind != domain.NetworkEventRoute || event.Action != domain.NetworkEventDelete || event.Family != domain.IPv4 || event.Table != route.Table || event.Protocol != uint8(agentRouteProtocol) || event.RouteType != route.Type || event.Prefix != netip.MustParsePrefix("192.0.2.0/24") || event.Metric != route.Priority {
			t.Fatalf("external deletion lost route identity: %#v", event)
		}
	default:
		t.Fatal("external deletion was incorrectly absorbed")
	}
	select {
	case event := <-events:
		t.Fatalf("self route mutation leaked to the Runner: %#v", event)
	default:
	}
}

func TestRouteMutationTrackerFailsPendingWriteWhenSubscriptionStops(t *testing.T) {
	tracker := &routeMutationTracker{}
	if err := tracker.activate(); err != nil {
		t.Fatal(err)
	}
	route := &vnetlink.Route{
		Family: vnetlink.FAMILY_V6, Table: 100, Protocol: agentRouteProtocol,
		Type: unix.RTN_BLACKHOLE, Scope: vnetlink.SCOPE_UNIVERSE,
	}
	expectation, err := tracker.expect(unix.RTM_NEWROUTE, route)
	if err != nil {
		t.Fatal(err)
	}
	reason := errors.New("subscription failed")
	tracker.deactivate(reason)
	if err := tracker.wait(context.Background(), expectation); !errors.Is(err, reason) {
		t.Fatalf("pending write did not fail with the subscription: %v", err)
	}
}

func TestRouteMutationIdentityUsesOnlyStableKernelFields(t *testing.T) {
	blackholeRequest := &vnetlink.Route{
		Family: vnetlink.FAMILY_V6, Table: 100, Protocol: agentRouteProtocol,
		Type: unix.RTN_BLACKHOLE, Scope: vnetlink.SCOPE_UNIVERSE,
		Dst: ipNetFromPrefix(domain.DefaultPrefix(domain.IPv6)),
	}
	blackholeNotification := *blackholeRequest
	blackholeNotification.Dst = nil
	blackholeNotification.LinkIndex = 1
	requestKey, err := routeMutationIdentity(unix.RTM_NEWROUTE, blackholeRequest)
	if err != nil {
		t.Fatal(err)
	}
	notificationKey, err := routeMutationIdentity(unix.RTM_NEWROUTE, &blackholeNotification)
	if err != nil {
		t.Fatal(err)
	}
	if requestKey != notificationKey {
		t.Fatalf("kernel-derived reject route link changed identity: request=%#v notification=%#v", requestKey, notificationKey)
	}

	unicastRequest := &vnetlink.Route{
		Family: vnetlink.FAMILY_V6, Table: 100, Protocol: agentRouteProtocol,
		Type: unix.RTN_UNICAST, Scope: vnetlink.SCOPE_LINK, LinkIndex: 2,
		Dst: ipNetFromPrefix(netip.MustParsePrefix("2001:db8::/64")),
		Gw:  net.ParseIP("2001:db8::1"), Priority: 100,
	}
	unicastNotification := *unicastRequest
	unicastNotification.LinkIndex = 3
	unicastNotification.Gw = net.ParseIP("2001:db8::2")
	unicastNotification.Scope = vnetlink.SCOPE_UNIVERSE
	unicastNotification.Flags = unix.RTNH_F_ONLINK
	requestKey, err = routeMutationIdentity(unix.RTM_NEWROUTE, unicastRequest)
	if err != nil {
		t.Fatal(err)
	}
	notificationKey, err = routeMutationIdentity(unix.RTM_NEWROUTE, &unicastNotification)
	if err != nil {
		t.Fatal(err)
	}
	if requestKey != notificationKey {
		t.Fatalf("kernel-normalized route attributes changed event identity: request=%#v notification=%#v", requestKey, notificationKey)
	}
	unicastNotification.Priority++
	metricKey, err := routeMutationIdentity(unix.RTM_NEWROUTE, &unicastNotification)
	if err != nil {
		t.Fatal(err)
	}
	if requestKey == metricKey {
		t.Fatal("route metric was omitted from event identity")
	}
}

func TestApplyRoutingWaitsForTheExpectedKernelNotification(t *testing.T) {
	kernel := testKernel()
	adapter := &Adapter{kernel: kernel}
	if err := adapter.routeMutations.activate(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { adapter.routeMutations.deactivate(errRouteEventSubscriptionClosed) })
	kernel.routeReplaceHook = func(route *vnetlink.Route) {
		if !adapter.routeMutations.acknowledge(vnetlink.RouteUpdate{Type: unix.RTM_NEWROUTE, Route: *route}) {
			t.Error("simulated kernel notification did not match the registered mutation")
		}
	}

	writes, err := adapter.ApplyRouting(context.Background(), domain.RoutingChanges{UpsertRoutes: []domain.Route{{
		Family: domain.IPv4, Disposition: domain.RouteBlackhole, Table: 100,
		Prefix: netip.MustParsePrefix("192.0.2.0/24"), Metric: 32_760,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Fatalf("unexpected write count: %d", writes)
	}
}

type fakeKernel struct {
	links            map[int]vnetlink.Link
	addresses        map[int][]vnetlink.Addr
	routesByTarget   map[string][]vnetlink.Route
	routesByTable    map[int][]vnetlink.Route
	rules            []vnetlink.Rule
	ruleOperations   []string
	routeReplaceHook func(*vnetlink.Route)
	fibMatchObserved bool
}

func testKernel() *fakeKernel {
	links := map[int]vnetlink.Link{
		1: testLoopback(1, "loopback-test"),
		2: testTunnel(2, "tailnet-in"),
		3: testTunnel(3, "proxy-path"),
		4: testDevice(4, "internal-path"),
		5: testDevice(5, "dns-path-v4"),
		6: testDevice(6, "dns-path-v6"),
	}
	advertised := testRoute("10.0.8.0/24", 4, "10.42.0.1", vnetlink.SCOPE_UNIVERSE, 0)
	return &fakeKernel{
		links: links,
		addresses: map[int][]vnetlink.Addr{
			2: {testAddress("100.64.0.8/32"), testAddress("fd7a:115c:a1e0::8/128")},
			3: {testAddress("198.18.0.1/15"), testAddress("fd88:baba:fafa::1/126")},
		},
		routesByTarget: map[string][]vnetlink.Route{
			"10.0.8.1":   {advertised},
			"10.43.0.10": {testRoute("10.43.0.0/16", 5, "10.42.0.1", vnetlink.SCOPE_UNIVERSE, 0)},
			"fd00:43::a": {testRoute("fd00:43::/64", 6, "fd00:42::1", vnetlink.SCOPE_UNIVERSE, 0)},
		},
		routesByTable: map[int][]vnetlink.Route{254: {advertised}},
	}
}

func testLoopback(index int, name string) vnetlink.Link {
	attributes := usableAttributes(index, name)
	attributes.Flags |= net.FlagLoopback
	attributes.OperState = vnetlink.OperUnknown
	return &vnetlink.Device{LinkAttrs: attributes}
}

func testDiscoveryRequest() domain.DiscoveryRequest {
	return domain.DiscoveryRequest{
		TailnetAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.8"), netip.MustParseAddr("fd7a:115c:a1e0::8")},
		ProxyTunnelAddresses: []netip.Prefix{
			netip.MustParsePrefix("198.18.0.1/15"), netip.MustParsePrefix("fd88:baba:fafa::1/126"),
		},
		AdvertisedPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.8.0/24")},
		NameServers:        []netip.Addr{netip.MustParseAddr("10.43.0.10"), netip.MustParseAddr("fd00:43::a")},
	}
}

func testTunnel(index int, name string) vnetlink.Link {
	return &vnetlink.Tuntap{LinkAttrs: usableAttributes(index, name), Mode: vnetlink.TUNTAP_MODE_TUN}
}

func testDevice(index int, name string) vnetlink.Link {
	return &vnetlink.Device{LinkAttrs: usableAttributes(index, name)}
}

func usableAttributes(index int, name string) vnetlink.LinkAttrs {
	return vnetlink.LinkAttrs{Index: index, Name: name, Flags: net.FlagUp, OperState: vnetlink.OperUp}
}

func testAddress(value string) vnetlink.Addr {
	prefix := netip.MustParsePrefix(value)
	return vnetlink.Addr{IPNet: ipNetFromPrefix(prefix)}
}

func testRoute(prefix string, linkIndex int, gateway string, scope vnetlink.Scope, flags int) vnetlink.Route {
	parsedPrefix := netip.MustParsePrefix(prefix)
	route := vnetlink.Route{
		LinkIndex: linkIndex,
		Scope:     scope,
		Dst:       ipNetFromPrefix(parsedPrefix),
		Family:    linuxFamily(domain.FamilyOfPrefix(parsedPrefix)),
		Table:     254,
		Type:      unix.RTN_UNICAST,
		Flags:     flags,
	}
	if gateway != "" {
		route.Gw = net.IP(netip.MustParseAddr(gateway).AsSlice())
	}
	return route
}

func withRouteType(route vnetlink.Route, routeType int) vnetlink.Route {
	route.Type = routeType
	return route
}

func withMultipath(route vnetlink.Route) vnetlink.Route {
	route.MultiPath = []*vnetlink.NexthopInfo{{LinkIndex: route.LinkIndex}}
	return route
}

func withLinkIndex(route vnetlink.Route, linkIndex int) vnetlink.Route {
	route.LinkIndex = linkIndex
	return route
}

func withRouteFlags(route vnetlink.Route, flags int) vnetlink.Route {
	route.Flags = flags
	return route
}

func withRouteMTU(route vnetlink.Route, mtu int) vnetlink.Route {
	route.MTU = mtu
	return route
}

func withRouteMTULock(route vnetlink.Route) vnetlink.Route {
	route.MTULock = true
	return route
}

func (kernel *fakeKernel) LinkList() ([]vnetlink.Link, error) {
	result := make([]vnetlink.Link, 0, len(kernel.links))
	for _, link := range kernel.links {
		result = append(result, link)
	}
	return result, nil
}

func (kernel *fakeKernel) LinkByIndex(index int) (vnetlink.Link, error) {
	link, exists := kernel.links[index]
	if !exists {
		return nil, errors.New("link does not exist")
	}
	return link, nil
}

func (kernel *fakeKernel) AddrList(link vnetlink.Link, _ int) ([]vnetlink.Addr, error) {
	return kernel.addresses[link.Attrs().Index], nil
}

func (kernel *fakeKernel) RouteGetWithOptions(target net.IP, options *vnetlink.RouteGetOptions) ([]vnetlink.Route, error) {
	kernel.fibMatchObserved = kernel.fibMatchObserved || options != nil && options.FIBMatch
	address, _ := netip.AddrFromSlice(target)
	return kernel.routesByTarget[address.Unmap().String()], nil
}

func (kernel *fakeKernel) RouteListFiltered(_ int, filter *vnetlink.Route, _ uint64) ([]vnetlink.Route, error) {
	return kernel.routesByTable[filter.Table], nil
}

func (kernel *fakeKernel) RouteReplace(route *vnetlink.Route) error {
	if kernel.routeReplaceHook != nil {
		kernel.routeReplaceHook(route)
	}
	return nil
}
func (kernel *fakeKernel) RouteDel(*vnetlink.Route) error { return nil }
func (kernel *fakeKernel) RuleList(int) ([]vnetlink.Rule, error) {
	return slices.Clone(kernel.rules), nil
}
func (kernel *fakeKernel) RuleAdd(rule *vnetlink.Rule) error {
	kernel.ruleOperations = append(kernel.ruleOperations, "add")
	kernel.rules = append(kernel.rules, *rule)
	return nil
}
func (kernel *fakeKernel) RuleDel(rule *vnetlink.Rule) error {
	kernel.ruleOperations = append(kernel.ruleOperations, "delete")
	for index := range kernel.rules {
		if reflect.DeepEqual(kernel.rules[index], *rule) {
			kernel.rules = slices.Delete(kernel.rules, index, index+1)
			return nil
		}
	}
	return errors.New("rule does not exist")
}
