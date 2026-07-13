//go:build linux && integration

package netlink

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	vnetlink "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	integrationExitRouteTable          = 31_990
	integrationLocalEgressRouteTable   = 31_991
	integrationExitRulePriority        = 31_990
	integrationLocalEgressRulePriority = 31_991
	integrationActiveRouteMetric       = 100
	integrationFailClosedRouteMetric   = 32_760
)

func TestIntegrationDiscoversIndependentKernelEgressAndConvergesRouting(t *testing.T) {
	if err := purgeIntegrationRouting(); err != nil {
		t.Fatalf("remove stale integration routing state: %v", err)
	}
	t.Cleanup(func() {
		if err := purgeIntegrationRouting(); err != nil {
			t.Errorf("remove integration routing state: %v", err)
		}
	})

	tailnetLink := addIntegrationTunnel(t, "tailnet-test", []string{"100.64.0.8/32", "fd7a:115c:a1e0::8/128"})
	proxyLink := addIntegrationTunnel(t, "proxy-test", []string{"198.18.0.1/15", "fd88:baba:fafa::1/126"})
	ipv4Link := addIntegrationDummy(t, "uplink-v4", []string{"10.42.0.2/24"})
	ipv6Link := addIntegrationDummy(t, "uplink-v6", []string{"fd00:42::2/64"})

	advertisedPrefix := netip.MustParsePrefix("10.0.8.0/24")
	if err := vnetlink.RouteAdd(&vnetlink.Route{
		LinkIndex: ipv4Link.Attrs().Index,
		Dst:       ipNetFromPrefix(advertisedPrefix),
		Gw:        net.IP(netip.MustParseAddr("10.42.0.1").AsSlice()),
		Scope:     vnetlink.SCOPE_UNIVERSE,
		Type:      unix.RTN_UNICAST,
	}); err != nil {
		t.Fatalf("add integration advertised route: %v", err)
	}
	staleManagedRoute := &vnetlink.Route{
		Family:   vnetlink.FAMILY_V4,
		Table:    integrationExitRouteTable,
		Protocol: agentRouteProtocol,
		Type:     unix.RTN_BLACKHOLE,
		Dst:      ipNetFromPrefix(netip.MustParsePrefix("203.0.113.0/24")),
		Priority: integrationFailClosedRouteMetric,
		Scope:    vnetlink.SCOPE_UNIVERSE,
	}
	if err := vnetlink.RouteAdd(staleManagedRoute); err != nil {
		t.Fatalf("add stale managed route: %v", err)
	}
	t.Cleanup(func() { _ = vnetlink.RouteDel(staleManagedRoute) })

	adapter, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = adapter.Close() })
	subscriptionContext, cancelSubscription := context.WithCancel(context.Background())
	t.Cleanup(cancelSubscription)
	events, eventErrors, err := adapter.Subscribe(subscriptionContext)
	if err != nil {
		t.Fatal(err)
	}
	request := domain.DiscoveryRequest{
		TailnetAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.8"), netip.MustParseAddr("fd7a:115c:a1e0::8")},
		ProxyTunnelAddresses: []netip.Prefix{
			netip.MustParsePrefix("198.18.0.1/15"), netip.MustParsePrefix("fd88:baba:fafa::1/126"),
		},
		AdvertisedPrefixes: []netip.Prefix{advertisedPrefix},
		NameServers:        []netip.Addr{netip.MustParseAddr("10.42.0.53"), netip.MustParseAddr("fd00:42::53")},
	}
	snapshot, err := adapter.Discover(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.TailnetLink.Index != tailnetLink.Attrs().Index || snapshot.ProxyTunnelLink.Index != proxyLink.Attrs().Index {
		t.Fatalf("managed tunnels were not identified by their addresses: %#v", snapshot)
	}
	if snapshot.DNSEgressPaths[0].Link.Index != ipv4Link.Attrs().Index || snapshot.DNSEgressPaths[1].Link.Index != ipv6Link.Attrs().Index {
		t.Fatalf("DNS address families did not retain independent links: %#v", snapshot.DNSEgressPaths)
	}

	ownership := domain.RoutingOwnership{
		Tables:         []int{integrationExitRouteTable, integrationLocalEgressRouteTable},
		RulePriorities: []int{integrationExitRulePriority, integrationLocalEgressRulePriority},
	}
	desired := integrationRoutingState(snapshot)
	observed, err := adapter.ReadRouting(context.Background(), ownership)
	if err != nil {
		t.Fatal(err)
	}
	changes, err := domain.DiffRouting(desired, observed, ownership)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.ApplyRouting(context.Background(), changes); err != nil {
		t.Fatal(err)
	}
	verified, err := adapter.ReadRouting(context.Background(), ownership)
	if err != nil {
		t.Fatal(err)
	}
	remaining, err := domain.DiffRouting(desired, verified, ownership)
	if err != nil {
		t.Fatal(err)
	}
	if !remaining.Empty() {
		t.Fatalf("routing did not converge: %#v", remaining)
	}
	select {
	case event := <-events:
		t.Fatalf("managed route write leaked as an external event: %#v", event)
	case eventErr := <-eventErrors:
		t.Fatalf("route subscription failed after convergence: %v", eventErr)
	default:
	}

	deletedRoute, err := adapter.routeToNetlink(desired.Routes[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := vnetlink.RouteDel(deletedRoute); err != nil {
		t.Fatalf("delete managed route externally: %v", err)
	}
	select {
	case event := <-events:
		if event.Kind != domain.NetworkEventRoute || event.Action != domain.NetworkEventDelete || event.Table != deletedRoute.Table || event.Protocol != uint8(agentRouteProtocol) || event.Prefix != desired.Routes[0].Prefix {
			t.Fatalf("external route deletion lost identity: %#v", event)
		}
	case eventErr := <-eventErrors:
		t.Fatalf("route subscription failed while observing external deletion: %v", eventErr)
	case <-time.After(5 * time.Second):
		t.Fatal("external route deletion was not published")
	}

	drifted, err := adapter.ReadRouting(context.Background(), ownership)
	if err != nil {
		t.Fatal(err)
	}
	repair, err := domain.DiffRouting(desired, drifted, ownership)
	if err != nil {
		t.Fatal(err)
	}
	if repair.Empty() {
		t.Fatal("external route deletion did not create observable drift")
	}
	if _, err := adapter.ApplyRouting(context.Background(), repair); err != nil {
		t.Fatal(err)
	}
	stable, err := adapter.ReadRouting(context.Background(), ownership)
	if err != nil {
		t.Fatal(err)
	}
	stableChanges, err := domain.DiffRouting(desired, stable, ownership)
	if err != nil {
		t.Fatal(err)
	}
	if !stableChanges.Empty() {
		t.Fatalf("routing repair did not converge: %#v", stableChanges)
	}
	select {
	case event := <-events:
		t.Fatalf("managed repair leaked as an external event: %#v", event)
	case eventErr := <-eventErrors:
		t.Fatalf("route subscription failed after repair: %v", eventErr)
	default:
	}
}

func integrationRoutingState(snapshot domain.NetworkSnapshot) domain.RoutingState {
	state := domain.RoutingState{}
	for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
		state.Routes = append(state.Routes,
			domain.Route{Family: family, Disposition: domain.RouteUnicast, Table: integrationExitRouteTable, Prefix: domain.DefaultPrefix(family), Link: snapshot.ProxyTunnelLink, Metric: integrationActiveRouteMetric},
			domain.Route{Family: family, Disposition: domain.RouteBlackhole, Table: integrationExitRouteTable, Prefix: domain.DefaultPrefix(family), Metric: integrationFailClosedRouteMetric},
			domain.Route{Family: family, Disposition: domain.RouteUnicast, Table: integrationLocalEgressRouteTable, Prefix: domain.DefaultPrefix(family), Link: snapshot.ProxyTunnelLink, Metric: integrationActiveRouteMetric},
			domain.Route{Family: family, Disposition: domain.RouteBlackhole, Table: integrationLocalEgressRouteTable, Prefix: domain.DefaultPrefix(family), Metric: integrationFailClosedRouteMetric},
		)
		state.Rules = append(state.Rules,
			domain.Rule{Family: family, Priority: integrationExitRulePriority, Table: integrationExitRouteTable, IncomingInterface: snapshot.TailnetLink.Name},
			domain.Rule{Family: family, Priority: integrationLocalEgressRulePriority, Table: integrationLocalEgressRouteTable, Mark: 0x11, Mask: domain.LocalEgressPacketMarkMask},
		)
	}
	state.Routes = append(state.Routes,
		domain.Route{Family: domain.IPv4, Disposition: domain.RouteBlackhole, Table: integrationExitRouteTable, Prefix: netip.MustParsePrefix("100.64.0.0/10"), Metric: integrationFailClosedRouteMetric},
		domain.Route{Family: domain.IPv6, Disposition: domain.RouteBlackhole, Table: integrationExitRouteTable, Prefix: netip.MustParsePrefix("fd7a:115c:a1e0::/48"), Metric: integrationFailClosedRouteMetric},
	)
	return state
}

func purgeIntegrationRouting() error {
	var cleanupErrors []error
	for _, family := range []int{vnetlink.FAMILY_V4, vnetlink.FAMILY_V6} {
		for _, table := range []int{integrationExitRouteTable, integrationLocalEgressRouteTable} {
			routes, err := vnetlink.RouteListFiltered(family, &vnetlink.Route{Table: table}, vnetlink.RT_FILTER_TABLE)
			if err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("list family %d table %d routes: %w", family, table, err))
				continue
			}
			for index := range routes {
				if routes[index].Protocol != agentRouteProtocol {
					continue
				}
				if err := vnetlink.RouteDel(&routes[index]); err != nil {
					cleanupErrors = append(cleanupErrors, fmt.Errorf("delete family %d table %d route: %w", family, table, err))
				}
			}
		}
		rules, err := vnetlink.RuleList(family)
		if err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("list family %d rules: %w", family, err))
			continue
		}
		for index := range rules {
			if rules[index].Protocol != uint8(agentRouteProtocol) ||
				(rules[index].Priority != integrationExitRulePriority && rules[index].Priority != integrationLocalEgressRulePriority) {
				continue
			}
			if err := vnetlink.RuleDel(&rules[index]); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("delete family %d priority %d rule: %w", family, rules[index].Priority, err))
			}
		}
	}
	return errors.Join(cleanupErrors...)
}

func addIntegrationTunnel(t *testing.T, name string, addresses []string) vnetlink.Link {
	t.Helper()
	attributes := vnetlink.NewLinkAttrs()
	attributes.Name = name
	link := &vnetlink.Tuntap{LinkAttrs: attributes, Mode: vnetlink.TUNTAP_MODE_TUN, Flags: vnetlink.TUNTAP_DEFAULTS, Queues: 1}
	if err := vnetlink.LinkAdd(link); err != nil {
		t.Fatalf("add TUN %s: %v", name, err)
	}
	if len(link.Fds) != link.Queues || len(link.Fds) == 0 {
		_ = vnetlink.LinkDel(link)
		t.Fatalf("add TUN %s returned %d active queues, want %d", name, len(link.Fds), link.Queues)
	}
	t.Cleanup(func() {
		_ = vnetlink.LinkDel(link)
		for index, file := range link.Fds {
			if err := file.Close(); err != nil {
				t.Errorf("close TUN %s queue %d: %v", name, index, err)
			}
		}
	})
	configureIntegrationLink(t, link, addresses)
	return link
}

func addIntegrationDummy(t *testing.T, name string, addresses []string) vnetlink.Link {
	t.Helper()
	attributes := vnetlink.NewLinkAttrs()
	attributes.Name = name
	link := &vnetlink.Dummy{LinkAttrs: attributes}
	if err := vnetlink.LinkAdd(link); err != nil {
		t.Fatalf("add dummy link %s: %v", name, err)
	}
	t.Cleanup(func() {
		if err := vnetlink.LinkDel(link); err != nil {
			t.Errorf("delete dummy link %s: %v", name, err)
		}
	})
	configureIntegrationLink(t, link, addresses)
	return link
}

func configureIntegrationLink(t *testing.T, link vnetlink.Link, addresses []string) {
	t.Helper()
	for _, value := range addresses {
		prefix := netip.MustParsePrefix(value)
		address := &vnetlink.Addr{IPNet: ipNetFromPrefix(prefix)}
		if prefix.Addr().Is6() {
			address.Flags = unix.IFA_F_NODAD
		}
		if err := vnetlink.AddrAdd(link, address); err != nil {
			t.Fatalf("add address %s to %s: %v", prefix, link.Attrs().Name, err)
		}
	}
	if err := vnetlink.LinkSetUp(link); err != nil {
		t.Fatalf("set link %s up: %v", link.Attrs().Name, err)
	}
	observed, err := vnetlink.LinkByIndex(link.Attrs().Index)
	if err != nil {
		t.Fatalf("read configured link %s: %v", link.Attrs().Name, err)
	}
	if !usableLinkAttributes(observed.Attrs()) {
		t.Fatalf("configured link %s is not operationally usable: %v", link.Attrs().Name, observed.Attrs().OperState)
	}
}
