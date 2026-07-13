package domain

import (
	"net/netip"
	"strings"
	"testing"
)

func TestRouteResolutionFailsClosedForUncertainKernelResults(t *testing.T) {
	base := RouteResolution{
		Target:        netip.MustParseAddr("10.0.8.1"),
		MatchedPrefix: netip.MustParsePrefix("10.0.8.0/24"),
		Disposition:   RouteUnicast,
		Table:         254,
		Gateway:       netip.MustParseAddr("10.42.0.1"),
		Link:          LinkIdentity{Index: 7, Name: "uplink-a"},
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid route resolution was rejected: %v", err)
	}
	tests := []struct {
		name     string
		mutate   func(*RouteResolution)
		fragment string
	}{
		{name: "blackhole", mutate: func(value *RouteResolution) { value.Disposition = RouteBlackhole }, fragment: "disposition blackhole"},
		{name: "multipath", mutate: func(value *RouteResolution) { value.Multipath = true }, fragment: "multipath"},
		{name: "missing link", mutate: func(value *RouteResolution) { value.Link = LinkIdentity{} }, fragment: "output link"},
		{name: "unsupported attributes", mutate: func(value *RouteResolution) { value.UnexpectedAttributes = true }, fragment: "unsupported attributes"},
		{name: "on-link without gateway", mutate: func(value *RouteResolution) { value.Gateway = netip.Addr{}; value.OnLink = true }, fragment: "on-link without a gateway"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			test.mutate(&candidate)
			err := candidate.Validate()
			if err == nil || !strings.Contains(err.Error(), test.fragment) {
				t.Fatalf("expected %q error, got %v", test.fragment, err)
			}
		})
	}
}

func TestProxyTunnelDiscoveryRejectsMappedIPv4Prefix(t *testing.T) {
	request := ProxyTunnelDiscoveryRequest{Addresses: []netip.Prefix{
		netip.MustParsePrefix("::ffff:198.18.0.1/120"),
		netip.MustParsePrefix("fd88:baba:fafa::1/126"),
	}}
	if err := request.Validate(); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("mapped IPv4 proxy address was accepted: %v", err)
	}
}

func TestNetworkSnapshotExpressesIndependentIPv4AndIPv6Egress(t *testing.T) {
	request := DiscoveryRequest{
		TailnetAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.8"), netip.MustParseAddr("fd7a:115c:a1e0::8")},
		ProxyTunnelAddresses: []netip.Prefix{
			netip.MustParsePrefix("198.18.0.1/15"), netip.MustParsePrefix("fd88:baba:fafa::1/126"),
		},
		AdvertisedPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.8.0/24")},
		NameServers:        []netip.Addr{netip.MustParseAddr("10.43.0.10"), netip.MustParseAddr("fd00:43::a")},
	}
	snapshot := NetworkSnapshot{
		TailnetLink:     LinkIdentity{Index: 2, Name: "tailnet-in"},
		ProxyTunnelLink: LinkIdentity{Index: 3, Name: "proxy-path"},
		AdvertisedRoutes: []DirectRouteProjection{{
			Prefix: netip.MustParsePrefix("10.0.8.0/24"), Gateway: netip.MustParseAddr("10.42.0.1"), Link: LinkIdentity{Index: 4, Name: "internal-net"},
		}},
		DNSEgressPaths: []DNSEgressPath{
			{NameServer: netip.MustParseAddr("10.43.0.10"), Gateway: netip.MustParseAddr("10.42.0.1"), Link: LinkIdentity{Index: 5, Name: "dns-v4"}},
			{NameServer: netip.MustParseAddr("fd00:43::a"), Link: LinkIdentity{Index: 6, Name: "dns-v6"}},
		},
	}
	if err := snapshot.Validate(request); err != nil {
		t.Fatalf("dual-stack snapshot was rejected: %v", err)
	}
}

func TestNetworkSnapshotRejectsDNSPathThatConflictsWithCoveringProjection(t *testing.T) {
	request := DiscoveryRequest{
		TailnetAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.8")},
		ProxyTunnelAddresses: []netip.Prefix{
			netip.MustParsePrefix("198.18.0.1/15"), netip.MustParsePrefix("fd88:baba:fafa::1/126"),
		},
		AdvertisedPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.8.0/24")},
		NameServers:        []netip.Addr{netip.MustParseAddr("10.0.8.53")},
	}
	snapshot := NetworkSnapshot{
		TailnetLink:     LinkIdentity{Index: 2, Name: "tailnet-in"},
		ProxyTunnelLink: LinkIdentity{Index: 3, Name: "proxy-path"},
		AdvertisedRoutes: []DirectRouteProjection{{
			Prefix: netip.MustParsePrefix("10.0.8.0/24"), Gateway: netip.MustParseAddr("10.42.0.1"), Link: LinkIdentity{Index: 4, Name: "internal-net"},
		}},
		DNSEgressPaths: []DNSEgressPath{{
			NameServer: netip.MustParseAddr("10.0.8.53"), Gateway: netip.MustParseAddr("10.42.0.2"), Link: LinkIdentity{Index: 5, Name: "different-path"},
		}},
	}
	if err := snapshot.Validate(request); err == nil || !strings.Contains(err.Error(), "disagrees with advertised route projection") {
		t.Fatalf("conflicting DNS and advertised-prefix paths were accepted: %v", err)
	}
}

func TestDiffRoutingRejectsDuplicateObservedIdentity(t *testing.T) {
	ownership := RoutingOwnership{Tables: []int{100}, RulePriorities: []int{99}}
	route := Route{Family: IPv4, Disposition: RouteBlackhole, Table: 100, Prefix: DefaultPrefix(IPv4), Metric: 32_760}
	_, err := DiffRouting(RoutingState{Routes: []Route{route}}, RoutingState{Routes: []Route{route, route}}, ownership)
	if err == nil || !strings.Contains(err.Error(), "duplicate route identity") {
		t.Fatalf("duplicate observed route was not rejected: %v", err)
	}
}

func TestDiffRoutingEqualStateProducesNoChanges(t *testing.T) {
	state := RoutingState{
		Routes: []Route{
			{Family: IPv4, Disposition: RouteUnicast, Table: 100, Prefix: DefaultPrefix(IPv4), Link: LinkIdentity{Index: 3, Name: "proxy-path"}, Metric: 100},
			{Family: IPv4, Disposition: RouteBlackhole, Table: 100, Prefix: DefaultPrefix(IPv4), Metric: 32_760},
		},
		Rules: []Rule{{Family: IPv4, Priority: 99, Table: 100, IncomingInterface: "tailnet-in"}},
	}
	changes, err := DiffRouting(state, state, RoutingOwnership{Tables: []int{100}, RulePriorities: []int{99}})
	if err != nil {
		t.Fatal(err)
	}
	if !changes.Empty() {
		t.Fatalf("equal routing state produced changes: %#v", changes)
	}
}
