package application

import (
	"net/netip"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
)

func buildSafetyRouting(configuration domain.Configuration) domain.RoutingState {
	network := configuration.Network
	state := domain.RoutingState{}
	for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
		state.Routes = append(state.Routes,
			blackholeRoute(family, network.ExitRouteTable, domain.DefaultPrefix(family), network.FailClosedRouteMetric),
		)
	}
	state.Routes = append(state.Routes,
		blackholeRoute(domain.IPv4, network.ExitRouteTable, network.TailnetIPv4Prefix, network.FailClosedRouteMetric),
		blackholeRoute(domain.IPv6, network.ExitRouteTable, network.TailnetIPv6Prefix, network.FailClosedRouteMetric),
	)
	for _, prefix := range configuration.Tailnet.AdvertiseRoutes {
		state.Routes = append(state.Routes, blackholeRoute(domain.FamilyOfPrefix(prefix), network.ExitRouteTable, prefix, network.FailClosedRouteMetric))
	}
	if configuration.PacketFilter.LocalEgress.Enabled {
		for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
			state.Routes = append(state.Routes, blackholeRoute(family, network.LocalEgressRouteTable, domain.DefaultPrefix(family), network.FailClosedRouteMetric))
			state.Rules = append(state.Rules,
				domain.Rule{Family: family, Priority: network.LocalEgressRulePriority, Table: network.LocalEgressRouteTable, Mark: network.LocalEgressPacketMark, Mask: domain.LocalEgressPacketMarkMask},
			)
		}
	}
	return state
}

func buildFailClosedRouting(configuration domain.Configuration, tailnetLink, proxyTunnelLink domain.LinkIdentity) domain.RoutingState {
	state := buildPreparedRouting(configuration, proxyTunnelLink)
	if !tailnetLink.Valid() {
		return state
	}
	for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
		state.Rules = append(state.Rules,
			domain.Rule{Family: family, Priority: configuration.Network.ExitRulePriority, Table: configuration.Network.ExitRouteTable, IncomingInterface: tailnetLink.Name},
		)
	}
	return state
}

func buildPreparedRouting(configuration domain.Configuration, proxyTunnelLink domain.LinkIdentity) domain.RoutingState {
	state := buildSafetyRouting(configuration)
	if !configuration.PacketFilter.LocalEgress.Enabled || !proxyTunnelLink.Valid() {
		return state
	}
	for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
		state.Routes = append(state.Routes,
			activeRoute(configuration.Network, family, configuration.Network.LocalEgressRouteTable, domain.DefaultPrefix(family), netip.Addr{}, proxyTunnelLink, false),
		)
	}
	return state
}

func buildDesiredRouting(configuration domain.Configuration, snapshot domain.NetworkSnapshot, activeExitDefaults domain.ExitDefaultRouteSet) domain.RoutingState {
	network := configuration.Network
	state := buildPreparedRouting(configuration, snapshot.ProxyTunnelLink)
	for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
		if activeExitDefaults.Contains(family) {
			state.Routes = append(state.Routes,
				activeRoute(network, family, network.ExitRouteTable, domain.DefaultPrefix(family), netip.Addr{}, snapshot.ProxyTunnelLink, false),
			)
		}
		state.Rules = append(state.Rules,
			domain.Rule{Family: family, Priority: network.ExitRulePriority, Table: network.ExitRouteTable, IncomingInterface: snapshot.TailnetLink.Name},
		)
	}
	state.Routes = append(state.Routes,
		activeRoute(network, domain.IPv4, network.ExitRouteTable, network.TailnetIPv4Prefix, netip.Addr{}, snapshot.TailnetLink, false),
		activeRoute(network, domain.IPv6, network.ExitRouteTable, network.TailnetIPv6Prefix, netip.Addr{}, snapshot.TailnetLink, false),
	)
	for _, projection := range snapshot.AdvertisedRoutes {
		state.Routes = append(state.Routes, activeRoute(
			network, domain.FamilyOfPrefix(projection.Prefix), network.ExitRouteTable,
			projection.Prefix, projection.Gateway, projection.Link, projection.OnLink,
		))
	}
	for _, path := range snapshot.DNSEgressPaths {
		address := path.NameServer.Unmap()
		coveredByAdvertisedRoute := false
		for _, projection := range snapshot.AdvertisedRoutes {
			if projection.Prefix.Contains(address) {
				coveredByAdvertisedRoute = true
				break
			}
		}
		if coveredByAdvertisedRoute {
			continue
		}
		state.Routes = append(state.Routes, activeRoute(
			network, domain.FamilyOfAddress(address), network.ExitRouteTable,
			netip.PrefixFrom(address, address.BitLen()), path.Gateway, path.Link, path.OnLink,
		))
	}
	return state
}

func routingOwnership(configuration domain.Configuration) domain.RoutingOwnership {
	return domain.RoutingOwnership{
		Tables:         []int{configuration.Network.ExitRouteTable, configuration.Network.LocalEgressRouteTable},
		RulePriorities: []int{configuration.Network.ExitRulePriority, configuration.Network.LocalEgressRulePriority},
	}
}

func blackholeRoute(family domain.AddressFamily, table int, prefix netip.Prefix, metric int) domain.Route {
	return domain.Route{Family: family, Disposition: domain.RouteBlackhole, Table: table, Prefix: prefix, Metric: metric}
}

func activeRoute(network domain.NetworkConfiguration, family domain.AddressFamily, table int, prefix netip.Prefix, gateway netip.Addr, link domain.LinkIdentity, onLink bool) domain.Route {
	return domain.Route{
		Family: family, Disposition: domain.RouteUnicast, Table: table, Prefix: prefix,
		Gateway: gateway, Link: link, OnLink: onLink, Metric: network.ActiveRouteMetric,
	}
}
