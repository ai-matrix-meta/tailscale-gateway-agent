//go:build linux

package netlink

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	vnetlink "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const agentRouteProtocol = vnetlink.RouteProtocol(186)

type kernelAPI interface {
	LinkList() ([]vnetlink.Link, error)
	LinkByIndex(int) (vnetlink.Link, error)
	AddrList(vnetlink.Link, int) ([]vnetlink.Addr, error)
	RouteGetWithOptions(net.IP, *vnetlink.RouteGetOptions) ([]vnetlink.Route, error)
	RouteListFiltered(int, *vnetlink.Route, uint64) ([]vnetlink.Route, error)
	RouteReplace(*vnetlink.Route) error
	RouteDel(*vnetlink.Route) error
	RuleList(int) ([]vnetlink.Rule, error)
	RuleAdd(*vnetlink.Rule) error
	RuleDel(*vnetlink.Rule) error
}

type Adapter struct {
	kernel         kernelAPI
	handle         *vnetlink.Handle
	routeMutations routeMutationTracker
}

func New() (*Adapter, error) {
	handle, err := vnetlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("open rtnetlink handle: %w", err)
	}
	if err := handle.SetSocketTimeout(10 * time.Second); err != nil {
		handle.Close()
		return nil, fmt.Errorf("configure rtnetlink timeout: %w", err)
	}
	return &Adapter{kernel: handle, handle: handle}, nil
}

func (adapter *Adapter) Close() error {
	adapter.routeMutations.deactivate(errRouteEventSubscriptionClosed)
	if adapter.handle != nil {
		adapter.handle.Close()
	}
	return nil
}

func (adapter *Adapter) Discover(ctx context.Context, request domain.DiscoveryRequest) (domain.NetworkSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return domain.NetworkSnapshot{}, err
	}
	if err := request.Validate(); err != nil {
		return domain.NetworkSnapshot{}, fmt.Errorf("validate discovery request: %w", err)
	}
	tailnetLink, err := adapter.discoverTunnelLink(request.TailnetAddresses, nil)
	if err != nil {
		return domain.NetworkSnapshot{}, fmt.Errorf("discover tailnet ingress link: %w", err)
	}
	proxyTunnelLink, err := adapter.DiscoverProxyTunnel(ctx, domain.ProxyTunnelDiscoveryRequest{Addresses: request.ProxyTunnelAddresses})
	if err != nil {
		return domain.NetworkSnapshot{}, fmt.Errorf("discover proxy tunnel link: %w", err)
	}
	snapshot := domain.NetworkSnapshot{TailnetLink: tailnetLink, ProxyTunnelLink: proxyTunnelLink}
	for _, prefix := range request.AdvertisedPrefixes {
		resolution, resolutionErr := adapter.resolveRoute(ctx, routeProbe(prefix))
		if resolutionErr != nil {
			return domain.NetworkSnapshot{}, fmt.Errorf("resolve advertised prefix %s: %w", prefix, resolutionErr)
		}
		if !resolution.MatchedPrefix.IsValid() || resolution.MatchedPrefix.Bits() > prefix.Bits() || !resolution.MatchedPrefix.Contains(prefix.Addr()) {
			return domain.NetworkSnapshot{}, fmt.Errorf("route selected for advertised prefix %s does not cover the complete prefix", prefix)
		}
		if err := adapter.ensureUniformProjection(ctx, prefix, resolution); err != nil {
			return domain.NetworkSnapshot{}, fmt.Errorf("validate advertised prefix %s projection: %w", prefix, err)
		}
		snapshot.AdvertisedRoutes = append(snapshot.AdvertisedRoutes, domain.DirectRouteProjection{
			Prefix: prefix, Gateway: resolution.Gateway, Link: resolution.Link, OnLink: resolution.OnLink,
		})
	}
	for _, nameServer := range request.NameServers {
		resolution, resolutionErr := adapter.resolveRoute(ctx, nameServer)
		if resolutionErr != nil {
			return domain.NetworkSnapshot{}, fmt.Errorf("resolve DNS nameserver %s: %w", nameServer, resolutionErr)
		}
		snapshot.DNSEgressPaths = append(snapshot.DNSEgressPaths, domain.DNSEgressPath{
			NameServer: nameServer, Gateway: resolution.Gateway, Link: resolution.Link, OnLink: resolution.OnLink,
		})
	}
	if err := snapshot.Validate(request); err != nil {
		return domain.NetworkSnapshot{}, err
	}
	return snapshot, nil
}

func (adapter *Adapter) DiscoverProxyTunnel(ctx context.Context, request domain.ProxyTunnelDiscoveryRequest) (domain.LinkIdentity, error) {
	if err := ctx.Err(); err != nil {
		return domain.LinkIdentity{}, err
	}
	if err := request.Validate(); err != nil {
		return domain.LinkIdentity{}, fmt.Errorf("validate proxy tunnel discovery request: %w", err)
	}
	addresses := make([]netip.Addr, 0, len(request.Addresses))
	for _, prefix := range request.Addresses {
		addresses = append(addresses, prefix.Addr().Unmap())
	}
	return adapter.discoverTunnelLink(addresses, request.Addresses)
}

func (adapter *Adapter) discoverTunnelLink(requiredAddresses []netip.Addr, requiredPrefixes []netip.Prefix) (domain.LinkIdentity, error) {
	if len(requiredAddresses) == 0 {
		return domain.LinkIdentity{}, errors.New("at least one identifying address is required")
	}
	links, err := adapter.kernel.LinkList()
	if err != nil {
		return domain.LinkIdentity{}, fmt.Errorf("list links: %w", err)
	}
	var matches []domain.LinkIdentity
	for _, link := range links {
		attributes := link.Attrs()
		if !usableLinkAttributes(attributes) || !isTUNLink(link) {
			continue
		}
		addresses, err := adapter.kernel.AddrList(link, vnetlink.FAMILY_ALL)
		if err != nil {
			return domain.LinkIdentity{}, fmt.Errorf("list addresses for link %s: %w", attributes.Name, err)
		}
		observedAddresses := make(map[netip.Addr]struct{}, len(addresses))
		observedPrefixes := make(map[netip.Prefix]struct{}, len(addresses))
		for _, address := range addresses {
			if address.Flags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DADFAILED) != 0 {
				continue
			}
			if address.IPNet == nil {
				continue
			}
			converted := addressFromIP(address.IPNet.IP)
			ones, bits := address.IPNet.Mask.Size()
			if converted.IsValid() && ones >= 0 && bits == converted.BitLen() {
				observedAddresses[converted] = struct{}{}
				observedPrefixes[netip.PrefixFrom(converted, ones)] = struct{}{}
			}
		}
		matched := true
		for _, required := range requiredAddresses {
			if _, exists := observedAddresses[required.Unmap()]; !exists {
				matched = false
				break
			}
		}
		if matched {
			for _, required := range requiredPrefixes {
				if _, exists := observedPrefixes[required]; !exists {
					matched = false
					break
				}
			}
		}
		if matched {
			identity := domain.LinkIdentity{Index: attributes.Index, Name: attributes.Name}
			if err := identity.Validate(); err != nil {
				return domain.LinkIdentity{}, fmt.Errorf("identifying addresses resolved to an invalid link: %w", err)
			}
			matches = append(matches, identity)
		}
	}
	if len(matches) != 1 {
		return domain.LinkIdentity{}, fmt.Errorf("identifying addresses resolved to %d links; exactly one is required", len(matches))
	}
	return matches[0], nil
}

func (adapter *Adapter) resolveRoute(ctx context.Context, target netip.Addr) (domain.RouteResolution, error) {
	if err := ctx.Err(); err != nil {
		return domain.RouteResolution{}, err
	}
	routes, err := adapter.kernel.RouteGetWithOptions(net.IP(target.AsSlice()), &vnetlink.RouteGetOptions{FIBMatch: true})
	if err != nil {
		return domain.RouteResolution{}, err
	}
	if len(routes) != 1 {
		return domain.RouteResolution{}, fmt.Errorf("kernel returned %d route candidates", len(routes))
	}
	route := routes[0]
	family := domain.FamilyOfAddress(target)
	expectedFamily := linuxFamily(family)
	unexpected := routeHasUnsupportedDiscoveryAttributes(route) || route.Table <= 0 || route.Family != 0 && route.Family != expectedFamily
	if len(route.Gw) != 0 {
		unexpected = unexpected || route.Scope != vnetlink.SCOPE_UNIVERSE
	} else if family == domain.IPv4 {
		unexpected = unexpected || route.Scope != vnetlink.SCOPE_LINK
	} else {
		unexpected = unexpected || route.Scope != vnetlink.SCOPE_UNIVERSE && route.Scope != vnetlink.SCOPE_LINK
	}
	resolution := domain.RouteResolution{
		Target:               target,
		MatchedPrefix:        domain.DefaultPrefix(domain.FamilyOfAddress(target)),
		Disposition:          routeDisposition(route.Type),
		Table:                route.Table,
		Gateway:              addressFromIP(route.Gw),
		OnLink:               route.Flags&unix.RTNH_F_ONLINK != 0,
		Multipath:            len(route.MultiPath) != 0,
		UnexpectedAttributes: unexpected,
	}
	if route.Dst != nil {
		resolution.MatchedPrefix = prefixFromIPNet(route.Dst)
	}
	if route.LinkIndex > 0 {
		link, linkErr := adapter.kernel.LinkByIndex(route.LinkIndex)
		if linkErr != nil {
			return domain.RouteResolution{}, fmt.Errorf("resolve output link index %d: %w", route.LinkIndex, linkErr)
		}
		attributes := link.Attrs()
		if !usableLinkAttributes(attributes) || attributes.Index != route.LinkIndex {
			return domain.RouteResolution{}, fmt.Errorf("output link index %d is missing or not up", route.LinkIndex)
		}
		resolution.Link = domain.LinkIdentity{Index: attributes.Index, Name: attributes.Name}
	}
	if err := resolution.Validate(); err != nil {
		return domain.RouteResolution{}, err
	}
	return resolution, nil
}

func (adapter *Adapter) ensureUniformProjection(ctx context.Context, advertisedPrefix netip.Prefix, resolution domain.RouteResolution) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	routes, err := adapter.kernel.RouteListFiltered(linuxFamily(domain.FamilyOfPrefix(advertisedPrefix)), &vnetlink.Route{Table: resolution.Table}, vnetlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("list table %d routes: %w", resolution.Table, err)
	}
	for _, route := range routes {
		candidate := domain.DefaultPrefix(domain.FamilyOfPrefix(advertisedPrefix))
		if route.Dst != nil {
			candidate = prefixFromIPNet(route.Dst)
		}
		if !candidate.IsValid() || candidate != candidate.Masked() {
			return fmt.Errorf("table %d contains an invalid destination prefix", resolution.Table)
		}
		if candidate.Bits() <= resolution.MatchedPrefix.Bits() || !prefixesOverlap(candidate, advertisedPrefix) {
			continue
		}
		return fmt.Errorf("more-specific route %s prevents a single deterministic projection", candidate)
	}
	return nil
}

func (adapter *Adapter) ReadRouting(ctx context.Context, ownership domain.RoutingOwnership) (domain.RoutingState, error) {
	state := domain.RoutingState{}
	for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
		linuxAddressFamily := linuxFamily(family)
		for _, table := range ownership.Tables {
			if err := ctx.Err(); err != nil {
				return domain.RoutingState{}, err
			}
			routes, err := adapter.kernel.RouteListFiltered(linuxAddressFamily, &vnetlink.Route{Table: table}, vnetlink.RT_FILTER_TABLE)
			if err != nil {
				return domain.RoutingState{}, fmt.Errorf("list family %d table %d routes: %w", family, table, err)
			}
			for _, route := range routes {
				if route.Protocol != agentRouteProtocol {
					return domain.RoutingState{}, fmt.Errorf("route table %d contains a foreign route with protocol %d", table, route.Protocol)
				}
				observed, err := adapter.routeFromNetlink(family, route)
				if err != nil {
					return domain.RoutingState{}, fmt.Errorf("decode family %d table %d managed route: %w", family, table, err)
				}
				state.Routes = append(state.Routes, observed)
			}
		}
		rules, err := adapter.kernel.RuleList(linuxAddressFamily)
		if err != nil {
			return domain.RoutingState{}, fmt.Errorf("list family %d policy rules: %w", family, err)
		}
		for _, rule := range rules {
			if !slices.Contains(ownership.RulePriorities, rule.Priority) {
				continue
			}
			if rule.Protocol != uint8(agentRouteProtocol) {
				return domain.RoutingState{}, fmt.Errorf("rule priority %d contains a foreign rule with protocol %d", rule.Priority, rule.Protocol)
			}
			state.Rules = append(state.Rules, ruleFromNetlink(family, rule))
		}
	}
	return state, nil
}

func (adapter *Adapter) ApplyRouting(ctx context.Context, changes domain.RoutingChanges) (int, error) {
	writes := 0
	for _, route := range changes.UpsertRoutes {
		if err := ctx.Err(); err != nil {
			return writes, err
		}
		netlinkRoute, err := adapter.routeToNetlink(route)
		if err != nil {
			return writes, err
		}
		if err := adapter.replaceRoute(ctx, netlinkRoute); err != nil {
			return writes, fmt.Errorf("replace %s route %s in table %d: %w", route.Disposition, route.Prefix, route.Table, err)
		}
		writes++
	}
	replacements := make(map[string]domain.Rule, len(changes.DeleteRules))
	for _, rule := range changes.DeleteRules {
		replacements[managedRuleIdentity(rule)] = rule
	}
	for _, rule := range changes.AddRules {
		if err := ctx.Err(); err != nil {
			return writes, err
		}
		if err := adapter.kernel.RuleAdd(ruleToNetlink(rule)); err != nil {
			return writes, fmt.Errorf("add family %d policy rule at priority %d: %w", rule.Family, rule.Priority, err)
		}
		writes++
		identity := managedRuleIdentity(rule)
		if _, replacing := replacements[identity]; replacing {
			// Once the safe replacement exists, finish removal of the stale rule
			// even if the caller is canceled. Leaving duplicate priorities would
			// make subsequent ownership reads ambiguous.
			deleted, err := adapter.deleteRulesAtPriorityExcept(context.WithoutCancel(ctx), rule.Family, rule.Priority, &rule)
			writes += deleted
			if err != nil {
				return writes, err
			}
			delete(replacements, identity)
		}
	}
	for _, rule := range changes.DeleteRules {
		identity := managedRuleIdentity(rule)
		if _, remains := replacements[identity]; !remains {
			continue
		}
		deleted, err := adapter.deleteRulesAtPriorityExcept(ctx, rule.Family, rule.Priority, nil)
		writes += deleted
		if err != nil {
			return writes, err
		}
		delete(replacements, identity)
	}
	for _, route := range changes.DeleteRoutes {
		deleted, err := adapter.deleteRoute(ctx, route)
		writes += deleted
		if err != nil {
			return writes, err
		}
	}
	return writes, nil
}

func (adapter *Adapter) Subscribe(ctx context.Context) (<-chan domain.NetworkEvent, <-chan error, error) {
	done := make(chan struct{})
	linkUpdates := make(chan vnetlink.LinkUpdate, 128)
	addressUpdates := make(chan vnetlink.AddrUpdate, 128)
	routeUpdates := make(chan vnetlink.RouteUpdate, 128)
	events := make(chan domain.NetworkEvent, 128)
	eventErrors := make(chan error, 8)
	errorCallback := func(err error) {
		select {
		case eventErrors <- err:
		default:
		}
	}
	if err := vnetlink.LinkSubscribeWithOptions(linkUpdates, done, vnetlink.LinkSubscribeOptions{ErrorCallback: errorCallback}); err != nil {
		close(done)
		return nil, nil, fmt.Errorf("subscribe to link events: %w", err)
	}
	if err := vnetlink.AddrSubscribeWithOptions(addressUpdates, done, vnetlink.AddrSubscribeOptions{ErrorCallback: errorCallback}); err != nil {
		close(done)
		return nil, nil, fmt.Errorf("subscribe to address events: %w", err)
	}
	if err := vnetlink.RouteSubscribeWithOptions(routeUpdates, done, vnetlink.RouteSubscribeOptions{ErrorCallback: errorCallback}); err != nil {
		close(done)
		return nil, nil, fmt.Errorf("subscribe to route events: %w", err)
	}
	if err := adapter.routeMutations.activate(); err != nil {
		close(done)
		return nil, nil, err
	}
	var closeOnce sync.Once
	closeSubscriptions := func() {
		closeOnce.Do(func() {
			adapter.routeMutations.deactivate(errRouteEventSubscriptionClosed)
			close(done)
		})
	}
	go func() {
		<-ctx.Done()
		closeSubscriptions()
	}()
	var forwarders sync.WaitGroup
	forwarders.Add(3)
	go forwardLinkEvents(ctx, &forwarders, linkUpdates, events)
	go forwardAddressEvents(ctx, &forwarders, addressUpdates, events)
	go forwardRouteEvents(ctx, &forwarders, routeUpdates, &adapter.routeMutations, events)
	go func() {
		forwarders.Wait()
		close(events)
	}()
	return events, eventErrors, nil
}

func (adapter *Adapter) routeFromNetlink(family domain.AddressFamily, route vnetlink.Route) (domain.Route, error) {
	prefix, err := canonicalRoutePrefix(family, route.Dst)
	if err != nil {
		return domain.Route{}, err
	}
	disposition := routeDisposition(route.Type)
	expectedScope := managedRouteScope(family, disposition, len(route.Gw) != 0)
	unexpected := route.Protocol != agentRouteProtocol || route.Scope != expectedScope ||
		route.Family != 0 && route.Family != linuxFamily(family) || route.Table <= 0 || route.Priority <= 0 ||
		routeHasUnsupportedManagedAttributes(route)
	if disposition == domain.RouteBlackhole && (len(route.Gw) != 0 || route.Flags != 0) {
		unexpected = true
	}
	link := domain.LinkIdentity{}
	if route.LinkIndex > 0 {
		resolved, linkErr := adapter.kernel.LinkByIndex(route.LinkIndex)
		if linkErr != nil {
			return domain.Route{}, fmt.Errorf("resolve managed route link index %d: %w", route.LinkIndex, linkErr)
		}
		attributes := resolved.Attrs()
		if !usableLinkAttributes(attributes) || attributes.Index != route.LinkIndex {
			return domain.Route{}, fmt.Errorf("managed route link index %d is missing, changed, or not up", route.LinkIndex)
		}
		link = domain.LinkIdentity{Index: attributes.Index, Name: attributes.Name}
		if err := link.Validate(); err != nil {
			return domain.Route{}, fmt.Errorf("validate managed route link index %d: %w", route.LinkIndex, err)
		}
		if disposition == domain.RouteBlackhole {
			if family != domain.IPv6 || unexpected {
				return domain.Route{}, fmt.Errorf("refuse to normalize unexpected family %d blackhole link %d/%s", family, link.Index, link.Name)
			}
			if attributes.Flags&net.FlagLoopback == 0 {
				return domain.Route{}, fmt.Errorf("ipv6 blackhole route carries non-loopback link %d/%s", link.Index, link.Name)
			}
			link = domain.LinkIdentity{}
		}
	} else if route.LinkIndex < 0 {
		return domain.Route{}, fmt.Errorf("managed route carries negative link index %d", route.LinkIndex)
	}
	if disposition == domain.RouteUnicast && !link.Valid() {
		return domain.Route{}, errors.New("managed unicast route has no usable link")
	}
	return domain.Route{
		Family: family, Disposition: disposition, Table: route.Table, Prefix: prefix,
		Gateway: addressFromIP(route.Gw), Link: link, OnLink: route.Flags&unix.RTNH_F_ONLINK != 0,
		Metric: route.Priority, UnexpectedAttributes: unexpected,
	}, nil
}

func (adapter *Adapter) routeToNetlink(route domain.Route) (*vnetlink.Route, error) {
	if err := route.Validate(); err != nil {
		return nil, fmt.Errorf("validate managed route: %w", err)
	}
	result := &vnetlink.Route{
		Table: route.Table, Protocol: agentRouteProtocol, Family: linuxFamily(route.Family), Priority: route.Metric,
		Dst: ipNetFromPrefix(route.Prefix),
	}
	switch route.Disposition {
	case domain.RouteBlackhole:
		result.Type = unix.RTN_BLACKHOLE
		result.Scope = vnetlink.SCOPE_UNIVERSE
	case domain.RouteUnicast:
		link, err := adapter.kernel.LinkByIndex(route.Link.Index)
		if err != nil {
			return nil, fmt.Errorf("resolve route link index %d: %w", route.Link.Index, err)
		}
		if !usableLinkAttributes(link.Attrs()) || link.Attrs().Index != route.Link.Index || link.Attrs().Name != route.Link.Name {
			return nil, fmt.Errorf("route link %d/%s changed or is not up", route.Link.Index, route.Link.Name)
		}
		result.LinkIndex = route.Link.Index
		result.Type = unix.RTN_UNICAST
		result.Scope = managedRouteScope(route.Family, route.Disposition, route.Gateway.IsValid())
		if route.Gateway.IsValid() {
			result.Gw = net.IP(route.Gateway.AsSlice())
		}
		if route.OnLink {
			result.Flags = unix.RTNH_F_ONLINK
		}
	default:
		return nil, fmt.Errorf("cannot write route disposition %q", route.Disposition)
	}
	return result, nil
}

func managedRouteScope(family domain.AddressFamily, disposition domain.RouteDisposition, hasGateway bool) vnetlink.Scope {
	if disposition == domain.RouteBlackhole || hasGateway || family == domain.IPv6 {
		return vnetlink.SCOPE_UNIVERSE
	}
	return vnetlink.SCOPE_LINK
}

func (adapter *Adapter) deleteRulesAtPriorityExcept(ctx context.Context, family domain.AddressFamily, priority int, keep *domain.Rule) (int, error) {
	rules, err := adapter.kernel.RuleList(linuxFamily(family))
	if err != nil {
		return 0, fmt.Errorf("list rules before deleting priority %d: %w", priority, err)
	}
	deleted := 0
	for index := range rules {
		if rules[index].Priority != priority {
			continue
		}
		if rules[index].Protocol != uint8(agentRouteProtocol) {
			return deleted, fmt.Errorf("refusing to delete foreign rule at priority %d", priority)
		}
		if keep != nil && managedRulesEqual(ruleFromNetlink(family, rules[index]), *keep) {
			keep = nil
			continue
		}
		if err := ctx.Err(); err != nil {
			return deleted, err
		}
		if err := adapter.kernel.RuleDel(&rules[index]); err != nil {
			return deleted, fmt.Errorf("delete family %d rule at priority %d: %w", family, priority, err)
		}
		deleted++
	}
	return deleted, nil
}

func (adapter *Adapter) deleteRoute(ctx context.Context, target domain.Route) (int, error) {
	routes, err := adapter.kernel.RouteListFiltered(linuxFamily(target.Family), &vnetlink.Route{Table: target.Table}, vnetlink.RT_FILTER_TABLE)
	if err != nil {
		return 0, fmt.Errorf("list routes before deleting %s from table %d: %w", target.Prefix, target.Table, err)
	}
	deleted := 0
	for index := range routes {
		if routes[index].Protocol != agentRouteProtocol {
			return deleted, fmt.Errorf("refusing to delete foreign route from table %d", target.Table)
		}
		observed, decodeErr := adapter.routeFromNetlink(target.Family, routes[index])
		if decodeErr != nil {
			return deleted, fmt.Errorf("decode managed route before deletion: %w", decodeErr)
		}
		if observed.Prefix.Masked() != target.Prefix.Masked() || observed.Disposition != target.Disposition || observed.Metric != target.Metric {
			continue
		}
		if err := ctx.Err(); err != nil {
			return deleted, err
		}
		if err := adapter.deleteNetlinkRoute(ctx, &routes[index]); err != nil {
			return deleted, fmt.Errorf("delete %s route %s from table %d: %w", target.Disposition, target.Prefix, target.Table, err)
		}
		deleted++
	}
	return deleted, nil
}

func ruleFromNetlink(family domain.AddressFamily, rule vnetlink.Rule) domain.Rule {
	mask := uint32(0)
	if rule.Mask != nil {
		mask = *rule.Mask
	}
	unexpected := rule.OifName != "" || rule.Src != nil || rule.Dst != nil || rule.Tos != 0 || rule.TunID != 0 || rule.Goto >= 0 || rule.Flow >= 0 || rule.SuppressIfgroup >= 0 || rule.SuppressPrefixlen >= 0 || rule.Invert || rule.Dport != nil || rule.Sport != nil || rule.IPProto != 0 || rule.UIDRange != nil || rule.Protocol != uint8(agentRouteProtocol) || rule.Type != 0 && rule.Type != unix.RTN_UNICAST
	return domain.Rule{
		Family: family, Priority: rule.Priority, Table: rule.Table, IncomingInterface: rule.IifName,
		Mark: rule.Mark, Mask: mask, UnexpectedMatch: unexpected,
	}
}

func ruleToNetlink(rule domain.Rule) *vnetlink.Rule {
	result := vnetlink.NewRule()
	result.Family = linuxFamily(rule.Family)
	result.Priority = rule.Priority
	result.Table = rule.Table
	result.IifName = rule.IncomingInterface
	result.Protocol = uint8(agentRouteProtocol)
	result.Type = unix.RTN_UNICAST
	if rule.Mark != 0 {
		result.Mark = rule.Mark
		mask := rule.Mask
		result.Mask = &mask
	}
	return result
}

func managedRuleIdentity(rule domain.Rule) string {
	return fmt.Sprintf("%d/%d", rule.Family, rule.Priority)
}

func managedRulesEqual(left, right domain.Rule) bool {
	return left.Family == right.Family && left.Priority == right.Priority && left.Table == right.Table && left.IncomingInterface == right.IncomingInterface && left.Mark == right.Mark && left.Mask == right.Mask && left.UnexpectedMatch == right.UnexpectedMatch
}

func routeDisposition(routeType int) domain.RouteDisposition {
	switch routeType {
	case 0, unix.RTN_UNICAST:
		return domain.RouteUnicast
	case unix.RTN_BLACKHOLE:
		return domain.RouteBlackhole
	case unix.RTN_UNREACHABLE:
		return domain.RouteUnreachable
	case unix.RTN_PROHIBIT:
		return domain.RouteProhibit
	case unix.RTN_THROW:
		return domain.RouteThrow
	default:
		return domain.RouteUnknown
	}
}

func routeHasUnsupportedDiscoveryAttributes(route vnetlink.Route) bool {
	return route.ILinkIndex != 0 || route.MPLSDst != nil || route.NewDst != nil || route.Encap != nil || route.Via != nil || route.Realm != 0 || route.Tos != 0 || route.Flags & ^unix.RTNH_F_ONLINK != 0 || routeHasUnsupportedMetrics(route)
}

func routeHasUnsupportedManagedAttributes(route vnetlink.Route) bool {
	return routeHasUnsupportedDiscoveryAttributes(route) || len(route.MultiPath) != 0 || len(route.Src) != 0
}

func routeHasUnsupportedMetrics(route vnetlink.Route) bool {
	return route.MTU != 0 || route.MTULock || route.Window != 0 || route.Rtt != 0 || route.RttVar != 0 || route.Ssthresh != 0 || route.Cwnd != 0 || route.AdvMSS != 0 || route.Reordering != 0 || route.Hoplimit != 0 || route.InitCwnd != 0 || route.Features != 0 || route.RtoMin != 0 || route.RtoMinLock || route.InitRwnd != 0 || route.QuickACK != 0 || route.Congctl != "" || route.FastOpenNoCookie != 0
}

func ipNetFromPrefix(prefix netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: net.IP(prefix.Addr().AsSlice()), Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())}
}

func prefixFromIPNet(network *net.IPNet) netip.Prefix {
	address := addressFromIP(network.IP)
	ones, _ := network.Mask.Size()
	return netip.PrefixFrom(address, ones).Masked()
}

func canonicalRoutePrefix(family domain.AddressFamily, network *net.IPNet) (netip.Prefix, error) {
	prefix := domain.DefaultPrefix(family)
	if network != nil {
		prefix = prefixFromIPNet(network)
	}
	if !prefix.IsValid() || prefix != prefix.Masked() || domain.FamilyOfPrefix(prefix) != family {
		return netip.Prefix{}, fmt.Errorf("route has invalid family %d destination %v", family, network)
	}
	return prefix, nil
}

func addressFromIP(address net.IP) netip.Addr {
	if len(address) == 0 {
		return netip.Addr{}
	}
	converted, valid := netip.AddrFromSlice(address)
	if !valid {
		return netip.Addr{}
	}
	return converted.Unmap()
}

func linuxFamily(family domain.AddressFamily) int {
	if family == domain.IPv4 {
		return vnetlink.FAMILY_V4
	}
	return vnetlink.FAMILY_V6
}

func routeProbe(prefix netip.Prefix) netip.Addr {
	prefix = prefix.Masked()
	if prefix.Bits() < prefix.Addr().BitLen() {
		if next := prefix.Addr().Next(); next.IsValid() && prefix.Contains(next) {
			return next
		}
	}
	return prefix.Addr()
}

func prefixesOverlap(left, right netip.Prefix) bool {
	if !left.IsValid() || !right.IsValid() || domain.FamilyOfPrefix(left) != domain.FamilyOfPrefix(right) {
		return false
	}
	return left.Contains(right.Addr()) || right.Contains(left.Addr())
}

func usableLinkAttributes(attributes *vnetlink.LinkAttrs) bool {
	if attributes == nil || attributes.Index <= 0 || attributes.Name == "" || len(attributes.Name) > domain.MaximumInterfaceNameBytes || attributes.Flags&net.FlagUp == 0 {
		return false
	}
	return attributes.OperState == vnetlink.OperUnknown || attributes.OperState == vnetlink.OperUp
}

func isTUNLink(link vnetlink.Link) bool {
	tunnel, ok := link.(*vnetlink.Tuntap)
	return ok && tunnel.Mode == vnetlink.TUNTAP_MODE_TUN
}

func forwardLinkEvents(ctx context.Context, waitGroup *sync.WaitGroup, updates <-chan vnetlink.LinkUpdate, events chan<- domain.NetworkEvent) {
	defer waitGroup.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case _, open := <-updates:
			if !open || !sendEvent(ctx, events, domain.NetworkEvent{Kind: domain.NetworkEventLink}) {
				return
			}
		}
	}
}

func forwardAddressEvents(ctx context.Context, waitGroup *sync.WaitGroup, updates <-chan vnetlink.AddrUpdate, events chan<- domain.NetworkEvent) {
	defer waitGroup.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case _, open := <-updates:
			if !open || !sendEvent(ctx, events, domain.NetworkEvent{Kind: domain.NetworkEventAddress}) {
				return
			}
		}
	}
}

func forwardRouteEvents(ctx context.Context, waitGroup *sync.WaitGroup, updates <-chan vnetlink.RouteUpdate, tracker *routeMutationTracker, events chan<- domain.NetworkEvent) {
	defer waitGroup.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case update, open := <-updates:
			if !open {
				return
			}
			if tracker != nil && tracker.acknowledge(update) {
				continue
			}
			if !sendEvent(ctx, events, networkEventFromRouteUpdate(update)) {
				return
			}
		}
	}
}

func sendEvent(ctx context.Context, output chan<- domain.NetworkEvent, event domain.NetworkEvent) bool {
	select {
	case output <- event:
		return true
	case <-ctx.Done():
		return false
	}
}
