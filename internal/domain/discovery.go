package domain

import (
	"errors"
	"fmt"
	"net/netip"
)

type RouteResolution struct {
	Target               netip.Addr
	MatchedPrefix        netip.Prefix
	Disposition          RouteDisposition
	Table                int
	Gateway              netip.Addr
	Link                 LinkIdentity
	OnLink               bool
	Multipath            bool
	UnexpectedAttributes bool
}

func (resolution RouteResolution) Validate() error {
	target := resolution.Target.Unmap()
	if !target.IsValid() || target.Zone() != "" {
		return fmt.Errorf("route target %q is invalid", resolution.Target)
	}
	if resolution.Disposition != RouteUnicast {
		return fmt.Errorf("route to %s has disposition %s", target, resolution.Disposition)
	}
	if resolution.Multipath {
		return fmt.Errorf("route to %s is multipath", target)
	}
	if resolution.UnexpectedAttributes {
		return fmt.Errorf("route to %s contains unsupported attributes", target)
	}
	if resolution.Table <= 0 {
		return fmt.Errorf("route to %s has invalid table %d", target, resolution.Table)
	}
	if err := resolution.Link.Validate(); err != nil {
		return fmt.Errorf("route to %s has no usable output link: %w", target, err)
	}
	if !validMaskedPrefix(resolution.MatchedPrefix, FamilyOfAddress(target)) || !resolution.MatchedPrefix.Contains(target) {
		return fmt.Errorf("route to %s has invalid matched prefix %q", target, resolution.MatchedPrefix)
	}
	if resolution.Gateway.IsValid() {
		gateway := resolution.Gateway.Unmap()
		if gateway.Zone() != "" || FamilyOfAddress(gateway) != FamilyOfAddress(target) {
			return fmt.Errorf("route to %s has invalid gateway %s", target, resolution.Gateway)
		}
	} else if resolution.OnLink {
		return fmt.Errorf("route to %s sets on-link without a gateway", target)
	}
	return nil
}

type DiscoveryRequest struct {
	TailnetAddresses     []netip.Addr
	ProxyTunnelAddresses []netip.Prefix
	AdvertisedPrefixes   []netip.Prefix
	NameServers          []netip.Addr
}

type ProxyTunnelDiscoveryRequest struct {
	Addresses []netip.Prefix
}

func (request ProxyTunnelDiscoveryRequest) Validate() error {
	if len(request.Addresses) == 0 {
		return errors.New("at least one proxy tunnel address is required")
	}
	var validationErrors []error
	seenAddresses := make(map[netip.Addr]struct{}, len(request.Addresses))
	seenFamilies := make(map[AddressFamily]struct{}, 2)
	for _, prefix := range request.Addresses {
		if !validInterfaceAddressPrefix(prefix) {
			validationErrors = append(validationErrors, fmt.Errorf("proxy tunnel address %q is invalid", prefix))
			continue
		}
		address := prefix.Addr().Unmap()
		if _, duplicate := seenAddresses[address]; duplicate {
			validationErrors = append(validationErrors, fmt.Errorf("proxy tunnel address %s is duplicated", address))
		}
		seenAddresses[address] = struct{}{}
		seenFamilies[FamilyOfAddress(address)] = struct{}{}
	}
	if _, exists := seenFamilies[IPv4]; !exists {
		validationErrors = append(validationErrors, errors.New("proxy tunnel addresses require an IPv4 address"))
	}
	if _, exists := seenFamilies[IPv6]; !exists {
		validationErrors = append(validationErrors, errors.New("proxy tunnel addresses require an IPv6 address"))
	}
	return errors.Join(validationErrors...)
}

func (request DiscoveryRequest) Validate() error {
	var validationErrors []error
	if err := validateUniqueAddresses("tailnet address", request.TailnetAddresses, true); err != nil {
		validationErrors = append(validationErrors, err)
	}
	if len(request.ProxyTunnelAddresses) == 0 {
		validationErrors = append(validationErrors, errors.New("at least one proxy tunnel address is required"))
	}
	seenTunnelAddresses := make(map[netip.Addr]struct{}, len(request.ProxyTunnelAddresses))
	for _, prefix := range request.ProxyTunnelAddresses {
		if !validInterfaceAddressPrefix(prefix) {
			validationErrors = append(validationErrors, fmt.Errorf("proxy tunnel address %q is invalid", prefix))
			continue
		}
		address := prefix.Addr().Unmap()
		if _, exists := seenTunnelAddresses[address]; exists {
			validationErrors = append(validationErrors, fmt.Errorf("proxy tunnel address %s is duplicated", address))
		}
		seenTunnelAddresses[address] = struct{}{}
	}
	if err := validateUniquePrefixes("advertised prefix", request.AdvertisedPrefixes); err != nil {
		validationErrors = append(validationErrors, err)
	}
	if err := validateUniqueAddresses("DNS nameserver", request.NameServers, true); err != nil {
		validationErrors = append(validationErrors, err)
	}
	return errors.Join(validationErrors...)
}

type DirectRouteProjection struct {
	Prefix  netip.Prefix
	Gateway netip.Addr
	Link    LinkIdentity
	OnLink  bool
}

func (projection DirectRouteProjection) Validate() error {
	if !projection.Prefix.IsValid() || projection.Prefix.Bits() == 0 || projection.Prefix != projection.Prefix.Masked() {
		return fmt.Errorf("direct route prefix %q must be a masked non-default prefix", projection.Prefix)
	}
	if err := projection.Link.Validate(); err != nil {
		return fmt.Errorf("direct route %s has invalid link: %w", projection.Prefix, err)
	}
	if projection.Gateway.IsValid() {
		gateway := projection.Gateway.Unmap()
		if gateway.Zone() != "" || FamilyOfAddress(gateway) != FamilyOfPrefix(projection.Prefix) {
			return fmt.Errorf("direct route %s has invalid gateway %s", projection.Prefix, projection.Gateway)
		}
	} else if projection.OnLink {
		return fmt.Errorf("direct route %s sets on-link without a gateway", projection.Prefix)
	}
	return nil
}

type DNSEgressPath struct {
	NameServer netip.Addr
	Gateway    netip.Addr
	Link       LinkIdentity
	OnLink     bool
}

type NetworkSnapshot struct {
	TailnetLink      LinkIdentity
	ProxyTunnelLink  LinkIdentity
	AdvertisedRoutes []DirectRouteProjection
	DNSEgressPaths   []DNSEgressPath
}

func (snapshot NetworkSnapshot) Validate(request DiscoveryRequest) error {
	if err := request.Validate(); err != nil {
		return fmt.Errorf("invalid discovery request: %w", err)
	}
	var validationErrors []error
	if err := snapshot.TailnetLink.Validate(); err != nil {
		validationErrors = append(validationErrors, fmt.Errorf("tailnet ingress link is invalid: %w", err))
	}
	if err := snapshot.ProxyTunnelLink.Validate(); err != nil {
		validationErrors = append(validationErrors, fmt.Errorf("proxy tunnel link is invalid: %w", err))
	}
	if snapshot.TailnetLink.Index > 0 && snapshot.TailnetLink.Index == snapshot.ProxyTunnelLink.Index {
		validationErrors = append(validationErrors, errors.New("tailnet ingress and proxy tunnel resolve to the same link"))
	}

	expectedPrefixes := make(map[netip.Prefix]struct{}, len(request.AdvertisedPrefixes))
	for _, prefix := range request.AdvertisedPrefixes {
		expectedPrefixes[prefix] = struct{}{}
	}
	seenPrefixes := make(map[netip.Prefix]struct{}, len(snapshot.AdvertisedRoutes))
	for _, projection := range snapshot.AdvertisedRoutes {
		if err := projection.Validate(); err != nil {
			validationErrors = append(validationErrors, err)
			continue
		}
		if _, expected := expectedPrefixes[projection.Prefix]; !expected {
			validationErrors = append(validationErrors, fmt.Errorf("unexpected advertised route projection %s", projection.Prefix))
		}
		if _, duplicate := seenPrefixes[projection.Prefix]; duplicate {
			validationErrors = append(validationErrors, fmt.Errorf("advertised route projection %s is duplicated", projection.Prefix))
		}
		seenPrefixes[projection.Prefix] = struct{}{}
		if projection.Link.Index == snapshot.TailnetLink.Index || projection.Link.Index == snapshot.ProxyTunnelLink.Index {
			validationErrors = append(validationErrors, fmt.Errorf("advertised prefix %s resolves through a managed tunnel", projection.Prefix))
		}
	}
	for _, prefix := range request.AdvertisedPrefixes {
		if _, exists := seenPrefixes[prefix]; !exists {
			validationErrors = append(validationErrors, fmt.Errorf("advertised prefix %s has no route projection", prefix))
		}
	}

	expectedNameServers := make(map[netip.Addr]struct{}, len(request.NameServers))
	for _, address := range request.NameServers {
		expectedNameServers[address.Unmap()] = struct{}{}
	}
	seenNameServers := make(map[netip.Addr]struct{}, len(snapshot.DNSEgressPaths))
	for _, path := range snapshot.DNSEgressPaths {
		address := path.NameServer.Unmap()
		if !address.IsValid() || address.Zone() != "" {
			validationErrors = append(validationErrors, fmt.Errorf("DNS egress path has invalid nameserver %q", path.NameServer))
			continue
		}
		if err := path.Link.Validate(); err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("DNS nameserver %s has invalid egress link: %w", address, err))
		}
		if path.Gateway.IsValid() {
			gateway := path.Gateway.Unmap()
			if gateway.Zone() != "" || FamilyOfAddress(gateway) != FamilyOfAddress(address) {
				validationErrors = append(validationErrors, fmt.Errorf("DNS nameserver %s has invalid gateway %s", address, path.Gateway))
			}
		} else if path.OnLink {
			validationErrors = append(validationErrors, fmt.Errorf("DNS nameserver %s sets on-link without a gateway", address))
		}
		if _, expected := expectedNameServers[address]; !expected {
			validationErrors = append(validationErrors, fmt.Errorf("unexpected DNS egress path for %s", address))
		}
		if _, duplicate := seenNameServers[address]; duplicate {
			validationErrors = append(validationErrors, fmt.Errorf("DNS egress path for %s is duplicated", address))
		}
		seenNameServers[address] = struct{}{}
		if path.Link.Index == snapshot.TailnetLink.Index || path.Link.Index == snapshot.ProxyTunnelLink.Index {
			validationErrors = append(validationErrors, fmt.Errorf("DNS nameserver %s resolves through a managed tunnel", address))
		}
		for _, projection := range snapshot.AdvertisedRoutes {
			if !projection.Prefix.Contains(address) {
				continue
			}
			if path.Link != projection.Link || path.Gateway.Unmap() != projection.Gateway.Unmap() || path.OnLink != projection.OnLink {
				validationErrors = append(validationErrors, fmt.Errorf("DNS nameserver %s disagrees with advertised route projection %s", address, projection.Prefix))
			}
		}
	}
	for _, configuredAddress := range request.NameServers {
		address := configuredAddress.Unmap()
		if _, exists := seenNameServers[address]; !exists {
			validationErrors = append(validationErrors, fmt.Errorf("DNS nameserver %s has no egress path", address))
		}
	}
	return errors.Join(validationErrors...)
}
