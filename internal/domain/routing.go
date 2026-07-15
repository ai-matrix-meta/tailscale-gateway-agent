package domain

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

const MaximumInterfaceNameBytes = 15

type AddressFamily uint8

const (
	IPv4 AddressFamily = 4
	IPv6 AddressFamily = 6
)

type LinkIdentity struct {
	Index int
	Name  string
}

func (link LinkIdentity) Validate() error {
	switch {
	case link.Index <= 0:
		return fmt.Errorf("link index %d must be positive", link.Index)
	case link.Name == "":
		return errors.New("link name must not be empty")
	case len(link.Name) > MaximumInterfaceNameBytes:
		return fmt.Errorf("link name %q exceeds %d bytes", link.Name, MaximumInterfaceNameBytes)
	case link.Name == "." || link.Name == "..":
		return fmt.Errorf("link name %q is reserved", link.Name)
	case strings.ContainsAny(link.Name, "/:"):
		return fmt.Errorf("link name %q contains a prohibited delimiter", link.Name)
	default:
		for _, character := range []byte(link.Name) {
			if character <= ' ' || character == 0x7f {
				return fmt.Errorf("link name %q contains whitespace or a control byte", link.Name)
			}
		}
		return nil
	}
}

func (link LinkIdentity) Valid() bool { return link.Validate() == nil }

type RouteDisposition string

const (
	RouteUnicast     RouteDisposition = "unicast"
	RouteBlackhole   RouteDisposition = "blackhole"
	RouteUnreachable RouteDisposition = "unreachable"
	RouteProhibit    RouteDisposition = "prohibit"
	RouteThrow       RouteDisposition = "throw"
	RouteUnknown     RouteDisposition = "unknown"
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

type Route struct {
	Family               AddressFamily
	Disposition          RouteDisposition
	Table                int
	Prefix               netip.Prefix
	Gateway              netip.Addr
	Link                 LinkIdentity
	OnLink               bool
	Metric               int
	UnexpectedAttributes bool
}

func (route Route) Validate() error {
	if route.UnexpectedAttributes {
		return errors.New("desired route contains unexpected attributes")
	}
	if route.Family != IPv4 && route.Family != IPv6 {
		return fmt.Errorf("route has unsupported address family %d", route.Family)
	}
	if route.Table <= 0 {
		return fmt.Errorf("route table %d must be positive", route.Table)
	}
	if !validMaskedPrefix(route.Prefix, route.Family) {
		return fmt.Errorf("route prefix %q does not match family %d", route.Prefix, route.Family)
	}
	if route.Metric <= 0 || route.Metric > maximumNetlinkInteger {
		return fmt.Errorf("route metric %d must be within 1..2147483647", route.Metric)
	}
	switch route.Disposition {
	case RouteUnicast:
		if err := route.Link.Validate(); err != nil {
			return fmt.Errorf("unicast route %s has invalid link: %w", route.Prefix, err)
		}
		if route.Gateway.IsValid() {
			gateway := route.Gateway.Unmap()
			if gateway.Zone() != "" || FamilyOfAddress(gateway) != route.Family {
				return fmt.Errorf("unicast route %s has invalid gateway %s", route.Prefix, route.Gateway)
			}
		} else if route.OnLink {
			return fmt.Errorf("unicast route %s sets on-link without a gateway", route.Prefix)
		}
	case RouteBlackhole:
		if route.Link != (LinkIdentity{}) || route.Gateway.IsValid() || route.OnLink {
			return fmt.Errorf("blackhole route %s must not carry a link, gateway, or on-link flag", route.Prefix)
		}
	default:
		return fmt.Errorf("managed route %s has unsupported disposition %q", route.Prefix, route.Disposition)
	}
	return nil
}

type Rule struct {
	Family            AddressFamily
	Priority          int
	Table             int
	IncomingInterface string
	Mark              uint32
	Mask              uint32
	UnexpectedMatch   bool
}

func (rule Rule) Validate() error {
	if rule.UnexpectedMatch {
		return errors.New("desired rule contains unexpected match attributes")
	}
	if rule.Family != IPv4 && rule.Family != IPv6 {
		return fmt.Errorf("rule has unsupported address family %d", rule.Family)
	}
	if rule.Priority <= 0 || rule.Table <= 0 {
		return fmt.Errorf("rule priority %d and table %d must be positive", rule.Priority, rule.Table)
	}
	if rule.IncomingInterface != "" {
		if err := (LinkIdentity{Index: 1, Name: rule.IncomingInterface}).Validate(); err != nil {
			return fmt.Errorf("rule has invalid incoming interface: %w", err)
		}
	}
	if rule.Mark == 0 && rule.Mask != 0 || rule.Mark != 0 && rule.Mask == 0 {
		return errors.New("rule packet mark and mask must either both be zero or both be non-zero")
	}
	if rule.IncomingInterface != "" && rule.Mark != 0 {
		return errors.New("managed rule must not combine incoming-interface and packet-mark selectors")
	}
	if rule.IncomingInterface == "" && rule.Mark == 0 {
		return errors.New("managed rule requires an incoming-interface or packet-mark selector")
	}
	return nil
}

type RoutingState struct {
	Routes []Route
	Rules  []Rule
}

type ExitDefaultRouteSet struct {
	IPv4 bool
	IPv6 bool
}

func AllExitDefaultRoutes() ExitDefaultRouteSet {
	return ExitDefaultRouteSet{IPv4: true, IPv6: true}
}

func (routes ExitDefaultRouteSet) Empty() bool {
	return !routes.IPv4 && !routes.IPv6
}

func (routes ExitDefaultRouteSet) Equal(other ExitDefaultRouteSet) bool {
	return routes.IPv4 == other.IPv4 && routes.IPv6 == other.IPv6
}

func (routes ExitDefaultRouteSet) Contains(family AddressFamily) bool {
	switch family {
	case IPv4:
		return routes.IPv4
	case IPv6:
		return routes.IPv6
	default:
		return false
	}
}

type RoutingOwnership struct {
	Tables         []int
	RulePriorities []int
}

func (ownership RoutingOwnership) Validate() error {
	var validationErrors []error
	if len(ownership.Tables) == 0 {
		validationErrors = append(validationErrors, errors.New("at least one owned route table is required"))
	}
	if len(ownership.RulePriorities) == 0 {
		validationErrors = append(validationErrors, errors.New("at least one owned rule priority is required"))
	}
	if err := validateUniquePositiveIntegers("route table", ownership.Tables); err != nil {
		validationErrors = append(validationErrors, err)
	}
	if err := validateUniquePositiveIntegers("rule priority", ownership.RulePriorities); err != nil {
		validationErrors = append(validationErrors, err)
	}
	return errors.Join(validationErrors...)
}

type RoutingChanges struct {
	UpsertRoutes []Route
	DeleteRules  []Rule
	AddRules     []Rule
	DeleteRoutes []Route
}

func (changes RoutingChanges) Empty() bool {
	return len(changes.UpsertRoutes) == 0 && len(changes.DeleteRules) == 0 && len(changes.AddRules) == 0 && len(changes.DeleteRoutes) == 0
}

func (changes RoutingChanges) Equal(other RoutingChanges) bool {
	return slices.Equal(changes.UpsertRoutes, other.UpsertRoutes) &&
		slices.Equal(changes.DeleteRules, other.DeleteRules) &&
		slices.Equal(changes.AddRules, other.AddRules) &&
		slices.Equal(changes.DeleteRoutes, other.DeleteRoutes)
}

func DiffRouting(desired, observed RoutingState, ownership RoutingOwnership) (RoutingChanges, error) {
	if err := ownership.Validate(); err != nil {
		return RoutingChanges{}, fmt.Errorf("invalid routing ownership: %w", err)
	}
	desiredRoutes, err := indexedRoutes("desired", desired.Routes, ownership)
	if err != nil {
		return RoutingChanges{}, err
	}
	observedRoutes, err := indexedRoutes("observed", observed.Routes, ownership)
	if err != nil {
		return RoutingChanges{}, err
	}
	desiredRules, err := indexedRules("desired", desired.Rules, ownership)
	if err != nil {
		return RoutingChanges{}, err
	}
	observedRules, err := indexedRules("observed", observed.Rules, ownership)
	if err != nil {
		return RoutingChanges{}, err
	}

	var changes RoutingChanges
	for key, desiredRoute := range desiredRoutes {
		observedRoute, exists := observedRoutes[key]
		if !exists || !routeEqual(desiredRoute, observedRoute) {
			changes.UpsertRoutes = append(changes.UpsertRoutes, desiredRoute)
		}
	}
	for key, observedRoute := range observedRoutes {
		if _, exists := desiredRoutes[key]; !exists {
			changes.DeleteRoutes = append(changes.DeleteRoutes, observedRoute)
		}
	}
	for key, desiredRule := range desiredRules {
		observedRule, exists := observedRules[key]
		if exists && ruleEqual(desiredRule, observedRule) {
			continue
		}
		if exists {
			changes.DeleteRules = append(changes.DeleteRules, observedRule)
		}
		changes.AddRules = append(changes.AddRules, desiredRule)
	}
	for key, observedRule := range observedRules {
		if _, exists := desiredRules[key]; !exists {
			changes.DeleteRules = append(changes.DeleteRules, observedRule)
		}
	}

	slices.SortFunc(changes.UpsertRoutes, compareRoutes)
	slices.SortFunc(changes.DeleteRoutes, compareRoutes)
	slices.SortFunc(changes.DeleteRules, compareRules)
	slices.SortFunc(changes.AddRules, compareRules)
	return changes, nil
}

func DefaultPrefix(family AddressFamily) netip.Prefix {
	if family == IPv4 {
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	}
	return netip.PrefixFrom(netip.IPv6Unspecified(), 0)
}

func FamilyOfAddress(address netip.Addr) AddressFamily {
	if address.Unmap().Is4() {
		return IPv4
	}
	return IPv6
}

func FamilyOfPrefix(prefix netip.Prefix) AddressFamily { return FamilyOfAddress(prefix.Addr()) }

func validInterfaceAddressPrefix(prefix netip.Prefix) bool {
	if !prefix.IsValid() || prefix.Bits() == 0 || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
		return false
	}
	return prefix.Bits() <= prefix.Addr().BitLen()
}

func indexedRoutes(label string, routes []Route, ownership RoutingOwnership) (map[string]Route, error) {
	result := make(map[string]Route, len(routes))
	for _, route := range routes {
		if label == "desired" {
			if err := route.Validate(); err != nil {
				return nil, fmt.Errorf("%s routing state is invalid: %w", label, err)
			}
		} else if err := validateObservedRouteIdentity(route); err != nil {
			return nil, fmt.Errorf("%s routing state is invalid: %w", label, err)
		}
		if !slices.Contains(ownership.Tables, route.Table) {
			return nil, fmt.Errorf("%s route table %d is outside managed ownership", label, route.Table)
		}
		key := routeKey(route)
		if _, duplicate := result[key]; duplicate {
			return nil, fmt.Errorf("%s routing state contains duplicate route identity %s", label, key)
		}
		result[key] = route
	}
	return result, nil
}

func indexedRules(label string, rules []Rule, ownership RoutingOwnership) (map[string]Rule, error) {
	result := make(map[string]Rule, len(rules))
	for _, rule := range rules {
		if label == "desired" {
			if err := rule.Validate(); err != nil {
				return nil, fmt.Errorf("%s routing state is invalid: %w", label, err)
			}
		} else if err := validateObservedRuleIdentity(rule); err != nil {
			return nil, fmt.Errorf("%s routing state is invalid: %w", label, err)
		}
		if !slices.Contains(ownership.RulePriorities, rule.Priority) || label == "desired" && !slices.Contains(ownership.Tables, rule.Table) {
			return nil, fmt.Errorf("%s rule priority %d or table %d is outside managed ownership", label, rule.Priority, rule.Table)
		}
		key := ruleKey(rule)
		if _, duplicate := result[key]; duplicate {
			return nil, fmt.Errorf("%s routing state contains duplicate rule identity %s", label, key)
		}
		result[key] = rule
	}
	return result, nil
}

func validateObservedRouteIdentity(route Route) error {
	if route.Family != IPv4 && route.Family != IPv6 {
		return fmt.Errorf("route has unsupported address family %d", route.Family)
	}
	if route.Table <= 0 || !validMaskedPrefix(route.Prefix, route.Family) || route.Metric < 0 {
		return fmt.Errorf("route table %d, prefix %q, or metric %d is invalid", route.Table, route.Prefix, route.Metric)
	}
	return nil
}

func validateObservedRuleIdentity(rule Rule) error {
	if rule.Family != IPv4 && rule.Family != IPv6 {
		return fmt.Errorf("rule has unsupported address family %d", rule.Family)
	}
	if rule.Priority <= 0 || rule.Table <= 0 {
		return fmt.Errorf("rule priority %d or table %d is invalid", rule.Priority, rule.Table)
	}
	return nil
}

func routeKey(route Route) string {
	return fmt.Sprintf("%d/%s/%d/%s/%d", route.Family, route.Disposition, route.Table, route.Prefix.Masked(), route.Metric)
}

func ruleKey(rule Rule) string { return fmt.Sprintf("%d/%d", rule.Family, rule.Priority) }

func routeEqual(left, right Route) bool {
	return left.Family == right.Family && left.Disposition == right.Disposition && left.Table == right.Table && left.Prefix.Masked() == right.Prefix.Masked() && left.Gateway == right.Gateway && left.Link == right.Link && left.OnLink == right.OnLink && left.Metric == right.Metric && left.UnexpectedAttributes == right.UnexpectedAttributes
}

func ruleEqual(left, right Rule) bool {
	return left.Family == right.Family && left.Priority == right.Priority && left.Table == right.Table && left.IncomingInterface == right.IncomingInterface && left.Mark == right.Mark && left.Mask == right.Mask && left.UnexpectedMatch == right.UnexpectedMatch
}

func compareRoutes(left, right Route) int { return compareStrings(routeKey(left), routeKey(right)) }
func compareRules(left, right Rule) int   { return compareStrings(ruleKey(left), ruleKey(right)) }

func compareStrings(left, right string) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func validateUniqueAddresses(label string, values []netip.Addr, requireNonEmpty bool) error {
	var validationErrors []error
	if requireNonEmpty && len(values) == 0 {
		validationErrors = append(validationErrors, fmt.Errorf("at least one %s is required", label))
	}
	seen := make(map[netip.Addr]struct{}, len(values))
	for _, value := range values {
		address := value.Unmap()
		if !address.IsValid() || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
			validationErrors = append(validationErrors, fmt.Errorf("%s %q is invalid", label, value))
			continue
		}
		if _, duplicate := seen[address]; duplicate {
			validationErrors = append(validationErrors, fmt.Errorf("%s %s is duplicated", label, address))
		}
		seen[address] = struct{}{}
	}
	return errors.Join(validationErrors...)
}

func validateUniquePrefixes(label string, values []netip.Prefix) error {
	var validationErrors []error
	seen := make(map[netip.Prefix]struct{}, len(values))
	for index, value := range values {
		if !value.IsValid() || value.Bits() == 0 || value != value.Masked() {
			validationErrors = append(validationErrors, fmt.Errorf("%s %q must be a masked non-default prefix", label, value))
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			validationErrors = append(validationErrors, fmt.Errorf("%s %s is duplicated", label, value))
		}
		seen[value] = struct{}{}
		for _, previous := range values[:index] {
			if value != previous && prefixesOverlap(value, previous) {
				validationErrors = append(validationErrors, fmt.Errorf("%s values %s and %s overlap", label, previous, value))
			}
		}
	}
	return errors.Join(validationErrors...)
}

func validateUniquePositiveIntegers(label string, values []int) error {
	var validationErrors []error
	seen := make(map[int]struct{}, len(values))
	for _, value := range values {
		if value <= 0 {
			validationErrors = append(validationErrors, fmt.Errorf("%s %d must be positive", label, value))
		}
		if _, duplicate := seen[value]; duplicate {
			validationErrors = append(validationErrors, fmt.Errorf("%s %d is duplicated", label, value))
		}
		seen[value] = struct{}{}
	}
	return errors.Join(validationErrors...)
}
