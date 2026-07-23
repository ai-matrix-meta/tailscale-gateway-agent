package domain

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
)

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
	desiredRoutes, err := indexDesiredRoutes(desired.Routes, ownership)
	if err != nil {
		return RoutingChanges{}, err
	}
	observedRoutes, err := indexObservedRoutes(observed.Routes, ownership)
	if err != nil {
		return RoutingChanges{}, err
	}
	desiredRules, err := indexDesiredRules(desired.Rules, ownership)
	if err != nil {
		return RoutingChanges{}, err
	}
	observedRules, err := indexObservedRules(observed.Rules, ownership)
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

func indexDesiredRoutes(routes []Route, ownership RoutingOwnership) (map[string]Route, error) {
	return indexRoutes(routes, ownership, true, "desired")
}

func indexObservedRoutes(routes []Route, ownership RoutingOwnership) (map[string]Route, error) {
	return indexRoutes(routes, ownership, false, "observed")
}

func indexRoutes(routes []Route, ownership RoutingOwnership, strict bool, label string) (map[string]Route, error) {
	result := make(map[string]Route, len(routes))
	for _, route := range routes {
		if strict {
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

func indexDesiredRules(rules []Rule, ownership RoutingOwnership) (map[string]Rule, error) {
	return indexRules(rules, ownership, true, "desired")
}

func indexObservedRules(rules []Rule, ownership RoutingOwnership) (map[string]Rule, error) {
	return indexRules(rules, ownership, false, "observed")
}

func indexRules(rules []Rule, ownership RoutingOwnership, strict bool, label string) (map[string]Rule, error) {
	result := make(map[string]Rule, len(rules))
	for _, rule := range rules {
		if strict {
			if err := rule.Validate(); err != nil {
				return nil, fmt.Errorf("%s routing state is invalid: %w", label, err)
			}
		} else if err := validateObservedRuleIdentity(rule); err != nil {
			return nil, fmt.Errorf("%s routing state is invalid: %w", label, err)
		}
		if !slices.Contains(ownership.RulePriorities, rule.Priority) {
			return nil, fmt.Errorf("%s rule priority %d is outside managed ownership", label, rule.Priority)
		}
		if strict && !slices.Contains(ownership.Tables, rule.Table) {
			return nil, fmt.Errorf("%s rule table %d is outside managed ownership", label, rule.Table)
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
