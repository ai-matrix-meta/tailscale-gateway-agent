package environment

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
)

const ownedPrefix = "TAILSCALE_GATEWAY_"

const (
	configAPIVersion            = ownedPrefix + "CONFIG_API_VERSION"
	proxyTunnelAddresses        = ownedPrefix + "PROXY_TUNNEL_ADDRESSES"
	tailnetIPv4Prefix           = ownedPrefix + "TAILNET_IPV4_PREFIX"
	tailnetIPv6Prefix           = ownedPrefix + "TAILNET_IPV6_PREFIX"
	exitRouteTable              = ownedPrefix + "EXIT_ROUTE_TABLE"
	exitRulePriority            = ownedPrefix + "EXIT_RULE_PRIORITY"
	localEgressRouteTable       = ownedPrefix + "LOCAL_EGRESS_ROUTE_TABLE"
	localEgressRulePriority     = ownedPrefix + "LOCAL_EGRESS_RULE_PRIORITY"
	localEgressPacketMark       = ownedPrefix + "LOCAL_EGRESS_PACKET_MARK"
	activeRouteMetric           = ownedPrefix + "ACTIVE_ROUTE_METRIC"
	failClosedRouteMetric       = ownedPrefix + "FAIL_CLOSED_ROUTE_METRIC"
	nftablesFilterTable         = ownedPrefix + "NFTABLES_FILTER_TABLE"
	nftablesForwardGuardChain   = ownedPrefix + "NFTABLES_FORWARD_GUARD_CHAIN"
	nftablesLocalEgressChain    = ownedPrefix + "NFTABLES_LOCAL_EGRESS_CHAIN"
	nftablesLocalEgressIPv4Set  = ownedPrefix + "NFTABLES_LOCAL_EGRESS_IPV4_SET"
	nftablesLocalEgressIPv6Set  = ownedPrefix + "NFTABLES_LOCAL_EGRESS_IPV6_SET"
	nftablesNATTable            = ownedPrefix + "NFTABLES_NAT_TABLE"
	nftablesDNSSNATChain        = ownedPrefix + "NFTABLES_DNS_SNAT_CHAIN"
	localEgressEnabled          = ownedPrefix + "LOCAL_EGRESS_ENABLED"
	localEgressDomains          = ownedPrefix + "LOCAL_EGRESS_DOMAINS"
	localEgressProtocols        = ownedPrefix + "LOCAL_EGRESS_PROTOCOLS"
	localEgressPorts            = ownedPrefix + "LOCAL_EGRESS_PORTS"
	localEgressRefreshInterval  = ownedPrefix + "LOCAL_EGRESS_REFRESH_INTERVAL"
	localEgressMaximumStaleness = ownedPrefix + "LOCAL_EGRESS_MAXIMUM_STALENESS"
	tailscaleSocketPath         = ownedPrefix + "TAILSCALE_SOCKET_PATH"
	advertiseRoutes             = ownedPrefix + "ADVERTISE_ROUTES"
	advertiseExitNode           = ownedPrefix + "ADVERTISE_EXIT_NODE"
	preferenceAuditInterval     = ownedPrefix + "PREFERENCE_AUDIT_INTERVAL"
	tailscaleOperationTimeout   = ownedPrefix + "TAILSCALE_OPERATION_TIMEOUT"
	capabilityProbeIPv4URL      = ownedPrefix + "CAPABILITY_PROBE_IPV4_URL"
	capabilityProbeIPv6URL      = ownedPrefix + "CAPABILITY_PROBE_IPV6_URL"
	capabilityProbeInterval     = ownedPrefix + "CAPABILITY_PROBE_INTERVAL"
	capabilityProbeTimeout      = ownedPrefix + "CAPABILITY_PROBE_TIMEOUT"
	capabilityProbeValidity     = ownedPrefix + "CAPABILITY_PROBE_VALIDITY"
	capabilitySuccessThreshold  = ownedPrefix + "CAPABILITY_PROBE_SUCCESS_THRESHOLD"
	capabilityFailureThreshold  = ownedPrefix + "CAPABILITY_PROBE_FAILURE_THRESHOLD"
	auditInterval               = ownedPrefix + "AUDIT_INTERVAL"
	reconcileTimeout            = ownedPrefix + "RECONCILE_TIMEOUT"
	eventDebounce               = ownedPrefix + "EVENT_DEBOUNCE"
	readinessMaximumAge         = ownedPrefix + "READINESS_MAXIMUM_AGE"
	dnsLookupTimeout            = ownedPrefix + "DNS_LOOKUP_TIMEOUT"
	shutdownTimeout             = ownedPrefix + "SHUTDOWN_TIMEOUT"
	healthListenAddress         = ownedPrefix + "HEALTH_LISTEN_ADDRESS"
	resolverPath                = ownedPrefix + "RESOLVER_PATH"
	logLevel                    = ownedPrefix + "LOG_LEVEL"
	coordinationBackend         = ownedPrefix + "COORDINATION_BACKEND"
	coordinationResourceName    = ownedPrefix + "COORDINATION_RESOURCE_NAME"
	coordinationNamespacePath   = ownedPrefix + "COORDINATION_NAMESPACE_PATH"
	coordinationLockFile        = ownedPrefix + "COORDINATION_LOCK_FILE"
	coordinationLeaseDuration   = ownedPrefix + "COORDINATION_LEASE_DURATION"
	coordinationRenewDeadline   = ownedPrefix + "COORDINATION_RENEW_DEADLINE"
	coordinationRetryPeriod     = ownedPrefix + "COORDINATION_RETRY_PERIOD"
	coordinationAcquireTimeout  = ownedPrefix + "COORDINATION_ACQUIRE_TIMEOUT"
)

var knownVariables = map[string]struct{}{
	configAPIVersion: {}, proxyTunnelAddresses: {}, tailnetIPv4Prefix: {}, tailnetIPv6Prefix: {},
	exitRouteTable: {}, exitRulePriority: {}, localEgressRouteTable: {}, localEgressRulePriority: {},
	localEgressPacketMark: {}, activeRouteMetric: {}, failClosedRouteMetric: {}, nftablesFilterTable: {}, nftablesForwardGuardChain: {},
	nftablesLocalEgressChain: {}, nftablesLocalEgressIPv4Set: {}, nftablesLocalEgressIPv6Set: {},
	nftablesNATTable: {}, nftablesDNSSNATChain: {}, localEgressEnabled: {}, localEgressDomains: {},
	localEgressProtocols: {}, localEgressPorts: {}, localEgressRefreshInterval: {}, localEgressMaximumStaleness: {},
	tailscaleSocketPath: {}, advertiseRoutes: {}, advertiseExitNode: {}, preferenceAuditInterval: {},
	tailscaleOperationTimeout: {}, auditInterval: {}, reconcileTimeout: {}, eventDebounce: {}, readinessMaximumAge: {}, dnsLookupTimeout: {},
	capabilityProbeIPv4URL: {}, capabilityProbeIPv6URL: {}, capabilityProbeInterval: {}, capabilityProbeTimeout: {},
	capabilityProbeValidity: {}, capabilitySuccessThreshold: {}, capabilityFailureThreshold: {},
	shutdownTimeout: {}, healthListenAddress: {}, resolverPath: {}, logLevel: {}, coordinationBackend: {},
	coordinationResourceName: {}, coordinationNamespacePath: {}, coordinationLockFile: {}, coordinationLeaseDuration: {},
	coordinationRenewDeadline: {}, coordinationRetryPeriod: {}, coordinationAcquireTimeout: {},
}

var containerbootVariables = map[string]struct{}{
	"HOME": {}, "HOSTNAME": {}, "PATH": {}, "TZ": {},
	"SSL_CERT_FILE": {}, "SSL_CERT_DIR": {},
	"HTTP_PROXY": {}, "HTTPS_PROXY": {}, "NO_PROXY": {}, "ALL_PROXY": {},
	"http_proxy": {}, "https_proxy": {}, "no_proxy": {}, "all_proxy": {},
	"KUBERNETES_SERVICE_HOST": {}, "KUBERNETES_SERVICE_PORT": {}, "KUBERNETES_SERVICE_PORT_HTTPS": {},
	"TS_ACCEPT_DNS": {}, "TS_AUTHKEY": {}, "TS_AUTH_ONCE": {}, "TS_ENABLE_HEALTH_CHECK": {},
	"TS_HOSTNAME": {}, "TS_KUBE_SECRET": {}, "TS_LOCAL_ADDR_PORT": {}, "TS_SOCKET": {},
	"TS_TAILSCALED_EXTRA_ARGS": {}, "TS_EXTRA_ARGS": {}, "TS_USERSPACE": {},
}

func Load() (domain.Configuration, error) {
	return load(os.Environ())
}

func load(entries []string) (domain.Configuration, error) {
	values, environmentErrors := environmentMap(entries)
	configuration := domain.DefaultConfiguration()
	var parseErrors []error
	parseErrors = append(parseErrors, environmentErrors...)
	parseErrors = append(parseErrors, validateTailscaleOwnership(values)...)

	stringValue(values, configAPIVersion, &configuration.APIVersion)
	prefixListValue(values, proxyTunnelAddresses, &configuration.Network.ProxyTunnelAddresses, &parseErrors)
	prefixValue(values, tailnetIPv4Prefix, &configuration.Network.TailnetIPv4Prefix, &parseErrors)
	prefixValue(values, tailnetIPv6Prefix, &configuration.Network.TailnetIPv6Prefix, &parseErrors)
	intValue(values, exitRouteTable, &configuration.Network.ExitRouteTable, &parseErrors)
	intValue(values, exitRulePriority, &configuration.Network.ExitRulePriority, &parseErrors)
	intValue(values, localEgressRouteTable, &configuration.Network.LocalEgressRouteTable, &parseErrors)
	intValue(values, localEgressRulePriority, &configuration.Network.LocalEgressRulePriority, &parseErrors)
	uint32Value(values, localEgressPacketMark, &configuration.Network.LocalEgressPacketMark, &parseErrors)
	intValue(values, activeRouteMetric, &configuration.Network.ActiveRouteMetric, &parseErrors)
	intValue(values, failClosedRouteMetric, &configuration.Network.FailClosedRouteMetric, &parseErrors)

	stringValue(values, nftablesFilterTable, &configuration.PacketFilter.FilterTable)
	stringValue(values, nftablesForwardGuardChain, &configuration.PacketFilter.ForwardGuardChain)
	stringValue(values, nftablesLocalEgressChain, &configuration.PacketFilter.LocalEgressChain)
	stringValue(values, nftablesLocalEgressIPv4Set, &configuration.PacketFilter.LocalEgressIPv4Set)
	stringValue(values, nftablesLocalEgressIPv6Set, &configuration.PacketFilter.LocalEgressIPv6Set)
	stringValue(values, nftablesNATTable, &configuration.PacketFilter.NATTable)
	stringValue(values, nftablesDNSSNATChain, &configuration.PacketFilter.DNSMasqueradeChain)
	boolValue(values, localEgressEnabled, &configuration.PacketFilter.LocalEgress.Enabled, &parseErrors)
	stringListValue(values, localEgressDomains, &configuration.PacketFilter.LocalEgress.Domains, &parseErrors)
	protocolListValue(values, localEgressProtocols, &configuration.PacketFilter.LocalEgress.Protocols, &parseErrors)
	portListValue(values, localEgressPorts, &configuration.PacketFilter.LocalEgress.Ports, &parseErrors)
	durationValue(values, localEgressRefreshInterval, &configuration.PacketFilter.LocalEgress.RefreshInterval, &parseErrors)
	durationValue(values, localEgressMaximumStaleness, &configuration.PacketFilter.LocalEgress.MaximumStaleness, &parseErrors)

	stringValue(values, tailscaleSocketPath, &configuration.Tailnet.SocketPath)
	prefixListValue(values, advertiseRoutes, &configuration.Tailnet.AdvertiseRoutes, &parseErrors)
	boolValue(values, advertiseExitNode, &configuration.Tailnet.AdvertiseExitNode, &parseErrors)
	durationValue(values, preferenceAuditInterval, &configuration.Tailnet.PreferenceAuditInterval, &parseErrors)
	durationValue(values, tailscaleOperationTimeout, &configuration.Tailnet.OperationTimeout, &parseErrors)

	stringValue(values, capabilityProbeIPv4URL, &configuration.InternetCapability.IPv4ProbeURL)
	stringValue(values, capabilityProbeIPv6URL, &configuration.InternetCapability.IPv6ProbeURL)
	durationValue(values, capabilityProbeInterval, &configuration.InternetCapability.ProbeInterval, &parseErrors)
	durationValue(values, capabilityProbeTimeout, &configuration.InternetCapability.ProbeTimeout, &parseErrors)
	durationValue(values, capabilityProbeValidity, &configuration.InternetCapability.ProbeValidity, &parseErrors)
	uint32Value(values, capabilitySuccessThreshold, &configuration.InternetCapability.SuccessThreshold, &parseErrors)
	uint32Value(values, capabilityFailureThreshold, &configuration.InternetCapability.FailureThreshold, &parseErrors)
	if !configuration.Tailnet.AdvertiseExitNode {
		for _, name := range []string{capabilityProbeIPv4URL, capabilityProbeIPv6URL} {
			if _, exists := values[name]; exists {
				parseErrors = append(parseErrors, fmt.Errorf("%s must be absent when Exit advertisement is disabled", name))
			}
		}
	}

	durationValue(values, auditInterval, &configuration.Runtime.AuditInterval, &parseErrors)
	durationValue(values, reconcileTimeout, &configuration.Runtime.ReconcileTimeout, &parseErrors)
	durationValue(values, eventDebounce, &configuration.Runtime.EventDebounce, &parseErrors)
	durationValue(values, readinessMaximumAge, &configuration.Runtime.ReadinessMaximumAge, &parseErrors)
	durationValue(values, dnsLookupTimeout, &configuration.Runtime.DNSLookupTimeout, &parseErrors)
	durationValue(values, shutdownTimeout, &configuration.Runtime.ShutdownTimeout, &parseErrors)
	stringValue(values, healthListenAddress, &configuration.Runtime.HealthListenAddress)
	stringValue(values, resolverPath, &configuration.Runtime.ResolverPath)
	stringValue(values, logLevel, &configuration.Runtime.LogLevel)
	configuration.Runtime.LogLevel = strings.ToLower(configuration.Runtime.LogLevel)

	backend := string(configuration.Coordination.Backend)
	stringValue(values, coordinationBackend, &backend)
	configuration.Coordination.Backend = domain.CoordinationBackend(strings.ToLower(backend))
	stringValue(values, coordinationResourceName, &configuration.Coordination.ResourceName)
	stringValue(values, coordinationNamespacePath, &configuration.Coordination.NamespacePath)
	stringValue(values, coordinationLockFile, &configuration.Coordination.LockFile)
	durationValue(values, coordinationLeaseDuration, &configuration.Coordination.LeaseDuration, &parseErrors)
	durationValue(values, coordinationRenewDeadline, &configuration.Coordination.RenewDeadline, &parseErrors)
	durationValue(values, coordinationRetryPeriod, &configuration.Coordination.RetryPeriod, &parseErrors)
	durationValue(values, coordinationAcquireTimeout, &configuration.Coordination.AcquireTimeout, &parseErrors)

	if validationErr := configuration.Validate(); validationErr != nil {
		parseErrors = append(parseErrors, validationErr)
	}
	return configuration, errors.Join(parseErrors...)
}

func ContainerbootEnvironment() ([]string, error) {
	return containerbootEnvironment(os.Environ())
}

func containerbootEnvironment(entries []string) ([]string, error) {
	values, environmentErrors := environmentMap(entries)
	var validationErrors []error
	validationErrors = append(validationErrors, environmentErrors...)
	validationErrors = append(validationErrors, validateTailscaleOwnership(values)...)
	var unsupported []string
	for name := range values {
		if strings.HasPrefix(name, "TS_") && name != "TS_ROUTES" && !allowedContainerbootVariable(name) {
			unsupported = append(unsupported, name)
		}
	}
	slices.Sort(unsupported)
	for _, name := range unsupported {
		validationErrors = append(validationErrors, fmt.Errorf("unsupported containerboot environment variable %s", name))
	}
	if err := errors.Join(validationErrors...); err != nil {
		return nil, err
	}
	allowed := make([]string, 0, len(values))
	for name, value := range values {
		if allowedContainerbootVariable(name) {
			allowed = append(allowed, name+"="+value)
		}
	}
	slices.Sort(allowed)
	return allowed, nil
}

func environmentMap(entries []string) (map[string]string, []error) {
	values := make(map[string]string, len(entries))
	var environmentErrors []error
	for index, entry := range entries {
		name, value, found := strings.Cut(entry, "=")
		if !found || name == "" {
			environmentErrors = append(environmentErrors, fmt.Errorf("environment entry at index %d is invalid", index))
			continue
		}
		if _, duplicate := values[name]; duplicate {
			environmentErrors = append(environmentErrors, fmt.Errorf("environment variable %s is defined more than once", name))
			continue
		}
		values[name] = value
	}
	var unknown []string
	for name := range values {
		if strings.HasPrefix(name, ownedPrefix) {
			if _, known := knownVariables[name]; !known {
				unknown = append(unknown, name)
			}
		}
	}
	slices.Sort(unknown)
	for _, name := range unknown {
		environmentErrors = append(environmentErrors, fmt.Errorf("unknown Agent environment variable %s", name))
	}
	return values, environmentErrors
}

func stringValue(values map[string]string, name string, target *string) {
	if value, exists := values[name]; exists {
		*target = strings.TrimSpace(value)
	}
}

func boolValue(values map[string]string, name string, target *bool, parseErrors *[]error) {
	value, exists := values[name]
	if !exists {
		return
	}
	// Keep this parser deliberately narrower than strconv.ParseBool. The v1
	// configuration API must not assign boolean meaning to numeric values.
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true":
		*target = true
	case "false":
		*target = false
	default:
		*parseErrors = append(*parseErrors, fmt.Errorf("%s must be true or false", name))
	}
}

func intValue(values map[string]string, name string, target *int, parseErrors *[]error) {
	value, exists := values[name]
	if !exists {
		return
	}
	parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 32)
	if err != nil {
		*parseErrors = append(*parseErrors, fmt.Errorf("%s must be a base-10 integer: %w", name, err))
		return
	}
	*target = int(parsed)
}

func uint32Value(values map[string]string, name string, target *uint32, parseErrors *[]error) {
	value, exists := values[name]
	if !exists {
		return
	}
	value = strings.TrimSpace(value)
	base := 10
	digits := value
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		base = 16
		digits = value[2:]
	}
	if digits == "" || strings.HasPrefix(digits, "+") || strings.HasPrefix(digits, "-") {
		*parseErrors = append(*parseErrors, fmt.Errorf("%s must be a 32-bit decimal or 0x-prefixed hexadecimal integer", name))
		return
	}
	parsed, err := strconv.ParseUint(digits, base, 32)
	if err != nil {
		*parseErrors = append(*parseErrors, fmt.Errorf("%s must be a 32-bit decimal or 0x-prefixed hexadecimal integer: %w", name, err))
		return
	}
	*target = uint32(parsed)
}

func durationValue(values map[string]string, name string, target *time.Duration, parseErrors *[]error) {
	value, exists := values[name]
	if !exists {
		return
	}
	parsed, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil {
		*parseErrors = append(*parseErrors, fmt.Errorf("%s must be a Go duration: %w", name, err))
		return
	}
	*target = parsed
}

func prefixValue(values map[string]string, name string, target *netip.Prefix, parseErrors *[]error) {
	value, exists := values[name]
	if !exists {
		return
	}
	parsed, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil {
		*parseErrors = append(*parseErrors, fmt.Errorf("%s must be an IP prefix: %w", name, err))
		return
	}
	*target = parsed
}

func prefixListValue(values map[string]string, name string, target *[]netip.Prefix, parseErrors *[]error) {
	value, exists := values[name]
	if !exists {
		return
	}
	items := splitList(value, name, parseErrors)
	result := make([]netip.Prefix, 0, len(items))
	for _, item := range items {
		prefix, err := netip.ParsePrefix(item)
		if err != nil {
			*parseErrors = append(*parseErrors, fmt.Errorf("%s contains invalid prefix %q: %w", name, item, err))
			continue
		}
		result = append(result, prefix)
	}
	slices.SortFunc(result, func(left, right netip.Prefix) int {
		if comparison := left.Addr().Compare(right.Addr()); comparison != 0 {
			return comparison
		}
		return left.Bits() - right.Bits()
	})
	*target = result
}

func stringListValue(values map[string]string, name string, target *[]string, parseErrors *[]error) {
	if value, exists := values[name]; exists {
		*target = splitList(strings.ToLower(value), name, parseErrors)
	}
}

func protocolListValue(values map[string]string, name string, target *[]domain.TransportProtocol, parseErrors *[]error) {
	if value, exists := values[name]; exists {
		items := splitList(strings.ToLower(value), name, parseErrors)
		result := make([]domain.TransportProtocol, 0, len(items))
		for _, item := range items {
			result = append(result, domain.TransportProtocol(item))
		}
		*target = result
	}
}

func portListValue(values map[string]string, name string, target *[]uint16, parseErrors *[]error) {
	value, exists := values[name]
	if !exists {
		return
	}
	items := splitList(value, name, parseErrors)
	result := make([]uint16, 0, len(items))
	for _, item := range items {
		port, err := strconv.ParseUint(item, 10, 16)
		if err != nil || port == 0 {
			*parseErrors = append(*parseErrors, fmt.Errorf("%s contains invalid port %q", name, item))
			continue
		}
		result = append(result, uint16(port))
	}
	slices.Sort(result)
	*target = result
}

func splitList(value, name string, parseErrors *[]error) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	var result []string
	for index, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item == "" {
			*parseErrors = append(*parseErrors, fmt.Errorf("%s contains an empty item at position %d", name, index+1))
		} else {
			result = append(result, item)
		}
	}
	slices.Sort(result)
	return result
}

func containsAdvertisementArgument(value string) bool {
	return strings.Contains(value, "--advertise-exit-node") || strings.Contains(value, "--advertise-routes")
}

func validateTailscaleOwnership(values map[string]string) []error {
	var validationErrors []error
	if _, exists := values["TS_ROUTES"]; exists {
		validationErrors = append(validationErrors, errors.New("TS_ROUTES must be absent because the Agent exclusively owns AdvertiseRoutes"))
	}
	for _, name := range []string{"TS_EXTRA_ARGS", "TS_TAILSCALED_EXTRA_ARGS"} {
		if containsAdvertisementArgument(values[name]) {
			validationErrors = append(validationErrors, fmt.Errorf("%s must not configure route or exit-node advertisements", name))
		}
	}
	return validationErrors
}

func allowedContainerbootVariable(name string) bool {
	_, allowed := containerbootVariables[name]
	return allowed
}
