package domain

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	ConfigurationAPIVersionV1 = "v1"
	maximumNetlinkInteger     = 2_147_483_647
)

var (
	nftIdentifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	dns1123LabelPattern  = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
)

type Configuration struct {
	APIVersion         string
	Network            NetworkConfiguration
	PacketFilter       PacketFilterConfiguration
	Tailnet            TailnetConfiguration
	InternetCapability InternetCapabilityConfiguration
	Runtime            RuntimeConfiguration
	Coordination       CoordinationConfiguration
}

type NetworkConfiguration struct {
	ProxyTunnelAddresses    []netip.Prefix
	TailnetIPv4Prefix       netip.Prefix
	TailnetIPv6Prefix       netip.Prefix
	ExitRouteTable          int
	ExitRulePriority        int
	LocalEgressRouteTable   int
	LocalEgressRulePriority int
	LocalEgressPacketMark   uint32
	ActiveRouteMetric       int
	FailClosedRouteMetric   int
}

type PacketFilterConfiguration struct {
	FilterTable        string
	ForwardGuardChain  string
	LocalEgressChain   string
	LocalEgressIPv4Set string
	LocalEgressIPv6Set string
	NATTable           string
	DNSMasqueradeChain string
	LocalEgress        LocalEgressConfiguration
}

type LocalEgressConfiguration struct {
	Enabled          bool
	Domains          []string
	Protocols        []TransportProtocol
	Ports            []uint16
	RefreshInterval  time.Duration
	MaximumStaleness time.Duration
}

type TailnetConfiguration struct {
	SocketPath              string
	AdvertiseRoutes         []netip.Prefix
	AdvertiseExitNode       bool
	PreferenceAuditInterval time.Duration
	OperationTimeout        time.Duration
}

type InternetCapabilityConfiguration struct {
	IPv4ProbeURL     string
	IPv6ProbeURL     string
	ProbeInterval    time.Duration
	ProbeTimeout     time.Duration
	ProbeValidity    time.Duration
	SuccessThreshold uint32
	FailureThreshold uint32
}

type RuntimeConfiguration struct {
	AuditInterval       time.Duration
	ReconcileTimeout    time.Duration
	EventDebounce       time.Duration
	ReadinessMaximumAge time.Duration
	DNSLookupTimeout    time.Duration
	ShutdownTimeout     time.Duration
	HealthListenAddress string
	ResolverPath        string
	LogLevel            string
}

type CoordinationBackend string

const (
	CoordinationKubernetesLease CoordinationBackend = "kubernetes-lease"
	CoordinationFileLock        CoordinationBackend = "file-lock"
)

type CoordinationConfiguration struct {
	Backend        CoordinationBackend
	ResourceName   string
	NamespacePath  string
	LockFile       string
	LeaseDuration  time.Duration
	RenewDeadline  time.Duration
	RetryPeriod    time.Duration
	AcquireTimeout time.Duration
}

func DefaultConfiguration() Configuration {
	return Configuration{
		APIVersion: ConfigurationAPIVersionV1,
		Network: NetworkConfiguration{
			TailnetIPv4Prefix:       netip.MustParsePrefix("100.64.0.0/10"),
			TailnetIPv6Prefix:       netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
			ExitRouteTable:          100,
			ExitRulePriority:        99,
			LocalEgressRouteTable:   101,
			LocalEgressRulePriority: 90,
			LocalEgressPacketMark:   0x11,
			ActiveRouteMetric:       100,
			FailClosedRouteMetric:   32_760,
		},
		PacketFilter: PacketFilterConfiguration{
			FilterTable:        "tailscale_gateway",
			ForwardGuardChain:  "tailnet_forward_guard",
			LocalEgressChain:   "local_egress_proxy_output",
			LocalEgressIPv4Set: "local_egress_ipv4",
			LocalEgressIPv6Set: "local_egress_ipv6",
			NATTable:           "tailscale_gateway_nat",
			DNSMasqueradeChain: "cluster_dns_masquerade",
			LocalEgress: LocalEgressConfiguration{
				Protocols:        []TransportProtocol{TransportTCP},
				Ports:            []uint16{443},
				RefreshInterval:  5 * time.Minute,
				MaximumStaleness: time.Hour,
			},
		},
		Tailnet: TailnetConfiguration{
			SocketPath:              "/var/run/tailscale/tailscaled.sock",
			PreferenceAuditInterval: 30 * time.Second,
			OperationTimeout:        20 * time.Second,
		},
		InternetCapability: InternetCapabilityConfiguration{
			ProbeInterval: 30 * time.Second, ProbeTimeout: 5 * time.Second, ProbeValidity: 2 * time.Minute,
			SuccessThreshold: 2, FailureThreshold: 2,
		},
		Runtime: RuntimeConfiguration{
			AuditInterval:       5 * time.Minute,
			ReconcileTimeout:    2 * time.Minute,
			EventDebounce:       500 * time.Millisecond,
			ReadinessMaximumAge: 10 * time.Minute,
			DNSLookupTimeout:    10 * time.Second,
			ShutdownTimeout:     30 * time.Second,
			HealthListenAddress: "127.0.0.1:8080",
			ResolverPath:        "/etc/resolv.conf",
			LogLevel:            "info",
		},
		Coordination: CoordinationConfiguration{
			ResourceName:   "tailscale-gateway-identity",
			NamespacePath:  "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
			LockFile:       "/run/tailscale-gateway-agent.lock",
			LeaseDuration:  90 * time.Second,
			RenewDeadline:  45 * time.Second,
			RetryPeriod:    2 * time.Second,
			AcquireTimeout: 5 * time.Minute,
		},
	}
}

func (configuration Configuration) Validate() error {
	var validationErrors []error
	appendError := func(err error) {
		if err != nil {
			validationErrors = append(validationErrors, err)
		}
	}

	if configuration.APIVersion != ConfigurationAPIVersionV1 {
		appendError(fmt.Errorf("unsupported configuration API version %q", configuration.APIVersion))
	}
	appendError(validateNetworkConfiguration(configuration.Network))
	appendError(validatePacketFilterConfiguration(configuration.PacketFilter, configuration.Network))
	appendError(validateTailnetConfiguration(configuration.Tailnet, configuration.Network))
	appendError(validateInternetCapabilityConfiguration(configuration.InternetCapability, configuration.Tailnet, configuration.Runtime))
	appendError(validateRuntimeConfiguration(configuration.Runtime))
	appendError(validateCoordinationConfiguration(configuration.Coordination))
	if configuration.Tailnet.OperationTimeout >= configuration.Runtime.ReconcileTimeout {
		appendError(errors.New("tailscale operation timeout must be shorter than the reconcile timeout"))
	}

	return errors.Join(validationErrors...)
}

func validateInternetCapabilityConfiguration(configuration InternetCapabilityConfiguration, tailnet TailnetConfiguration, runtime RuntimeConfiguration) error {
	var validationErrors []error
	if tailnet.AdvertiseExitNode {
		if configuration.IPv4ProbeURL == "" {
			validationErrors = append(validationErrors, errors.New("ipv4 capability probe URL is required when Exit advertisement is enabled"))
		}
		if configuration.IPv6ProbeURL == "" {
			validationErrors = append(validationErrors, errors.New("ipv6 capability probe URL is required when Exit advertisement is enabled"))
		}
	} else if configuration.IPv4ProbeURL != "" || configuration.IPv6ProbeURL != "" {
		validationErrors = append(validationErrors, errors.New("capability probe URLs require Exit advertisement to be enabled"))
	}
	if configuration.ProbeInterval < 10*time.Second {
		validationErrors = append(validationErrors, errors.New("capability probe interval must be at least 10 seconds"))
	}
	if configuration.ProbeTimeout <= 0 || configuration.ProbeTimeout >= configuration.ProbeInterval {
		validationErrors = append(validationErrors, errors.New("capability probe timeout must be positive and shorter than its interval"))
	}
	if configuration.ProbeTimeout >= runtime.ReconcileTimeout {
		validationErrors = append(validationErrors, errors.New("capability probe timeout must be shorter than the reconcile timeout"))
	}
	if configuration.ProbeValidity <= configuration.ProbeInterval || configuration.ProbeValidity > runtime.ReadinessMaximumAge {
		validationErrors = append(validationErrors, errors.New("capability probe validity must exceed its interval and not exceed readiness maximum age"))
	}
	if configuration.SuccessThreshold < 1 || configuration.SuccessThreshold > 16 {
		validationErrors = append(validationErrors, errors.New("capability probe success threshold must be within 1..16"))
	}
	if configuration.FailureThreshold < 1 || configuration.FailureThreshold > 16 {
		validationErrors = append(validationErrors, errors.New("capability probe failure threshold must be within 1..16"))
	}
	return errors.Join(validationErrors...)
}

func validateNetworkConfiguration(configuration NetworkConfiguration) error {
	var validationErrors []error
	if len(configuration.ProxyTunnelAddresses) == 0 {
		validationErrors = append(validationErrors, errors.New("at least one proxy tunnel address is required"))
	}
	seenFamilies := map[AddressFamily]bool{}
	seenAddresses := map[netip.Addr]bool{}
	for _, prefix := range configuration.ProxyTunnelAddresses {
		if !validInterfaceAddressPrefix(prefix) {
			validationErrors = append(validationErrors, fmt.Errorf("proxy tunnel address %q is invalid", prefix))
			continue
		}
		address := prefix.Addr().Unmap()
		if seenAddresses[address] {
			validationErrors = append(validationErrors, fmt.Errorf("proxy tunnel address %s is duplicated", address))
		}
		seenAddresses[address] = true
		seenFamilies[FamilyOfAddress(address)] = true
		if configuration.TailnetIPv4Prefix.Contains(address) || configuration.TailnetIPv6Prefix.Contains(address) {
			validationErrors = append(validationErrors, fmt.Errorf("proxy tunnel address %s overlaps a Tailnet prefix", address))
		}
	}
	if !seenFamilies[IPv4] || !seenFamilies[IPv6] {
		validationErrors = append(validationErrors, errors.New("proxy tunnel addresses must include IPv4 and IPv6"))
	}
	if !validMaskedPrefix(configuration.TailnetIPv4Prefix, IPv4) {
		validationErrors = append(validationErrors, fmt.Errorf("tailnet IPv4 prefix %q must be a masked IPv4 prefix", configuration.TailnetIPv4Prefix))
	}
	if !validMaskedPrefix(configuration.TailnetIPv6Prefix, IPv6) {
		validationErrors = append(validationErrors, fmt.Errorf("tailnet IPv6 prefix %q must be a masked IPv6 prefix", configuration.TailnetIPv6Prefix))
	}
	for _, item := range []struct {
		name     string
		table    int
		priority int
	}{
		{name: "exit", table: configuration.ExitRouteTable, priority: configuration.ExitRulePriority},
		{name: "local egress", table: configuration.LocalEgressRouteTable, priority: configuration.LocalEgressRulePriority},
	} {
		if item.table < 1 || item.table > maximumNetlinkInteger {
			validationErrors = append(validationErrors, fmt.Errorf("%s route table %d is outside 1..2147483647", item.name, item.table))
		}
		if item.table == 253 || item.table == 254 || item.table == 255 {
			validationErrors = append(validationErrors, fmt.Errorf("%s route table %d is reserved by Linux", item.name, item.table))
		}
		if item.priority < 1 || item.priority > 32_765 {
			validationErrors = append(validationErrors, fmt.Errorf("%s rule priority %d is outside 1..32765", item.name, item.priority))
		}
	}
	if configuration.ExitRouteTable == configuration.LocalEgressRouteTable {
		validationErrors = append(validationErrors, errors.New("exit and local-egress route tables must differ"))
	}
	if configuration.ExitRulePriority == configuration.LocalEgressRulePriority {
		validationErrors = append(validationErrors, errors.New("exit and local-egress rule priorities must differ"))
	}
	if configuration.LocalEgressPacketMark == 0 {
		validationErrors = append(validationErrors, errors.New("local-egress packet mark must be non-zero"))
	}
	// Tailscale owns the third mark byte on Linux. Restricting this Agent to the
	// low 16 bits makes the ownership domains disjoint for every configured value.
	if configuration.LocalEgressPacketMark&^LocalEgressPacketMarkMask != 0 {
		validationErrors = append(validationErrors, errors.New("local-egress packet mark must be within the low 16 bits"))
	}
	if configuration.ActiveRouteMetric < 1 || configuration.ActiveRouteMetric > maximumNetlinkInteger {
		validationErrors = append(validationErrors, errors.New("active route metric must be within 1..2147483647"))
	}
	if configuration.FailClosedRouteMetric < 1 || configuration.FailClosedRouteMetric > maximumNetlinkInteger {
		validationErrors = append(validationErrors, errors.New("fail-closed route metric must be within 1..2147483647"))
	}
	if configuration.ActiveRouteMetric >= configuration.FailClosedRouteMetric {
		validationErrors = append(validationErrors, errors.New("active route metric must be lower than the fail-closed route metric"))
	}
	return errors.Join(validationErrors...)
}

func validatePacketFilterConfiguration(configuration PacketFilterConfiguration, network NetworkConfiguration) error {
	var validationErrors []error
	identifiers := []struct {
		name  string
		value string
	}{
		{name: "filter table", value: configuration.FilterTable},
		{name: "forward guard chain", value: configuration.ForwardGuardChain},
		{name: "local-egress chain", value: configuration.LocalEgressChain},
		{name: "local-egress IPv4 set", value: configuration.LocalEgressIPv4Set},
		{name: "local-egress IPv6 set", value: configuration.LocalEgressIPv6Set},
		{name: "NAT table", value: configuration.NATTable},
		{name: "DNS masquerade chain", value: configuration.DNSMasqueradeChain},
	}
	seen := map[string]string{ReservedPacketFilterMetadataChain: "reserved metadata chain"}
	for _, item := range identifiers {
		if !nftIdentifierPattern.MatchString(item.value) {
			validationErrors = append(validationErrors, fmt.Errorf("%s %q is not a valid nftables identifier", item.name, item.value))
		}
		if previous, exists := seen[item.value]; exists {
			validationErrors = append(validationErrors, fmt.Errorf("%s and %s must use distinct nftables identifiers", previous, item.name))
		}
		seen[item.value] = item.name
	}
	local := configuration.LocalEgress
	if local.Enabled {
		if len(local.Domains) == 0 {
			validationErrors = append(validationErrors, errors.New("local-egress domains are required when enabled"))
		}
		if len(local.Protocols) == 0 {
			validationErrors = append(validationErrors, errors.New("local-egress protocols are required when enabled"))
		}
		if len(local.Ports) == 0 {
			validationErrors = append(validationErrors, errors.New("local-egress ports are required when enabled"))
		}
		if network.LocalEgressPacketMark == 0 {
			validationErrors = append(validationErrors, errors.New("local-egress mark is required when enabled"))
		}
	}
	if len(local.Domains) > 64 || len(local.Ports) > 64 {
		validationErrors = append(validationErrors, errors.New("local-egress domains and ports must not exceed 64 entries each"))
	}
	seenDomains := make(map[string]struct{}, len(local.Domains))
	for _, domainName := range local.Domains {
		if !validDomainName(domainName) {
			validationErrors = append(validationErrors, fmt.Errorf("local-egress domain %q is invalid", domainName))
		}
		if _, duplicate := seenDomains[domainName]; duplicate {
			validationErrors = append(validationErrors, fmt.Errorf("local-egress domain %q is duplicated", domainName))
		}
		seenDomains[domainName] = struct{}{}
	}
	seenProtocols := make(map[TransportProtocol]struct{}, len(local.Protocols))
	for _, protocol := range local.Protocols {
		if protocol != TransportTCP && protocol != TransportUDP {
			validationErrors = append(validationErrors, fmt.Errorf("local-egress protocol %q is unsupported", protocol))
		}
		if _, duplicate := seenProtocols[protocol]; duplicate {
			validationErrors = append(validationErrors, fmt.Errorf("local-egress protocol %q is duplicated", protocol))
		}
		seenProtocols[protocol] = struct{}{}
	}
	seenPorts := make(map[uint16]struct{}, len(local.Ports))
	for _, port := range local.Ports {
		if port == 0 {
			validationErrors = append(validationErrors, errors.New("local-egress port must be non-zero"))
		}
		if _, duplicate := seenPorts[port]; duplicate {
			validationErrors = append(validationErrors, fmt.Errorf("local-egress port %d is duplicated", port))
		}
		seenPorts[port] = struct{}{}
	}
	if local.RefreshInterval < 30*time.Second {
		validationErrors = append(validationErrors, errors.New("local-egress refresh interval must be at least 30 seconds"))
	}
	if local.MaximumStaleness <= local.RefreshInterval {
		validationErrors = append(validationErrors, errors.New("local-egress maximum staleness must exceed its refresh interval"))
	}
	return errors.Join(validationErrors...)
}

func validateTailnetConfiguration(configuration TailnetConfiguration, network NetworkConfiguration) error {
	var validationErrors []error
	if !validLinuxAbsolutePath(configuration.SocketPath) {
		validationErrors = append(validationErrors, fmt.Errorf("tailscale socket path %q must be a clean absolute path", configuration.SocketPath))
	}
	seenPrefixes := make(map[netip.Prefix]struct{}, len(configuration.AdvertiseRoutes))
	for index, prefix := range configuration.AdvertiseRoutes {
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Bits() == 0 {
			validationErrors = append(validationErrors, fmt.Errorf("advertised route %q must be a masked non-default prefix", prefix))
			continue
		}
		if _, duplicate := seenPrefixes[prefix]; duplicate {
			validationErrors = append(validationErrors, fmt.Errorf("advertised route %s is duplicated", prefix))
		}
		seenPrefixes[prefix] = struct{}{}
		if prefixesOverlap(prefix, network.TailnetIPv4Prefix) || prefixesOverlap(prefix, network.TailnetIPv6Prefix) {
			validationErrors = append(validationErrors, fmt.Errorf("advertised route %s overlaps a Tailnet prefix", prefix))
		}
		for _, tunnelAddress := range network.ProxyTunnelAddresses {
			if prefixesOverlap(prefix, tunnelAddress.Masked()) {
				validationErrors = append(validationErrors, fmt.Errorf("advertised route %s overlaps proxy tunnel prefix %s", prefix, tunnelAddress.Masked()))
			}
		}
		for _, previous := range configuration.AdvertiseRoutes[:index] {
			if prefix != previous && prefixesOverlap(prefix, previous) {
				validationErrors = append(validationErrors, fmt.Errorf("advertised routes %s and %s overlap", previous, prefix))
			}
		}
	}
	if configuration.PreferenceAuditInterval < 30*time.Second {
		validationErrors = append(validationErrors, errors.New("tailscale preference audit interval must be at least 30 seconds"))
	}
	if configuration.OperationTimeout <= 0 {
		validationErrors = append(validationErrors, errors.New("tailscale operation timeout must be positive"))
	}
	return errors.Join(validationErrors...)
}

func validateRuntimeConfiguration(configuration RuntimeConfiguration) error {
	var validationErrors []error
	if configuration.AuditInterval < 30*time.Second {
		validationErrors = append(validationErrors, errors.New("audit interval must be at least 30 seconds"))
	}
	if configuration.ReconcileTimeout < 10*time.Second || configuration.ReconcileTimeout >= configuration.AuditInterval {
		validationErrors = append(validationErrors, errors.New("reconcile timeout must be at least 10 seconds and shorter than the audit interval"))
	}
	if configuration.EventDebounce < 100*time.Millisecond || configuration.EventDebounce > 10*time.Second {
		validationErrors = append(validationErrors, errors.New("event debounce must be within 100ms..10s"))
	}
	if configuration.ReadinessMaximumAge <= configuration.AuditInterval {
		validationErrors = append(validationErrors, errors.New("readiness maximum age must exceed the audit interval"))
	}
	if configuration.DNSLookupTimeout <= 0 || configuration.ShutdownTimeout <= 0 {
		validationErrors = append(validationErrors, errors.New("DNS lookup and shutdown timeouts must be positive"))
	}
	if configuration.DNSLookupTimeout >= configuration.ReconcileTimeout {
		validationErrors = append(validationErrors, errors.New("DNS lookup timeout must be shorter than the reconcile timeout"))
	}
	_, healthPort, err := net.SplitHostPort(configuration.HealthListenAddress)
	if err != nil {
		validationErrors = append(validationErrors, fmt.Errorf("health listen address %q is invalid: %w", configuration.HealthListenAddress, err))
	} else if parsedPort, parseErr := strconv.ParseUint(healthPort, 10, 16); parseErr != nil || parsedPort == 0 {
		validationErrors = append(validationErrors, fmt.Errorf("health listen address %q must use a numeric port within 1..65535", configuration.HealthListenAddress))
	}
	if !validLinuxAbsolutePath(configuration.ResolverPath) {
		validationErrors = append(validationErrors, fmt.Errorf("resolver path %q must be a clean absolute path", configuration.ResolverPath))
	}
	if !slices.Contains([]string{"debug", "info", "warn", "error"}, configuration.LogLevel) {
		validationErrors = append(validationErrors, fmt.Errorf("log level %q is unsupported", configuration.LogLevel))
	}
	return errors.Join(validationErrors...)
}

func validateCoordinationConfiguration(configuration CoordinationConfiguration) error {
	var validationErrors []error
	if configuration.Backend != CoordinationKubernetesLease && configuration.Backend != CoordinationFileLock {
		validationErrors = append(validationErrors, fmt.Errorf("coordination backend %q is unsupported", configuration.Backend))
	}
	if configuration.Backend == CoordinationKubernetesLease {
		if !validDNS1123Subdomain(configuration.ResourceName) {
			validationErrors = append(validationErrors, fmt.Errorf("coordination resource name %q is invalid", configuration.ResourceName))
		}
		if !validLinuxAbsolutePath(configuration.NamespacePath) {
			validationErrors = append(validationErrors, fmt.Errorf("coordination namespace path %q must be a clean absolute path", configuration.NamespacePath))
		}
		if configuration.LeaseDuration <= configuration.RenewDeadline || configuration.RenewDeadline <= configuration.RetryPeriod || configuration.RetryPeriod <= 0 {
			validationErrors = append(validationErrors, errors.New("kubernetes Lease timing must satisfy lease duration > renew deadline > retry period > 0"))
		}
	}
	if configuration.Backend == CoordinationFileLock && !validLinuxAbsolutePath(configuration.LockFile) {
		validationErrors = append(validationErrors, fmt.Errorf("coordination lock file %q must be a clean absolute path", configuration.LockFile))
	}
	if configuration.Backend == CoordinationFileLock && configuration.RetryPeriod <= 0 {
		validationErrors = append(validationErrors, errors.New("file-lock retry period must be positive"))
	}
	if configuration.AcquireTimeout <= 0 {
		validationErrors = append(validationErrors, errors.New("coordination acquire timeout must be positive"))
	}
	return errors.Join(validationErrors...)
}

func validDomainName(value string) bool {
	if len(value) == 0 || len(value) > 253 || value[len(value)-1] == '.' {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func validDNS1123Subdomain(value string) bool {
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || !dns1123LabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func validLinuxAbsolutePath(value string) bool {
	return path.IsAbs(value) && path.Clean(value) == value && !strings.ContainsRune(value, '\\') && !strings.ContainsRune(value, '\x00')
}
