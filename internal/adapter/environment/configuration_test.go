package environment

import (
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
)

func TestLoadUsesDocumentedDefaultsAndExplicitCoordination(t *testing.T) {
	configuration, err := load(minimalEnvironment())
	if err != nil {
		t.Fatalf("load returned an error: %v", err)
	}
	if configuration.APIVersion != domain.ConfigurationAPIVersionV1 || configuration.Network.ExitRouteTable != 100 || configuration.Network.LocalEgressPacketMark != 0x11 {
		t.Fatalf("unexpected defaults: %#v", configuration)
	}
	if configuration.Coordination.Backend != domain.CoordinationFileLock {
		t.Fatalf("unexpected coordination backend: %q", configuration.Coordination.Backend)
	}
}

func TestLoadParsesCompleteProductionValues(t *testing.T) {
	entries := []string{
		configAPIVersion + "=v1",
		proxyTunnelAddresses + "=198.18.0.1/15,fd88:baba:fafa::1/126",
		tailnetIPv4Prefix + "=100.64.0.0/10",
		tailnetIPv6Prefix + "=fd7a:115c:a1e0::/48",
		exitRouteTable + "=200",
		exitRulePriority + "=199",
		localEgressRouteTable + "=201",
		localEgressRulePriority + "=190",
		localEgressPacketMark + "=0x22",
		activeRouteMetric + "=120",
		failClosedRouteMetric + "=32000",
		nftablesFilterTable + "=gateway_filter_test",
		nftablesForwardGuardChain + "=forward_guard_test",
		nftablesLocalEgressChain + "=local_egress_test",
		nftablesLocalEgressIPv4Set + "=local_ipv4_test",
		nftablesLocalEgressIPv6Set + "=local_ipv6_test",
		nftablesNATTable + "=gateway_nat_test",
		nftablesDNSSNATChain + "=dns_snat_test",
		localEgressEnabled + "=true",
		localEgressDomains + "=login.example.com,control.example.com",
		localEgressProtocols + "=udp,tcp",
		localEgressPorts + "=8443,443",
		localEgressRefreshInterval + "=45s",
		localEgressMaximumStaleness + "=2m",
		tailscaleSocketPath + "=/run/tailscale/control.sock",
		advertiseRoutes + "=10.0.9.0/24,10.0.8.0/24",
		advertiseExitNode + "=true",
		preferenceAuditInterval + "=45s",
		tailscaleOperationTimeout + "=5s",
		capabilityProbeIPv4URL + "=https://ipv4.probe.example.com/status",
		capabilityProbeIPv6URL + "=https://ipv6.probe.example.com/status",
		capabilityProbeInterval + "=15s",
		capabilityProbeTimeout + "=3s",
		capabilityProbeValidity + "=60s",
		capabilitySuccessThreshold + "=3",
		capabilityFailureThreshold + "=4",
		auditInterval + "=45s",
		reconcileTimeout + "=30s",
		eventDebounce + "=750ms",
		readinessMaximumAge + "=90s",
		dnsLookupTimeout + "=4s",
		shutdownTimeout + "=25s",
		healthListenAddress + "=127.0.0.1:9090",
		resolverPath + "=/run/systemd/resolve/resolv.conf",
		logLevel + "=WARN",
		coordinationBackend + "=kubernetes-lease",
		coordinationResourceName + "=gateway-test-identity",
		coordinationNamespacePath + "=/var/run/serviceaccount/namespace",
		coordinationLockFile + "=/run/gateway-test.lock",
		coordinationLeaseDuration + "=2m",
		coordinationRenewDeadline + "=1m",
		coordinationRetryPeriod + "=3s",
		coordinationAcquireTimeout + "=2m",
	}
	configuration, err := load(entries)
	if err != nil {
		t.Fatalf("load returned an error: %v", err)
	}
	want := domain.Configuration{
		APIVersion: "v1",
		Network: domain.NetworkConfiguration{
			ProxyTunnelAddresses: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/15"), netip.MustParsePrefix("fd88:baba:fafa::1/126")},
			TailnetIPv4Prefix:    netip.MustParsePrefix("100.64.0.0/10"), TailnetIPv6Prefix: netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
			ExitRouteTable: 200, ExitRulePriority: 199, LocalEgressRouteTable: 201, LocalEgressRulePriority: 190,
			LocalEgressPacketMark: 0x22, ActiveRouteMetric: 120, FailClosedRouteMetric: 32_000,
		},
		PacketFilter: domain.PacketFilterConfiguration{
			FilterTable: "gateway_filter_test", ForwardGuardChain: "forward_guard_test", LocalEgressChain: "local_egress_test",
			LocalEgressIPv4Set: "local_ipv4_test", LocalEgressIPv6Set: "local_ipv6_test", NATTable: "gateway_nat_test", DNSMasqueradeChain: "dns_snat_test",
			LocalEgress: domain.LocalEgressConfiguration{
				Enabled: true, Domains: []string{"control.example.com", "login.example.com"},
				Protocols: []domain.TransportProtocol{domain.TransportTCP, domain.TransportUDP}, Ports: []uint16{443, 8443},
				RefreshInterval: 45 * time.Second, MaximumStaleness: 2 * time.Minute,
			},
		},
		Tailnet: domain.TailnetConfiguration{
			SocketPath:        "/run/tailscale/control.sock",
			AdvertiseRoutes:   []netip.Prefix{netip.MustParsePrefix("10.0.8.0/24"), netip.MustParsePrefix("10.0.9.0/24")},
			AdvertiseExitNode: true, PreferenceAuditInterval: 45 * time.Second, OperationTimeout: 5 * time.Second,
		},
		InternetCapability: domain.InternetCapabilityConfiguration{
			IPv4ProbeURL: "https://ipv4.probe.example.com/status", IPv6ProbeURL: "https://ipv6.probe.example.com/status",
			ProbeInterval: 15 * time.Second, ProbeTimeout: 3 * time.Second, ProbeValidity: time.Minute,
			SuccessThreshold: 3, FailureThreshold: 4,
		},
		Runtime: domain.RuntimeConfiguration{
			AuditInterval: 45 * time.Second, ReconcileTimeout: 30 * time.Second, EventDebounce: 750 * time.Millisecond, ReadinessMaximumAge: 90 * time.Second,
			DNSLookupTimeout: 4 * time.Second, ShutdownTimeout: 25 * time.Second, HealthListenAddress: "127.0.0.1:9090",
			ResolverPath: "/run/systemd/resolve/resolv.conf", LogLevel: "warn",
		},
		Coordination: domain.CoordinationConfiguration{
			Backend: domain.CoordinationKubernetesLease, ResourceName: "gateway-test-identity",
			NamespacePath: "/var/run/serviceaccount/namespace", LockFile: "/run/gateway-test.lock",
			LeaseDuration: 2 * time.Minute, RenewDeadline: time.Minute, RetryPeriod: 3 * time.Second, AcquireTimeout: 2 * time.Minute,
		},
	}
	if !reflect.DeepEqual(configuration, want) {
		t.Fatalf("configuration mismatch:\n got: %#v\nwant: %#v", configuration, want)
	}
}

func TestLoadRejectsUnknownOwnedVariablesInStableOrder(t *testing.T) {
	entries := append(minimalEnvironment(),
		ownedPrefix+"ZZ_UNKNOWN=value",
		ownedPrefix+"AA_UNKNOWN=value",
	)
	_, first := load(entries)
	_, second := load(entries)
	if first == nil || second == nil || first.Error() != second.Error() {
		t.Fatalf("validation errors are not stable:\nfirst: %v\nsecond: %v", first, second)
	}
	if strings.Index(first.Error(), "AA_UNKNOWN") > strings.Index(first.Error(), "ZZ_UNKNOWN") {
		t.Fatalf("unknown variables are not sorted: %v", first)
	}
}

func TestLoadDistinguishesMissingAndExplicitEmptyValues(t *testing.T) {
	if _, err := load(minimalEnvironment()); err != nil {
		t.Fatalf("missing lock path did not use the default: %v", err)
	}
	_, err := load(append(minimalEnvironment(), coordinationLockFile+"="))
	if err == nil || !strings.Contains(err.Error(), "clean absolute path") {
		t.Fatalf("explicit empty lock path was not rejected: %v", err)
	}
}

func TestLoadRejectsDuplicateListEntries(t *testing.T) {
	tests := []struct {
		name     string
		entries  []string
		fragment string
	}{
		{name: "advertised route", entries: []string{advertiseRoutes + "=10.0.8.0/24,10.0.8.0/24"}, fragment: "advertised route 10.0.8.0/24 is duplicated"},
		{name: "local-egress domain", entries: []string{localEgressEnabled + "=true", localEgressDomains + "=control.example.com,control.example.com"}, fragment: "local-egress domain \"control.example.com\" is duplicated"},
		{name: "local-egress protocol", entries: []string{localEgressEnabled + "=true", localEgressDomains + "=control.example.com", localEgressProtocols + "=tcp,tcp"}, fragment: "local-egress protocol \"tcp\" is duplicated"},
		{name: "local-egress port", entries: []string{localEgressEnabled + "=true", localEgressDomains + "=control.example.com", localEgressPorts + "=443,443"}, fragment: "local-egress port 443 is duplicated"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entries := append(minimalEnvironment(), test.entries...)
			_, err := load(entries)
			if err == nil || !strings.Contains(err.Error(), test.fragment) {
				t.Fatalf("expected %q validation error, got %v", test.fragment, err)
			}
		})
	}
}

func TestLoadRejectsEmptyListMembers(t *testing.T) {
	entries := []string{
		advertiseRoutes + "=10.0.8.0/24,",
		localEgressDomains + "=,control.example.com",
		localEgressProtocols + "=tcp,,udp",
		localEgressPorts + "=443, ,8443",
	}
	for _, entry := range entries {
		_, err := load(append(minimalEnvironment(), entry))
		if err == nil || !strings.Contains(err.Error(), "contains an empty item") {
			t.Fatalf("malformed list %q was accepted: %v", entry, err)
		}
	}
	proxyEntry := proxyTunnelAddresses + "=198.18.0.1/15,,fd88:baba:fafa::1/126"
	_, err := load([]string{coordinationBackend + "=file-lock", proxyEntry})
	if err == nil || !strings.Contains(err.Error(), "contains an empty item") {
		t.Fatalf("malformed list %q was accepted: %v", proxyEntry, err)
	}
}

func TestLoadRejectsNonCanonicalScalarSyntax(t *testing.T) {
	for _, entry := range []string{
		advertiseExitNode + "=1",
		localEgressEnabled + "=t",
		localEgressPacketMark + "=0o21",
		localEgressPacketMark + "=+17",
	} {
		if _, err := load(append(minimalEnvironment(), entry)); err == nil {
			t.Fatalf("non-canonical scalar %q was accepted", entry)
		}
	}
	configuration, err := load(append(minimalEnvironment(), localEgressPacketMark+"=021"))
	if err != nil {
		t.Fatalf("decimal value with a leading zero was rejected: %v", err)
	}
	if configuration.Network.LocalEgressPacketMark != 21 {
		t.Fatalf("decimal value was assigned implicit octal meaning: got %d, want 21", configuration.Network.LocalEgressPacketMark)
	}
}

func TestLoadRequiresExplicitProxyTunnelAddresses(t *testing.T) {
	_, err := load([]string{coordinationBackend + "=file-lock"})
	if err == nil || !strings.Contains(err.Error(), "at least one proxy tunnel address is required") {
		t.Fatalf("missing cluster-owned proxy tunnel addresses were accepted: %v", err)
	}
}

func TestLoadRequiresCapabilityEndpointsExactlyWhenExitIsEnabled(t *testing.T) {
	_, err := load(append(minimalEnvironment(), advertiseExitNode+"=true"))
	if err == nil || !strings.Contains(err.Error(), "ipv4 capability probe URL is required") || !strings.Contains(err.Error(), "ipv6 capability probe URL is required") {
		t.Fatalf("exit advertisement without endpoints was accepted: %v", err)
	}

	for _, entry := range []string{capabilityProbeIPv4URL + "=", capabilityProbeIPv6URL + "=https://ipv6.probe.example.com/status"} {
		_, err = load(append(minimalEnvironment(), entry))
		if err == nil || !strings.Contains(err.Error(), "must be absent when Exit advertisement is disabled") {
			t.Fatalf("disabled Exit accepted endpoint entry %q: %v", entry, err)
		}
	}
}

func TestTailnetAdvertisementOwnershipIsExclusive(t *testing.T) {
	tests := []string{
		"TS_ROUTES=",
		"TS_EXTRA_ARGS=--accept-dns=false --advertise-routes=10.0.8.0/24",
		"TS_TAILSCALED_EXTRA_ARGS='--advertise-exit-node'",
	}
	for _, conflict := range tests {
		entries := append(minimalEnvironment(), conflict)
		if _, err := load(entries); err == nil {
			t.Fatalf("conflicting Tailscale ownership was accepted: %v", entries)
		}
	}
}

func minimalEnvironment() []string {
	return []string{
		coordinationBackend + "=file-lock",
		proxyTunnelAddresses + "=198.18.0.1/15,fd88:baba:fafa::1/126",
	}
}

func TestContainerbootEnvironmentUsesAllowlistWithoutMutatingSecrets(t *testing.T) {
	entries := []string{
		"PATH=/usr/local/bin:/usr/bin",
		"TS_AUTHKEY=opaque-value ",
		"TS_KUBE_SECRET=gateway-state",
		"KUBERNETES_SERVICE_HOST=10.0.0.1",
		"KUBERNETES_SERVICE_FAKE=discarded",
		"TAILSCALE_GATEWAY_COORDINATION_BACKEND=kubernetes-lease",
		"UNRELATED=value",
	}
	result, err := containerbootEnvironment(entries)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"KUBERNETES_SERVICE_HOST=10.0.0.1",
		"PATH=/usr/local/bin:/usr/bin",
		"TS_AUTHKEY=opaque-value ",
		"TS_KUBE_SECRET=gateway-state",
	}
	if !slices.Equal(result, want) {
		t.Fatalf("unexpected child environment:\n got: %q\nwant: %q", result, want)
	}
	for _, entry := range result {
		if strings.HasPrefix(entry, "TS_ROUTES=") {
			t.Fatalf("containerboot environment contains an Agent-owned preference: %q", entry)
		}
	}
}

func TestContainerbootEnvironmentRejectsUnsupportedTailscaleVariables(t *testing.T) {
	_, err := containerbootEnvironment([]string{
		"TS_DEST_IP=192.0.2.1",
		"TS_EXPERIMENTAL_VERSIONED_CONFIG_DIR=/configuration",
	})
	if err == nil {
		t.Fatal("unsupported containerboot variables were accepted")
	}
	if strings.Index(err.Error(), "TS_DEST_IP") > strings.Index(err.Error(), "TS_EXPERIMENTAL_VERSIONED_CONFIG_DIR") {
		t.Fatalf("unsupported variables are not reported in stable order: %v", err)
	}
}
