package domain

import (
	"net/netip"
	"strings"
	"testing"
)

func TestConfigurationValidationAcceptsExplicitV1Contract(t *testing.T) {
	configuration := validTestConfiguration()
	configuration.PacketFilter.LocalEgress.Enabled = true
	configuration.PacketFilter.LocalEgress.Domains = []string{"control.example.com"}
	configuration.Tailnet.AdvertiseRoutes = []netip.Prefix{netip.MustParsePrefix("10.0.8.0/24")}
	configuration.Tailnet.AdvertiseExitNode = true
	configuration.InternetCapability.IPv4ProbeURL = "https://ipv4.probe.example.com/status"
	configuration.InternetCapability.IPv6ProbeURL = "https://ipv6.probe.example.com/status"
	if err := configuration.Validate(); err != nil {
		t.Fatalf("configuration was rejected: %v", err)
	}
}

func TestDefaultHealthListenerIsHostLocal(t *testing.T) {
	if address := DefaultConfiguration().Runtime.HealthListenAddress; address != "127.0.0.1:8080" {
		t.Fatalf("default health listener %q is not host-local", address)
	}
}

func TestConfigurationValidationRejectsAmbiguousOwnership(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*Configuration)
		fragment string
	}{
		{
			name: "reserved metadata chain",
			mutate: func(configuration *Configuration) {
				configuration.PacketFilter.ForwardGuardChain = ReservedPacketFilterMetadataChain
			},
			fragment: "reserved metadata chain",
		},
		{
			name: "reserved route table",
			mutate: func(configuration *Configuration) {
				configuration.Network.ExitRouteTable = 254
			},
			fragment: "reserved by Linux",
		},
		{
			name: "advertised Tailnet overlap",
			mutate: func(configuration *Configuration) {
				configuration.Tailnet.AdvertiseRoutes = []netip.Prefix{netip.MustParsePrefix("100.64.1.0/24")}
			},
			fragment: "overlaps a Tailnet prefix",
		},
		{
			name: "duplicate domain",
			mutate: func(configuration *Configuration) {
				configuration.PacketFilter.LocalEgress.Enabled = true
				configuration.PacketFilter.LocalEgress.Domains = []string{"control.example.com", "control.example.com"}
			},
			fragment: "is duplicated",
		},
		{
			name: "overlapping advertisements",
			mutate: func(configuration *Configuration) {
				configuration.Tailnet.AdvertiseRoutes = []netip.Prefix{
					netip.MustParsePrefix("10.0.0.0/8"),
					netip.MustParsePrefix("10.0.8.0/24"),
				}
			},
			fragment: "advertised routes 10.0.0.0/8 and 10.0.8.0/24 overlap",
		},
		{
			name: "proxy tunnel overlap",
			mutate: func(configuration *Configuration) {
				configuration.Tailnet.AdvertiseRoutes = []netip.Prefix{netip.MustParsePrefix("198.18.0.0/16")}
			},
			fragment: "overlaps proxy tunnel prefix",
		},
		{
			name: "packet mark overlaps reserved upper bytes",
			mutate: func(configuration *Configuration) {
				configuration.Network.LocalEgressPacketMark = 0x10000
			},
			fragment: "low 16 bits",
		},
		{
			name: "active route metric exceeds netlink integer range",
			mutate: func(configuration *Configuration) {
				configuration.Network.ActiveRouteMetric = maximumNetlinkInteger + 1
			},
			fragment: "active route metric must be within 1..2147483647",
		},
		{
			name: "invalid Lease DNS label",
			mutate: func(configuration *Configuration) {
				configuration.Coordination.Backend = CoordinationKubernetesLease
				configuration.Coordination.ResourceName = "valid.-invalid"
			},
			fragment: "coordination resource name",
		},
		{
			name: "unbounded reconcile operation",
			mutate: func(configuration *Configuration) {
				configuration.Tailnet.OperationTimeout = configuration.Runtime.ReconcileTimeout
			},
			fragment: "tailscale operation timeout must be shorter",
		},
		{
			name: "zero health port",
			mutate: func(configuration *Configuration) {
				configuration.Runtime.HealthListenAddress = ":0"
			},
			fragment: "numeric port within 1..65535",
		},
		{
			name: "named health port",
			mutate: func(configuration *Configuration) {
				configuration.Runtime.HealthListenAddress = ":http"
			},
			fragment: "numeric port within 1..65535",
		},
		{
			name: "missing Exit capability endpoints",
			mutate: func(configuration *Configuration) {
				configuration.Tailnet.AdvertiseExitNode = true
			},
			fragment: "ipv4 capability probe URL is required",
		},
		{
			name: "capability endpoints without Exit advertisement",
			mutate: func(configuration *Configuration) {
				configuration.InternetCapability.IPv4ProbeURL = "https://ipv4.probe.example.com/status"
				configuration.InternetCapability.IPv6ProbeURL = "https://ipv6.probe.example.com/status"
			},
			fragment: "capability probe URLs require Exit advertisement",
		},
		{
			name: "capability timeout reaches interval",
			mutate: func(configuration *Configuration) {
				configuration.InternetCapability.ProbeTimeout = configuration.InternetCapability.ProbeInterval
			},
			fragment: "timeout must be positive and shorter",
		},
		{
			name: "capability validity does not exceed interval",
			mutate: func(configuration *Configuration) {
				configuration.InternetCapability.ProbeValidity = configuration.InternetCapability.ProbeInterval
			},
			fragment: "validity must exceed its interval",
		},
		{
			name: "capability threshold is unbounded",
			mutate: func(configuration *Configuration) {
				configuration.InternetCapability.FailureThreshold = 17
			},
			fragment: "failure threshold must be within 1..16",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration := validTestConfiguration()
			test.mutate(&configuration)
			err := configuration.Validate()
			if err == nil || !strings.Contains(err.Error(), test.fragment) {
				t.Fatalf("expected %q validation error, got %v", test.fragment, err)
			}
		})
	}
}

func validTestConfiguration() Configuration {
	configuration := DefaultConfiguration()
	configuration.Network.ProxyTunnelAddresses = []netip.Prefix{
		netip.MustParsePrefix("198.18.0.1/15"),
		netip.MustParsePrefix("fd88:baba:fafa::1/126"),
	}
	configuration.Coordination.Backend = CoordinationFileLock
	return configuration
}
