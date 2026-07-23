package domain

import (
	"net/netip"
	"strings"
	"testing"
)

func TestPacketFilterRevisionIncludesEveryDNSTargetEgress(t *testing.T) {
	policy := validPacketFilterPolicy()
	first := policy.NATRevision()
	policy.DNSTargets[1].OutputInterface = "dns-v6-next"
	if second := policy.NATRevision(); first == second {
		t.Fatal("changing one DNS output interface did not change the NAT revision")
	}
}

func TestPacketFilterPolicyRejectsInvalidDynamicFacts(t *testing.T) {
	policy := validPacketFilterPolicy()
	policy.DNSTargets[0].OutputInterface = strings.Repeat("x", MaximumInterfaceNameBytes+1)
	if err := policy.Validate(); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("invalid DNS output interface was not rejected: %v", err)
	}
}

func TestPacketFilterPolicyRejectsAmbiguousDNSEgress(t *testing.T) {
	policy := validPacketFilterPolicy()
	policy.DNSTargets = append(policy.DNSTargets, DNSMasqueradeTarget{
		Address: policy.DNSTargets[0].Address, OutputInterface: "different-path",
	})
	if err := policy.Validate(); err == nil || !strings.Contains(err.Error(), "multiple output interfaces") {
		t.Fatalf("ambiguous DNS egress was accepted: %v", err)
	}
}

func TestPacketFilterPolicyRejectsMarkOutsideOwnedLowBits(t *testing.T) {
	policy := validPacketFilterPolicy()
	policy.LocalEgress.Mark = LocalEgressPacketMarkMask + 1
	if err := policy.Validate(); err == nil || !strings.Contains(err.Error(), "low 16 bits") {
		t.Fatalf("overlapping local-egress mark was accepted: %v", err)
	}
}

func validPacketFilterPolicy() PacketFilterPolicy {
	return PacketFilterPolicy{
		FilterTable:        "gateway_filter",
		ForwardGuardChain:  "forward_guard",
		LocalEgressChain:   "local_proxy",
		LocalEgressIPv4Set: "proxy_targets_v4",
		LocalEgressIPv6Set: "proxy_targets_v6",
		NATTable:           "gateway_nat",
		DNSMasqueradeChain: "dns_masquerade",
		TailnetIPv4Prefix:  netip.MustParsePrefix("100.64.0.0/10"),
		TailnetIPv6Prefix:  netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
		DNSTargets: []DNSMasqueradeTarget{
			{Address: netip.MustParseAddr("10.43.0.10"), OutputInterface: "dns-v4"},
			{Address: netip.MustParseAddr("fd00:43::a"), OutputInterface: "dns-v6"},
		},
		LocalEgress: LocalEgressPolicy{
			Enabled:   true,
			IPv4:      []netip.Addr{netip.MustParseAddr("192.0.2.10")},
			IPv6:      []netip.Addr{netip.MustParseAddr("2001:db8::10")},
			Protocols: []TransportProtocol{TransportTCP}, Ports: []uint16{443}, Mark: 0x11,
		},
	}
}
