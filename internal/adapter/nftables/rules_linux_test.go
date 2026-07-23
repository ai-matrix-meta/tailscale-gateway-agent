//go:build linux

package nftables

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	gnft "github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

func TestForwardQuarantineExistsWhenLocalEgressIsDisabled(t *testing.T) {
	policy := basePolicy()
	policy.GateClosed = true
	rules, err := filterRuleSpecs(policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules[policy.ForwardGuardChain]) != 4 {
		t.Fatalf("quarantine did not cover both address families: %#v", rules)
	}
	if len(rules[policy.LocalEgressChain]) != 0 {
		t.Fatalf("disabled local egress generated rules: %#v", rules[policy.LocalEgressChain])
	}
}

func TestLocalEgressMarkPreservesTailscaleOwnedUpperBits(t *testing.T) {
	policy := enabledPolicy()
	sets := map[string]*gnft.Set{
		policy.LocalEgressIPv4Set: {Name: policy.LocalEgressIPv4Set, ID: 11},
		policy.LocalEgressIPv6Set: {Name: policy.LocalEgressIPv6Set, ID: 12},
	}
	rules, err := filterRuleSpecs(policy, sets)
	if err != nil {
		t.Fatal(err)
	}
	expressions := rules[policy.LocalEgressChain][0].expressions
	markRead, readOK := expressions[len(expressions)-3].(*expr.Meta)
	markMerge, mergeOK := expressions[len(expressions)-2].(*expr.Bitwise)
	markWrite, writeOK := expressions[len(expressions)-1].(*expr.Meta)
	if !readOK || markRead.Key != expr.MetaKeyMARK || markRead.SourceRegister {
		t.Fatalf("local-egress rule does not read the existing packet mark: %#v", expressions)
	}
	if !mergeOK || !bytes.Equal(markMerge.Mask, binaryutil.NativeEndian.PutUint32(^domain.LocalEgressPacketMarkMask)) || !bytes.Equal(markMerge.Xor, binaryutil.NativeEndian.PutUint32(policy.LocalEgress.Mark)) {
		t.Fatalf("local-egress rule does not preserve upper mark bits: %#v", markMerge)
	}
	if !writeOK || markWrite.Key != expr.MetaKeyMARK || !markWrite.SourceRegister {
		t.Fatalf("local-egress rule does not write the merged packet mark: %#v", expressions)
	}
}

func TestLocalEgressUsesBoundedAddressSets(t *testing.T) {
	policy := enabledPolicy()
	sets := map[string]*gnft.Set{
		policy.LocalEgressIPv4Set: {Name: policy.LocalEgressIPv4Set, ID: 11},
		policy.LocalEgressIPv6Set: {Name: policy.LocalEgressIPv6Set, ID: 12},
	}
	rules, err := filterRuleSpecs(policy, sets)
	if err != nil {
		t.Fatal(err)
	}
	want := (len(policy.LocalEgress.Protocols) * len(policy.LocalEgress.Ports)) * 2
	if got := len(rules[policy.LocalEgressChain]); got != want {
		t.Fatalf("rule count scales with addresses instead of protocol/port/family: got %d, want %d", got, want)
	}
	for _, specification := range rules[policy.LocalEgressChain] {
		foundLookup := false
		for _, expression := range specification.expressions {
			if _, ok := expression.(*expr.Lookup); ok {
				foundLookup = true
			}
		}
		if !foundLookup {
			t.Fatalf("local-egress rule does not use a set: %#v", specification.expressions)
		}
	}
}

func TestDNSRulesMatchEachExactAddressAndOutputInterface(t *testing.T) {
	policy := enabledPolicy()
	rules, err := natRuleSpecs(policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != len(policy.DNSTargets)*2 {
		t.Fatalf("unexpected DNS NAT rule count: %d", len(rules))
	}
	for targetIndex, target := range policy.DNSTargets {
		for protocolOffset := 0; protocolOffset < 2; protocolOffset++ {
			specification := rules[targetIndex*2+protocolOffset]
			destination, ok := specification.expressions[6].(*expr.Cmp)
			if !ok || !bytes.Equal(destination.Data, target.Address.AsSlice()) {
				t.Fatalf("rule does not match exact DNS destination %s: %#v", target.Address, specification.expressions)
			}
			output, ok := specification.expressions[8].(*expr.Cmp)
			if !ok || !bytes.Equal(output.Data, interfaceNameBytes(target.OutputInterface)) {
				t.Fatalf("rule does not match DNS output interface %s: %#v", target.OutputInterface, specification.expressions)
			}
		}
	}
}

func TestRuleGenerationIsDeterministic(t *testing.T) {
	policy := enabledPolicy()
	first, err := natRuleSpecs(policy)
	if err != nil {
		t.Fatal(err)
	}
	second, err := natRuleSpecs(policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != len(second) {
		t.Fatalf("non-deterministic rule count: %d != %d", len(first), len(second))
	}
	for index := range first {
		if !bytes.Equal(first[index].userData, second[index].userData) {
			t.Fatalf("non-deterministic rule metadata at %d", index)
		}
	}
}

func basePolicy() domain.PacketFilterPolicy {
	return domain.PacketFilterPolicy{
		FilterTable:        "gateway_filter",
		ForwardGuardChain:  "forward_guard",
		LocalEgressChain:   "local_proxy",
		LocalEgressIPv4Set: "proxy_targets_v4",
		LocalEgressIPv6Set: "proxy_targets_v6",
		NATTable:           "gateway_nat",
		DNSMasqueradeChain: "dns_masquerade",
		TailnetIPv4Prefix:  netip.MustParsePrefix("100.64.0.0/10"),
		TailnetIPv6Prefix:  netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
	}
}

func enabledPolicy() domain.PacketFilterPolicy {
	policy := basePolicy()
	policy.DNSTargets = []domain.DNSMasqueradeTarget{
		{Address: netip.MustParseAddr("10.43.0.10"), OutputInterface: "dns-path-v4"},
		{Address: netip.MustParseAddr("fd00:43::a"), OutputInterface: "dns-path-v6"},
	}
	policy.LocalEgress = domain.LocalEgressPolicy{
		Enabled:   true,
		IPv4:      []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.11")},
		IPv6:      []netip.Addr{netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("2001:db8::11")},
		Protocols: []domain.TransportProtocol{domain.TransportTCP, domain.TransportUDP},
		Ports:     []uint16{443, 8443},
		Mark:      0x11,
	}
	return policy
}
