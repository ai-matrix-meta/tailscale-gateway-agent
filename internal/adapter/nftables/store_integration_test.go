//go:build linux && integration

package nftables

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	gnft "github.com/google/nftables"
)

func TestIntegrationStoreConvergesAndRefusesForeignOwnership(t *testing.T) {
	policy := domain.PacketFilterPolicy{
		FilterTable:        "ts_gateway_test_filter",
		ForwardGuardChain:  "forward_guard",
		LocalEgressChain:   "local_proxy",
		LocalEgressIPv4Set: "proxy_targets_v4",
		LocalEgressIPv6Set: "proxy_targets_v6",
		NATTable:           "ts_gateway_test_nat",
		DNSMasqueradeChain: "dns_masquerade",
		GateClosed:         true,
		TailnetIPv4Prefix:  netip.MustParsePrefix("100.64.0.0/10"),
		TailnetIPv6Prefix:  netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
		DNSTargets: []domain.DNSMasqueradeTarget{
			{Address: netip.MustParseAddr("10.42.0.53"), OutputInterface: "uplink-v4"},
			{Address: netip.MustParseAddr("fd00:42::53"), OutputInterface: "uplink-v6"},
		},
		LocalEgress: domain.LocalEgressPolicy{
			Enabled:   true,
			IPv4:      []netip.Addr{netip.MustParseAddr("192.0.2.10")},
			IPv6:      []netip.Addr{netip.MustParseAddr("2001:db8::10")},
			Protocols: []domain.TransportProtocol{domain.TransportTCP, domain.TransportUDP},
			Ports:     []uint16{443},
			Mark:      0x11,
		},
	}
	cleanupIntegrationTables(t, policy.FilterTable, policy.NATTable)
	store := New()
	observation, err := store.Observe(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	if observation.Matches(policy) {
		t.Fatal("absent nftables state unexpectedly matched")
	}
	if err := store.Apply(context.Background(), policy, observation); err != nil {
		t.Fatal(err)
	}
	observation, err = store.Observe(context.Background(), policy)
	if err != nil {
		t.Fatal(err)
	}
	if !observation.Matches(policy) {
		t.Fatalf("nftables state did not converge: %#v", observation)
	}

	cleanupIntegrationTables(t, policy.FilterTable, policy.NATTable)
	connection, err := gnft.New()
	if err != nil {
		t.Fatal(err)
	}
	connection.AddTable(&gnft.Table{Name: policy.FilterTable, Family: gnft.TableFamilyINet})
	if err := connection.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Observe(context.Background(), policy); err == nil || !strings.Contains(err.Error(), "conflicts with Agent ownership") {
		t.Fatalf("foreign table was not rejected: %v", err)
	}
}

func cleanupIntegrationTables(t *testing.T, names ...string) {
	t.Helper()
	cleanup := func() {
		connection, err := gnft.New()
		if err != nil {
			return
		}
		tables, err := connection.ListTables()
		if err != nil {
			return
		}
		for _, table := range tables {
			for _, name := range names {
				if table.Name == name {
					connection.DelTable(table)
				}
			}
		}
		_ = connection.Flush()
	}
	cleanup()
	t.Cleanup(cleanup)
}
