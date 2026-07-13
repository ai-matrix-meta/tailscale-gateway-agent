package resolver

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestNameServersReturnsEveryConfiguredAddressFamily(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "resolver.conf")
	content := "search svc.example\n" +
		"nameserver 10.43.0.10 # IPv4 path\n" +
		"nameserver fd00:43::a ; IPv6 path\n" +
		"nameserver 10.44.0.10\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	resolver := New(path, time.Second)
	snapshot, err := resolver.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	addresses := snapshot.NameServers()
	want := []netip.Addr{
		netip.MustParseAddr("10.43.0.10"),
		netip.MustParseAddr("fd00:43::a"),
		netip.MustParseAddr("10.44.0.10"),
	}
	if !slices.Equal(addresses, want) {
		t.Fatalf("unexpected nameservers: got %v, want %v", addresses, want)
	}
}

func TestNameServersRejectsAnyMalformedDirective(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolver.conf")
	if err := os.WriteFile(path, []byte("nameserver 10.43.0.10\nnameserver invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New(path, time.Second).Snapshot(context.Background())
	if err == nil || !strings.Contains(err.Error(), "invalid nameserver") {
		t.Fatalf("malformed nameserver was not rejected: %v", err)
	}
}

func TestResolveNormalizesAndBoundsAddresses(t *testing.T) {
	snapshot := &resolverSnapshot{
		nameServers: []netip.Addr{netip.MustParseAddr("192.0.2.53")},
		resolver: staticLookup{addresses: []netip.Addr{
			netip.MustParseAddr("2001:db8::10"),
			netip.MustParseAddr("192.0.2.10"),
			netip.MustParseAddr("192.0.2.10"),
		}},
		lookupTimeout: time.Second,
	}
	addresses, err := snapshot.Resolve(context.Background(), "control.example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")}
	if !slices.Equal(addresses, want) {
		t.Fatalf("unexpected resolved addresses: got %v, want %v", addresses, want)
	}
}

func TestResolveUsesConfiguredNameServersForAnAbsoluteQuery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolver.conf")
	if err := os.WriteFile(path, []byte("nameserver 192.0.2.53\nnameserver 2001:db8::53\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolver := New(path, time.Second)
	var observedNameServers []netip.Addr
	var observedName string
	resolver.resolverFactory = func(nameServers []netip.Addr) lookupResolver {
		observedNameServers = slices.Clone(nameServers)
		return lookupFunc(func(_ context.Context, _, name string) ([]netip.Addr, error) {
			observedName = name
			return []netip.Addr{netip.MustParseAddr("198.51.100.10")}, nil
		})
	}

	snapshot, err := resolver.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.Resolve(context.Background(), "control.example.com"); err != nil {
		t.Fatal(err)
	}
	wantNameServers := []netip.Addr{netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("2001:db8::53")}
	if !slices.Equal(observedNameServers, wantNameServers) {
		t.Fatalf("lookup did not use configured nameservers: got %v, want %v", observedNameServers, wantNameServers)
	}
	if observedName != "control.example.com." {
		t.Fatalf("lookup was not made as an absolute DNS name: %q", observedName)
	}
}

func TestSnapshotRemainsBoundToOneResolverConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolver.conf")
	if err := os.WriteFile(path, []byte("nameserver 192.0.2.53\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolver := New(path, time.Second)
	var queryNameServers []netip.Addr
	resolver.resolverFactory = func(nameServers []netip.Addr) lookupResolver {
		bound := slices.Clone(nameServers)
		return lookupFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			queryNameServers = slices.Clone(bound)
			return []netip.Addr{netip.MustParseAddr("198.51.100.10")}, nil
		})
	}
	snapshot, err := resolver.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("nameserver 192.0.2.54\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.Resolve(context.Background(), "control.example.com"); err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{netip.MustParseAddr("192.0.2.53")}
	if !slices.Equal(snapshot.NameServers(), want) || !slices.Equal(queryNameServers, want) {
		t.Fatalf("snapshot mixed resolver configurations: nameservers=%v query=%v", snapshot.NameServers(), queryNameServers)
	}
	newSnapshot, err := resolver.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := newSnapshot.NameServers(); !slices.Equal(got, []netip.Addr{netip.MustParseAddr("192.0.2.54")}) {
		t.Fatalf("new snapshot did not observe the replacement configuration: %v", got)
	}
}

func TestNameServerPoolFallsBackAfterAnUpstreamFailure(t *testing.T) {
	want := []netip.Addr{netip.MustParseAddr("198.51.100.10")}
	pool := &nameServerPool{servers: []nameServerLookup{
		{address: netip.MustParseAddr("192.0.2.53"), resolver: lookupFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, context.DeadlineExceeded
		})},
		{address: netip.MustParseAddr("192.0.2.54"), resolver: lookupFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			return want, nil
		})},
	}}
	addresses, err := pool.LookupNetIP(context.Background(), "ip", "control.example.com.")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(addresses, want) {
		t.Fatalf("fallback resolver returned %v, want %v", addresses, want)
	}
}

type staticLookup struct {
	addresses []netip.Addr
}

type lookupFunc func(context.Context, string, string) ([]netip.Addr, error)

func (lookup lookupFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return lookup(ctx, network, host)
}

func (lookup staticLookup) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return slices.Clone(lookup.addresses), nil
}
