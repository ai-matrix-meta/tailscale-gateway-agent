//go:build linux && integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	netlinkadapter "github.com/ai-matrix-meta/tailscale-gateway-agent/internal/adapter/netlink"
	nftablesadapter "github.com/ai-matrix-meta/tailscale-gateway-agent/internal/adapter/nftables"
	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/application"
	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/port"
	gnft "github.com/google/nftables"
	vnetlink "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	integrationRouteProtocol           = vnetlink.RouteProtocol(186)
	integrationExitRouteTable          = 31_980
	integrationLocalEgressRouteTable   = 31_981
	integrationExitRulePriority        = 31_980
	integrationLocalEgressRulePriority = 31_981
	integrationActiveRouteMetric       = 123
	integrationFailClosedRouteMetric   = 32_123
	integrationFilterTable             = "ts_gateway_runtime_filter"
	integrationNATTable                = "ts_gateway_runtime_nat"
)

func TestRunnerConvergesWithoutSelfEventsAndRepairsExternalDrift(t *testing.T) {
	if err := purgeManagedRouting(); err != nil {
		t.Fatalf("remove stale managed routing: %v", err)
	}
	if err := purgeNFTables(); err != nil {
		t.Fatalf("remove stale managed nftables: %v", err)
	}
	t.Cleanup(func() {
		if err := purgeManagedRouting(); err != nil {
			t.Errorf("remove managed routing: %v", err)
		}
		if err := purgeNFTables(); err != nil {
			t.Errorf("remove managed nftables: %v", err)
		}
	})

	addTunnel(t, "runtime-tail", []string{"100.64.0.8/32", "fd7a:115c:a1e0::8/128"})
	addTunnel(t, "runtime-proxy", []string{"198.18.0.1/15", "fd88:baba:fafa::1/126"})
	ipv4Link := addDummy(t, "runtime-v4", []string{"10.42.80.2/24"})
	addDummy(t, "runtime-v6", []string{"fd00:80::2/64"})
	advertisedPrefix := netip.MustParsePrefix("10.80.0.0/24")
	advertisedRoute := &vnetlink.Route{
		LinkIndex: ipv4Link.Attrs().Index,
		Dst:       ipNet(advertisedPrefix),
		Gw:        net.IP(netip.MustParseAddr("10.42.80.1").AsSlice()),
		Scope:     vnetlink.SCOPE_UNIVERSE,
		Type:      unix.RTN_UNICAST,
	}
	if err := vnetlink.RouteAdd(advertisedRoute); err != nil {
		t.Fatalf("add advertised-prefix source route: %v", err)
	}
	t.Cleanup(func() { _ = vnetlink.RouteDel(advertisedRoute) })

	configuration := integrationConfiguration(advertisedPrefix)
	network, err := netlinkadapter.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = network.Close() })
	resolver := &staticDNSResolver{nameServers: []netip.Addr{
		netip.MustParseAddr("10.42.80.53"),
		netip.MustParseAddr("fd00:80::53"),
	}, resolved: []netip.Addr{
		netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("2001:db8::10"),
	}}
	tailnet := &staticTailnetControl{state: domain.TailnetState{
		Running: true, KernelTunnel: true,
		SelfAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.8"), netip.MustParseAddr("fd7a:115c:a1e0::8")},
		Preferences:   domain.NewTailnetPreferences(nil, false),
		Control: domain.TailnetControlObservation{
			SelfPresent: true, InNetworkMap: true, Online: true, AllowedIPsAvailable: true,
			ApprovedRoutes: domain.NewTailnetPreferences(configuration.Tailnet.AdvertiseRoutes, true).AdvertiseRoutes,
			ObservedAt:     time.Now(),
		},
	}}
	controller, err := application.NewController(configuration, application.ControllerDependencies{
		Kernel: staticKernelChecker{}, ProxyTunnel: network, Network: network, Routing: network,
		PacketFilter: nftablesadapter.New(), Resolver: resolver, Tailnet: tailnet,
		InternetCapability: staticInternetCapability{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Prepare(context.Background()); err != nil {
		t.Fatalf("prepare controller: %v", err)
	}
	tailnet.mutex.Lock()
	tailnet.state.Control.InNetworkMap = false
	tailnet.mutex.Unlock()
	if _, err := controller.Reconcile(context.Background()); err == nil || !strings.Contains(err.Error(), "absent from the current network map") {
		t.Fatalf("unavailable bootstrap state was accepted: %v", err)
	}
	failClosedReport, err := controller.FailClosed(context.Background())
	if err == nil || !strings.Contains(err.Error(), "absent from the current network map") {
		t.Fatalf("live fail-closed state did not report unavailable Tailnet control: %v", err)
	}
	if failClosedReport.Changed || failClosedReport.RoutingWrites != 0 || failClosedReport.PacketFilterWrites != 0 || failClosedReport.TailnetWrites != 0 {
		t.Fatalf("verified bootstrap recovery path was rewritten: %#v", failClosedReport)
	}
	assertLocalControlRecoveryRouting(t, network, configuration)
	tailnet.mutex.Lock()
	tailnet.state.Control.InNetworkMap = true
	tailnet.state.Control.ObservedAt = time.Now()
	tailnet.mutex.Unlock()

	status := application.NewStatus(configuration.Runtime.ReadinessMaximumAge)
	metrics := newRecordingMetrics()
	runner, err := application.NewRunner(configuration, controller, network, tailnet, status, metrics, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runnerResult := make(chan error, 1)
	go func() { runnerResult <- runner.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-runnerResult; err != nil {
			t.Errorf("stop runner: %v", err)
		}
	}()

	startup := metrics.waitForRecord(t, 1, 15*time.Second)[0]
	if startup.err != nil {
		t.Fatalf("startup reconciliation failed: %v", startup.err)
	}
	if startup.report.RoutingWrites == 0 || startup.report.PacketFilterWrites == 0 || startup.report.TailnetWrites == 0 {
		t.Fatalf("startup reconciliation omitted a managed resource: %#v", startup.report)
	}
	time.Sleep(2 * configuration.Runtime.EventDebounce)
	if records := metrics.snapshot(); len(records) != 1 {
		t.Fatalf("managed writes leaked self-generated network events: %#v", records)
	}

	deleted := findManagedIPv4Default(t)
	if err := vnetlink.RouteDel(&deleted); err != nil {
		t.Fatalf("delete managed route externally: %v", err)
	}
	repairRecords := metrics.waitForRecord(t, 2, 15*time.Second)
	repair := repairRecords[1]
	if repair.err != nil || repair.report.RoutingWrites == 0 {
		t.Fatalf("external route deletion was not repaired: %#v", repair)
	}
	_ = findManagedIPv4Default(t)

	addDummy(t, "runtime-noise", nil)
	steadyRecords := metrics.waitForRecord(t, 3, 15*time.Second)
	steady := steadyRecords[2]
	if steady.err != nil || steady.report.Changed || steady.report.RoutingWrites != 0 || steady.report.PacketFilterWrites != 0 || steady.report.TailnetWrites != 0 {
		t.Fatalf("no-drift event reconciliation performed writes: %#v", steady)
	}
}

func assertLocalControlRecoveryRouting(t *testing.T, store port.RoutingStore, configuration domain.Configuration) {
	t.Helper()
	state, err := store.ReadRouting(context.Background(), domain.RoutingOwnership{
		Tables: []int{
			configuration.Network.ExitRouteTable,
			configuration.Network.LocalEgressRouteTable,
		},
		RulePriorities: []int{
			configuration.Network.ExitRulePriority,
			configuration.Network.LocalEgressRulePriority,
		},
	})
	if err != nil {
		t.Fatalf("read fail-closed recovery routing: %v", err)
	}
	for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
		defaultPrefix := domain.DefaultPrefix(family)
		var localActive, localBlackhole, exitBlackhole bool
		for _, route := range state.Routes {
			if route.Family != family || route.Prefix != defaultPrefix {
				continue
			}
			switch {
			case route.Table == configuration.Network.LocalEgressRouteTable && route.Disposition == domain.RouteUnicast:
				localActive = route.Link.Valid() && route.Link.Name == "runtime-proxy"
			case route.Table == configuration.Network.LocalEgressRouteTable && route.Disposition == domain.RouteBlackhole:
				localBlackhole = true
			case route.Table == configuration.Network.ExitRouteTable && route.Disposition == domain.RouteBlackhole:
				exitBlackhole = true
			case route.Table == configuration.Network.ExitRouteTable && route.Disposition == domain.RouteUnicast:
				t.Fatalf("family %d Exit default remained active during bootstrap isolation: %#v", family, route)
			}
		}
		if !localActive || !localBlackhole || !exitBlackhole {
			t.Fatalf("family %d recovery routing is incomplete: %#v", family, state)
		}
	}
}

func integrationConfiguration(advertisedPrefix netip.Prefix) domain.Configuration {
	configuration := domain.DefaultConfiguration()
	configuration.Network.ProxyTunnelAddresses = []netip.Prefix{
		netip.MustParsePrefix("198.18.0.1/15"),
		netip.MustParsePrefix("fd88:baba:fafa::1/126"),
	}
	configuration.Network.ExitRouteTable = integrationExitRouteTable
	configuration.Network.LocalEgressRouteTable = integrationLocalEgressRouteTable
	configuration.Network.ExitRulePriority = integrationExitRulePriority
	configuration.Network.LocalEgressRulePriority = integrationLocalEgressRulePriority
	configuration.Network.ActiveRouteMetric = integrationActiveRouteMetric
	configuration.Network.FailClosedRouteMetric = integrationFailClosedRouteMetric
	configuration.PacketFilter.FilterTable = integrationFilterTable
	configuration.PacketFilter.ForwardGuardChain = "runtime_forward_guard"
	configuration.PacketFilter.LocalEgressChain = "runtime_local_egress"
	configuration.PacketFilter.LocalEgressIPv4Set = "runtime_local_ipv4"
	configuration.PacketFilter.LocalEgressIPv6Set = "runtime_local_ipv6"
	configuration.PacketFilter.NATTable = integrationNATTable
	configuration.PacketFilter.DNSMasqueradeChain = "runtime_dns_snat"
	configuration.PacketFilter.LocalEgress.Enabled = true
	configuration.PacketFilter.LocalEgress.Domains = []string{"control.example.com"}
	configuration.Tailnet.AdvertiseRoutes = []netip.Prefix{advertisedPrefix}
	configuration.Tailnet.AdvertiseExitNode = true
	configuration.InternetCapability.IPv4ProbeURL = "https://ipv4.probe.example.com/status"
	configuration.InternetCapability.IPv6ProbeURL = "https://ipv6.probe.example.com/status"
	configuration.InternetCapability.ProbeValidity = 45 * time.Second
	configuration.Tailnet.PreferenceAuditInterval = 30 * time.Second
	configuration.Tailnet.OperationTimeout = 2 * time.Second
	configuration.Runtime.AuditInterval = 30 * time.Second
	configuration.Runtime.ReconcileTimeout = 15 * time.Second
	configuration.Runtime.EventDebounce = 200 * time.Millisecond
	configuration.Runtime.ReadinessMaximumAge = time.Minute
	configuration.Runtime.DNSLookupTimeout = time.Second
	configuration.Runtime.ShutdownTimeout = 5 * time.Second
	configuration.Coordination.Backend = domain.CoordinationFileLock
	return configuration
}

type staticKernelChecker struct{}

func (staticKernelChecker) Check(context.Context) error { return nil }

type staticInternetCapability struct{}

func (staticInternetCapability) Observe(_ context.Context, proxyLink domain.LinkIdentity) (domain.InternetCapabilitySnapshot, error) {
	now := time.Now()
	fresh := domain.InternetFamilyCapability{
		Initialized: true, Available: true, ObservedAt: now, ValidUntil: now.Add(time.Minute),
	}
	return domain.InternetCapabilitySnapshot{ProxyLink: proxyLink, IPv4: fresh, IPv6: fresh}, nil
}

type staticDNSResolver struct {
	nameServers []netip.Addr
	resolved    []netip.Addr
}

func (resolver *staticDNSResolver) Snapshot(context.Context) (port.DNSResolverSnapshot, error) {
	return staticDNSSnapshot{nameServers: slices.Clone(resolver.nameServers), resolved: slices.Clone(resolver.resolved)}, nil
}

type staticDNSSnapshot struct {
	nameServers []netip.Addr
	resolved    []netip.Addr
}

func (snapshot staticDNSSnapshot) NameServers() []netip.Addr {
	return slices.Clone(snapshot.nameServers)
}

func (snapshot staticDNSSnapshot) Resolve(context.Context, string) ([]netip.Addr, error) {
	return slices.Clone(snapshot.resolved), nil
}

type staticTailnetControl struct {
	mutex sync.Mutex
	state domain.TailnetState
}

func (control *staticTailnetControl) ReadState(context.Context) (domain.TailnetState, error) {
	control.mutex.Lock()
	defer control.mutex.Unlock()
	state := control.state
	state.SelfAddresses = slices.Clone(state.SelfAddresses)
	state.Preferences.AdvertiseRoutes = slices.Clone(state.Preferences.AdvertiseRoutes)
	state.Control.ApprovedRoutes = slices.Clone(state.Control.ApprovedRoutes)
	state.Control.ObservedAt = time.Now()
	return state, nil
}

func (control *staticTailnetControl) WritePreferences(_ context.Context, preferences domain.TailnetPreferences) error {
	control.mutex.Lock()
	defer control.mutex.Unlock()
	control.state.Preferences = domain.NewTailnetPreferences(preferences.AdvertiseRoutes, false)
	return nil
}

func (*staticTailnetControl) Subscribe(ctx context.Context) (<-chan domain.TailnetEvent, <-chan error, error) {
	events := make(chan domain.TailnetEvent)
	eventErrors := make(chan error)
	go func() {
		<-ctx.Done()
		close(events)
		close(eventErrors)
	}()
	return events, eventErrors, nil
}

type reconcileRecord struct {
	trigger string
	report  domain.ReconcileReport
	err     error
}

type recordingMetrics struct {
	mutex   sync.Mutex
	records []reconcileRecord
	changed chan struct{}
}

func newRecordingMetrics() *recordingMetrics {
	return &recordingMetrics{changed: make(chan struct{}, 1)}
}

func (metrics *recordingMetrics) RecordReconcile(trigger string, _ time.Duration, report domain.ReconcileReport, err error) {
	metrics.mutex.Lock()
	metrics.records = append(metrics.records, reconcileRecord{trigger: trigger, report: report, err: err})
	metrics.mutex.Unlock()
	select {
	case metrics.changed <- struct{}{}:
	default:
	}
}

func (*recordingMetrics) SetReady(bool) {}

func (metrics *recordingMetrics) snapshot() []reconcileRecord {
	metrics.mutex.Lock()
	defer metrics.mutex.Unlock()
	return slices.Clone(metrics.records)
}

func (metrics *recordingMetrics) waitForRecord(t *testing.T, count int, timeout time.Duration) []reconcileRecord {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		if records := metrics.snapshot(); len(records) >= count {
			return records
		}
		select {
		case <-metrics.changed:
		case <-timer.C:
			t.Fatalf("reconciliation record count did not reach %d: %#v", count, metrics.snapshot())
		}
	}
}

func findManagedIPv4Default(t *testing.T) vnetlink.Route {
	t.Helper()
	routes, err := vnetlink.RouteListFiltered(vnetlink.FAMILY_V4, &vnetlink.Route{Table: integrationExitRouteTable}, vnetlink.RT_FILTER_TABLE)
	if err != nil {
		t.Fatalf("list managed IPv4 routes: %v", err)
	}
	for _, route := range routes {
		if route.Protocol == integrationRouteProtocol && route.Type == unix.RTN_UNICAST && route.Priority == integrationActiveRouteMetric && isDefault(route.Dst) {
			return route
		}
	}
	t.Fatal("managed IPv4 active default route was not found")
	return vnetlink.Route{}
}

func purgeManagedRouting() error {
	var cleanupErrors []error
	for _, family := range []int{vnetlink.FAMILY_V4, vnetlink.FAMILY_V6} {
		for _, table := range []int{integrationExitRouteTable, integrationLocalEgressRouteTable} {
			routes, err := vnetlink.RouteListFiltered(family, &vnetlink.Route{Table: table}, vnetlink.RT_FILTER_TABLE)
			if err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("list family %d table %d routes: %w", family, table, err))
				continue
			}
			for index := range routes {
				if routes[index].Protocol == integrationRouteProtocol {
					if err := vnetlink.RouteDel(&routes[index]); err != nil {
						cleanupErrors = append(cleanupErrors, fmt.Errorf("delete family %d table %d route: %w", family, table, err))
					}
				}
			}
		}
		rules, err := vnetlink.RuleList(family)
		if err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("list family %d rules: %w", family, err))
			continue
		}
		for index := range rules {
			if rules[index].Protocol == uint8(integrationRouteProtocol) &&
				(rules[index].Priority == integrationExitRulePriority || rules[index].Priority == integrationLocalEgressRulePriority) {
				if err := vnetlink.RuleDel(&rules[index]); err != nil {
					cleanupErrors = append(cleanupErrors, fmt.Errorf("delete family %d priority %d rule: %w", family, rules[index].Priority, err))
				}
			}
		}
	}
	return errors.Join(cleanupErrors...)
}

func purgeNFTables() error {
	connection, err := gnft.New()
	if err != nil {
		return err
	}
	tables, err := connection.ListTables()
	if err != nil {
		return err
	}
	for _, table := range tables {
		if table.Name == integrationFilterTable || table.Name == integrationNATTable {
			connection.DelTable(table)
		}
	}
	return connection.Flush()
}

func addTunnel(t *testing.T, name string, addresses []string) vnetlink.Link {
	t.Helper()
	removeLink(t, name)
	attributes := vnetlink.NewLinkAttrs()
	attributes.Name = name
	link := &vnetlink.Tuntap{LinkAttrs: attributes, Mode: vnetlink.TUNTAP_MODE_TUN, Flags: vnetlink.TUNTAP_DEFAULTS, Queues: 1}
	if err := vnetlink.LinkAdd(link); err != nil {
		t.Fatalf("add TUN %s: %v", name, err)
	}
	if len(link.Fds) != 1 {
		_ = vnetlink.LinkDel(link)
		t.Fatalf("TUN %s returned %d queues, want 1", name, len(link.Fds))
	}
	t.Cleanup(func() {
		_ = vnetlink.LinkDel(link)
		for _, file := range link.Fds {
			_ = file.Close()
		}
	})
	configureLink(t, link, addresses)
	return link
}

func addDummy(t *testing.T, name string, addresses []string) vnetlink.Link {
	t.Helper()
	removeLink(t, name)
	attributes := vnetlink.NewLinkAttrs()
	attributes.Name = name
	link := &vnetlink.Dummy{LinkAttrs: attributes}
	if err := vnetlink.LinkAdd(link); err != nil {
		t.Fatalf("add dummy %s: %v", name, err)
	}
	t.Cleanup(func() { _ = vnetlink.LinkDel(link) })
	configureLink(t, link, addresses)
	return link
}

func configureLink(t *testing.T, link vnetlink.Link, addresses []string) {
	t.Helper()
	for _, value := range addresses {
		prefix := netip.MustParsePrefix(value)
		address := &vnetlink.Addr{IPNet: ipNet(prefix)}
		if prefix.Addr().Is6() {
			address.Flags = unix.IFA_F_NODAD
		}
		if err := vnetlink.AddrAdd(link, address); err != nil {
			t.Fatalf("add address %s to %s: %v", prefix, link.Attrs().Name, err)
		}
	}
	if err := vnetlink.LinkSetUp(link); err != nil {
		t.Fatalf("set link %s up: %v", link.Attrs().Name, err)
	}
}

func removeLink(t *testing.T, name string) {
	t.Helper()
	link, err := vnetlink.LinkByName(name)
	if err == nil {
		if deleteErr := vnetlink.LinkDel(link); deleteErr != nil {
			t.Fatalf("remove stale link %s: %v", name, deleteErr)
		}
		return
	}
	var notFound vnetlink.LinkNotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("inspect stale link %s: %v", name, err)
	}
}

func ipNet(prefix netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: net.IP(prefix.Addr().AsSlice()), Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())}
}

func isDefault(network *net.IPNet) bool {
	if network == nil {
		return true
	}
	ones, _ := network.Mask.Size()
	return ones == 0
}
