package internetprobe

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/port"
)

func TestParseEndpointEnforcesTheStaticHTTPSContract(t *testing.T) {
	valid, err := parseEndpoint("https://probe.example.com/status", domain.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	if valid.hostname != "probe.example.com" || valid.port != "443" || valid.url.String() != "https://probe.example.com/status" {
		t.Fatalf("unexpected normalized endpoint: %#v", valid)
	}
	for _, value := range []string{
		"http://probe.example.com/status",
		"https://192.0.2.1/status",
		"https://user@probe.example.com/status",
		"https://probe.example.com:8443/status",
		"https://probe.example.com/status?token=value",
		"https://probe.example.com/status#fragment",
		"https://probe.example.com",
		"https://invalid_host.example.com/status",
	} {
		if _, err := parseEndpoint(value, domain.IPv4); err == nil {
			t.Fatalf("invalid endpoint %q was accepted", value)
		}
	}
}

func TestValidateResolvedAddressesRequiresExclusivePublicFamily(t *testing.T) {
	ipv4 := netip.MustParseAddr("8.8.8.8")
	ipv6 := netip.MustParseAddr("2606:4700:4700::1111")
	if got, err := validateResolvedAddresses([]netip.Addr{ipv4, ipv4}, domain.IPv4); err != nil || len(got) != 1 || got[0] != ipv4 {
		t.Fatalf("valid ipv4 set was rejected: addresses=%v err=%v", got, err)
	}
	if got, err := validateResolvedAddresses([]netip.Addr{ipv6}, domain.IPv6); err != nil || len(got) != 1 || got[0] != ipv6 {
		t.Fatalf("valid ipv6 set was rejected: addresses=%v err=%v", got, err)
	}
	for _, test := range []struct {
		name   string
		values []netip.Addr
		family domain.AddressFamily
	}{
		{name: "empty", family: domain.IPv4},
		{name: "mixed family", values: []netip.Addr{ipv4, ipv6}, family: domain.IPv4},
		{name: "private", values: []netip.Addr{netip.MustParseAddr("10.0.0.1")}, family: domain.IPv4},
		{name: "cgnat", values: []netip.Addr{netip.MustParseAddr("100.64.0.1")}, family: domain.IPv4},
		{name: "benchmark", values: []netip.Addr{netip.MustParseAddr("198.18.0.1")}, family: domain.IPv4},
		{name: "documentation ipv4", values: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, family: domain.IPv4},
		{name: "as112 ipv4", values: []netip.Addr{netip.MustParseAddr("192.31.196.1")}, family: domain.IPv4},
		{name: "documentation ipv6", values: []netip.Addr{netip.MustParseAddr("2001:db8::1")}, family: domain.IPv6},
		{name: "documentation ipv6 current", values: []netip.Addr{netip.MustParseAddr("3fff::1")}, family: domain.IPv6},
		{name: "srv6 sid", values: []netip.Addr{netip.MustParseAddr("5f00::1")}, family: domain.IPv6},
		{name: "nat64", values: []netip.Addr{netip.MustParseAddr("64:ff9b::808:808")}, family: domain.IPv6},
		{name: "link local", values: []netip.Addr{netip.MustParseAddr("fe80::1")}, family: domain.IPv6},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := validateResolvedAddresses(test.values, test.family); err == nil {
				t.Fatalf("unsafe address set was accepted: %v", test.values)
			}
		})
	}
	tooMany := make([]netip.Addr, maximumResolvedAddresses+1)
	for index := range tooMany {
		tooMany[index] = netip.AddrFrom4([4]byte{8, 8, 8, byte(index + 1)})
	}
	if _, err := validateResolvedAddresses(tooMany, domain.IPv4); err == nil {
		t.Fatal("unbounded DNS answer set was accepted")
	}
}

func TestResolveScopesDualStackEndpointToRequestedFamily(t *testing.T) {
	prober, err := New(
		"https://cp.cloudflare.com/generate_204",
		"https://cp.cloudflare.com/generate_204",
		time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &familyResolver{
		addresses: map[string][]netip.Addr{
			"ip4": {netip.MustParseAddr("104.16.132.229")},
			"ip6": {netip.MustParseAddr("2606:4700::6810:84e5")},
		},
	}
	prober.resolver = resolver

	for _, family := range []domain.AddressFamily{domain.IPv4, domain.IPv6} {
		addresses, resolveErr := prober.resolve(context.Background(), prober.endpoints[family])
		if resolveErr != nil {
			t.Fatalf("resolve IPv%d endpoint: %v", family, resolveErr)
		}
		if len(addresses) != 1 || domain.FamilyOfAddress(addresses[0]) != family {
			t.Fatalf("IPv%d resolution returned unexpected addresses: %v", family, addresses)
		}
	}

	wantLookups := []string{"ip4:cp.cloudflare.com", "ip6:cp.cloudflare.com"}
	if !slices.Equal(resolver.lookups, wantLookups) {
		t.Fatalf("family-scoped lookups = %v, want %v", resolver.lookups, wantLookups)
	}
}

func TestProbePinsValidatedAddressAndEnforcesTLSAndResponse(t *testing.T) {
	requestObserved := make(chan *http.Request, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestObserved <- request
		writer.WriteHeader(http.StatusNoContent)
	}))
	server.StartTLS()
	t.Cleanup(server.Close)

	prober := newTestProber(t, server)
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	request := port.InternetEgressProbeRequest{
		Family: domain.IPv4, ProxyLink: domain.LinkIdentity{Index: 7, Name: "proxy-test"}, PacketMark: 0x11,
	}
	if err := prober.Probe(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	select {
	case observed := <-requestObserved:
		if observed.Host != "example.com" || observed.UserAgent() != "" || observed.Method != http.MethodGet || observed.URL.Path != "/status" {
			t.Fatalf("probe request crossed its fixed contract: host=%q user_agent=%q method=%q path=%q", observed.Host, observed.UserAgent(), observed.Method, observed.URL.Path)
		}
	case <-time.After(time.Second):
		t.Fatal("probe request was not observed")
	}
	dial := prober.dialer.(*recordingDialer).snapshot()
	if dial.network != "tcp4" || dial.address != "8.8.8.8:443" || dial.link != request.ProxyLink || dial.mark != request.PacketMark {
		t.Fatalf("probe did not pin the validated address and socket identity: %#v", dial)
	}
}

func TestProbeRejectsRedirectStatusAndUntrustedTLS(t *testing.T) {
	for _, test := range []struct {
		name    string
		handler http.Handler
		want    string
	}{
		{
			name: "redirect",
			handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				http.Redirect(writer, &http.Request{}, "https://example.com/other", http.StatusFound)
			}),
			want: "redirect is prohibited",
		},
		{
			name: "wrong status",
			handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(http.StatusOK)
			}),
			want: "status 200",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewUnstartedServer(test.handler)
			server.StartTLS()
			defer server.Close()
			prober := newTestProber(t, server)
			err := prober.Probe(context.Background(), port.InternetEgressProbeRequest{
				Family: domain.IPv4, ProxyLink: domain.LinkIdentity{Index: 7, Name: "proxy-test"}, PacketMark: 0x11,
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("probe failure = %v, want fragment %q", err, test.want)
			}
		})
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	prober := newTestProber(t, server)
	prober.rootCAs = nil
	if err := prober.Probe(context.Background(), port.InternetEgressProbeRequest{
		Family: domain.IPv4, ProxyLink: domain.LinkIdentity{Index: 7, Name: "proxy-test"}, PacketMark: 0x11,
	}); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("untrusted TLS endpoint was accepted: %v", err)
	}
}

func TestProbeHonorsParentCancellation(t *testing.T) {
	prober, err := New("https://example.com/status", "https://ipv6.example.com/status", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	prober.resolver = &fakeResolver{addresses: map[string][]netip.Addr{"example.com": {netip.MustParseAddr("8.8.8.8")}}}
	prober.dialer = blockingDialer{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = prober.Probe(ctx, port.InternetEgressProbeRequest{
		Family: domain.IPv4, ProxyLink: domain.LinkIdentity{Index: 7, Name: "proxy-test"}, PacketMark: 0x11,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled probe error = %v, want context canceled", err)
	}
}

func newTestProber(t *testing.T, server *httptest.Server) *Prober {
	t.Helper()
	prober, err := New("https://example.com/status", "https://ipv6.example.com/status", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	prober.resolver = &fakeResolver{addresses: map[string][]netip.Addr{"example.com": {netip.MustParseAddr("8.8.8.8")}}}
	prober.dialer = &recordingDialer{target: server.Listener.Addr().String()}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(server.Certificate())
	prober.rootCAs = rootCAs
	return prober
}

type fakeResolver struct {
	addresses map[string][]netip.Addr
	err       error
}

type familyResolver struct {
	addresses map[string][]netip.Addr
	lookups   []string
}

func (resolver *familyResolver) LookupNetIP(_ context.Context, network, hostname string) ([]netip.Addr, error) {
	resolver.lookups = append(resolver.lookups, network+":"+hostname)
	return resolver.addresses[network], nil
}

func (resolver *fakeResolver) LookupNetIP(_ context.Context, _, hostname string) ([]netip.Addr, error) {
	return resolver.addresses[hostname], resolver.err
}

type dialObservation struct {
	network string
	address string
	link    domain.LinkIdentity
	mark    uint32
}

type recordingDialer struct {
	mutex  sync.Mutex
	target string
	last   dialObservation
}

func (dialer *recordingDialer) DialContext(ctx context.Context, network, address string, link domain.LinkIdentity, mark uint32) (net.Conn, error) {
	dialer.mutex.Lock()
	dialer.last = dialObservation{network: network, address: address, link: link, mark: mark}
	target := dialer.target
	dialer.mutex.Unlock()
	return (&net.Dialer{}).DialContext(ctx, "tcp", target)
}

func (dialer *recordingDialer) snapshot() dialObservation {
	dialer.mutex.Lock()
	defer dialer.mutex.Unlock()
	return dialer.last
}

type blockingDialer struct{}

func (blockingDialer) DialContext(ctx context.Context, _, _ string, _ domain.LinkIdentity, _ uint32) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
