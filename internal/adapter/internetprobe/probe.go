package internetprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/port"
)

const (
	maximumResolvedAddresses = 8
	maximumResponseHeaders   = 8 << 10
)

var errRedirectRejected = errors.New("capability probe redirect is prohibited")

type endpoint struct {
	url      *url.URL
	hostname string
	port     string
	family   domain.AddressFamily
}

type addressResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type markedDeviceDialer interface {
	DialContext(context.Context, string, string, domain.LinkIdentity, uint32) (net.Conn, error)
}

type Adapter struct {
	endpoints map[domain.AddressFamily]endpoint
	timeout   time.Duration
	resolver  addressResolver
	dialer    markedDeviceDialer
	rootCAs   *x509.CertPool
}

func New(ipv4URL, ipv6URL string, timeout time.Duration) (*Adapter, error) {
	if timeout <= 0 {
		return nil, errors.New("capability probe timeout must be positive")
	}
	ipv4, err := parseEndpoint(ipv4URL, domain.IPv4)
	if err != nil {
		return nil, fmt.Errorf("parse ipv4 capability endpoint: %w", err)
	}
	ipv6, err := parseEndpoint(ipv6URL, domain.IPv6)
	if err != nil {
		return nil, fmt.Errorf("parse ipv6 capability endpoint: %w", err)
	}
	return &Adapter{
		endpoints: map[domain.AddressFamily]endpoint{domain.IPv4: ipv4, domain.IPv6: ipv6},
		timeout:   timeout,
		resolver:  net.DefaultResolver,
		dialer:    systemMarkedDeviceDialer{},
	}, nil
}

func (adapter *Adapter) Probe(ctx context.Context, request port.InternetEgressProbeRequest) error {
	if ctx == nil {
		return errors.New("internet capability probe context is required")
	}
	if err := request.Validate(); err != nil {
		return err
	}
	target, exists := adapter.endpoints[request.Family]
	if !exists {
		return fmt.Errorf("internet capability endpoint for family %d is not configured", request.Family)
	}
	addresses, err := adapter.resolve(ctx, target)
	if err != nil {
		return err
	}

	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            adapter.pinnedDialContext(request, target, addresses),
		ForceAttemptHTTP2:      false,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		TLSHandshakeTimeout:    adapter.timeout,
		ResponseHeaderTimeout:  adapter.timeout,
		ExpectContinueTimeout:  0,
		MaxResponseHeaderBytes: maximumResponseHeaders,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: target.hostname,
			RootCAs:    adapter.rootCAs,
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   adapter.timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errRedirectRejected
		},
	}
	probeContext, cancel := context.WithTimeout(ctx, adapter.timeout)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(probeContext, http.MethodGet, target.url.String(), nil)
	if err != nil {
		return fmt.Errorf("build capability probe request: %w", err)
	}
	// A nil User-Agent value suppresses net/http's ambient default header.
	httpRequest.Header["User-Agent"] = nil
	response, err := client.Do(httpRequest)
	if err != nil {
		return fmt.Errorf("execute capability probe: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("capability probe returned HTTP status %d, want 204", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 2))
	if err != nil {
		return fmt.Errorf("read capability probe response: %w", err)
	}
	if len(body) != 0 {
		return errors.New("capability probe returned a non-empty response body")
	}
	return nil
}

func (adapter *Adapter) resolve(ctx context.Context, target endpoint) ([]netip.Addr, error) {
	addresses, err := adapter.resolver.LookupNetIP(ctx, "ip", target.hostname)
	if err != nil {
		return nil, fmt.Errorf("resolve capability endpoint: %w", err)
	}
	validated, err := validateResolvedAddresses(addresses, target.family)
	if err != nil {
		return nil, fmt.Errorf("validate capability endpoint addresses: %w", err)
	}
	return validated, nil
}

func (adapter *Adapter) pinnedDialContext(request port.InternetEgressProbeRequest, target endpoint, addresses []netip.Addr) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		network := "tcp4"
		if request.Family == domain.IPv6 {
			network = "tcp6"
		}
		var dialErrors []error
		for _, address := range addresses {
			connection, err := adapter.dialer.DialContext(
				ctx, network, net.JoinHostPort(address.String(), target.port), request.ProxyLink, request.PacketMark,
			)
			if err == nil {
				return connection, nil
			}
			dialErrors = append(dialErrors, fmt.Errorf("dial validated address: %w", err))
			if ctx.Err() != nil {
				break
			}
		}
		return nil, errors.Join(dialErrors...)
	}
}

func parseEndpoint(value string, family domain.AddressFamily) (endpoint, error) {
	if strings.Contains(value, "#") {
		return endpoint{}, errors.New("endpoint URL must not contain a fragment")
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil {
		return endpoint{}, fmt.Errorf("endpoint URL is invalid: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Opaque != "" {
		return endpoint{}, errors.New("endpoint URL scheme must be exactly https")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return endpoint{}, errors.New("endpoint URL must not contain user information, query, or fragment")
	}
	hostname := strings.ToLower(parsed.Hostname())
	if !validDNSName(hostname) {
		return endpoint{}, errors.New("endpoint host must be a valid DNS name")
	}
	if _, err := netip.ParseAddr(hostname); err == nil {
		return endpoint{}, errors.New("endpoint host must not be an IP literal")
	}
	explicitPort := parsed.Port()
	portNumber := explicitPort
	if portNumber == "" {
		portNumber = "443"
	} else if portNumber != "443" {
		return endpoint{}, errors.New("endpoint port must be 443 when specified")
	}
	if parsed.Path == "" || !strings.HasPrefix(parsed.EscapedPath(), "/") {
		return endpoint{}, errors.New("endpoint path must be absolute and non-empty")
	}
	parsed.Scheme = "https"
	parsed.Host = hostname
	if explicitPort != "" {
		parsed.Host = net.JoinHostPort(hostname, portNumber)
	}
	return endpoint{url: parsed, hostname: hostname, port: portNumber, family: family}, nil
}

func validDNSName(value string) bool {
	if value == "" || len(value) > 253 || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
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

func validateResolvedAddresses(values []netip.Addr, family domain.AddressFamily) ([]netip.Addr, error) {
	if len(values) == 0 || len(values) > maximumResolvedAddresses {
		return nil, fmt.Errorf("endpoint resolved to %d addresses; expected 1..%d", len(values), maximumResolvedAddresses)
	}
	seen := make(map[netip.Addr]struct{}, len(values))
	addresses := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		address := value.Unmap()
		if !address.IsValid() || address.Zone() != "" || domain.FamilyOfAddress(address) != family {
			return nil, fmt.Errorf("endpoint address %q does not exclusively match family %d", value, family)
		}
		if !publicInternetAddress(address) {
			return nil, fmt.Errorf("endpoint address %s is not a public Internet destination", address)
		}
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		addresses = append(addresses, address)
	}
	if len(addresses) == 0 {
		return nil, errors.New("endpoint resolution contains no unique addresses")
	}
	slices.SortFunc(addresses, func(left, right netip.Addr) int { return left.Compare(right) })
	return addresses, nil
}

var prohibitedInternetPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
}

func publicInternetAddress(address netip.Addr) bool {
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range prohibitedInternetPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}
