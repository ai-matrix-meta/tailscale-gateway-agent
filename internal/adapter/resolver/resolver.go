package resolver

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/port"
)

const maximumResolvedAddresses = 64
const maximumNameServers = 16

type lookupResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type Resolver struct {
	resolverFactory func([]netip.Addr) lookupResolver
	resolverPath    string
	lookupTimeout   time.Duration
}

type resolverSnapshot struct {
	nameServers   []netip.Addr
	resolver      lookupResolver
	lookupTimeout time.Duration
}

func New(resolverPath string, lookupTimeout time.Duration) *Resolver {
	return &Resolver{resolverFactory: newNameServerPool, resolverPath: resolverPath, lookupTimeout: lookupTimeout}
}

func (resolver *Resolver) Snapshot(ctx context.Context) (port.DNSResolverSnapshot, error) {
	nameServers, err := resolver.readNameServers(ctx)
	if err != nil {
		return nil, err
	}
	return &resolverSnapshot{
		nameServers: slices.Clone(nameServers), resolver: resolver.resolverFactory(nameServers), lookupTimeout: resolver.lookupTimeout,
	}, nil
}

func (snapshot *resolverSnapshot) NameServers() []netip.Addr {
	return slices.Clone(snapshot.nameServers)
}

func (snapshot *resolverSnapshot) Resolve(ctx context.Context, domainName string) ([]netip.Addr, error) {
	lookupContext, cancel := context.WithTimeout(ctx, snapshot.lookupTimeout)
	defer cancel()
	absoluteName := strings.TrimSuffix(domainName, ".") + "."
	addresses, err := snapshot.resolver.LookupNetIP(lookupContext, "ip", absoluteName)
	if err != nil {
		return nil, err
	}
	result := normalizeAddresses(addresses)
	if len(result) == 0 {
		return nil, errors.New("resolver returned no usable addresses")
	}
	if len(result) > maximumResolvedAddresses {
		return nil, fmt.Errorf("resolved address count %d exceeds limit %d", len(result), maximumResolvedAddresses)
	}
	return result, nil
}

func (resolver *Resolver) readNameServers(ctx context.Context) ([]netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := os.Open(resolver.resolverPath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", resolver.resolverPath, err)
	}
	defer file.Close()

	var addresses []netip.Addr
	var parseErrors []error
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 64*1024)
	lineNumber := 0
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lineNumber++
		line := scanner.Text()
		if commentIndex := strings.IndexAny(line, "#;"); commentIndex >= 0 {
			line = line[:commentIndex]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "nameserver" {
			continue
		}
		if len(fields) != 2 {
			parseErrors = append(parseErrors, fmt.Errorf("%s line %d has an invalid nameserver directive", resolver.resolverPath, lineNumber))
			continue
		}
		address, parseErr := netip.ParseAddr(fields[1])
		if parseErr != nil || address.Zone() != "" {
			parseErrors = append(parseErrors, fmt.Errorf("%s line %d contains invalid nameserver %q", resolver.resolverPath, lineNumber, fields[1]))
			continue
		}
		addresses = append(addresses, address.Unmap())
	}
	if err := scanner.Err(); err != nil {
		parseErrors = append(parseErrors, fmt.Errorf("scan %s: %w", resolver.resolverPath, err))
	}
	addresses = uniqueAddresses(addresses)
	if len(addresses) == 0 {
		parseErrors = append(parseErrors, fmt.Errorf("%s contains no usable nameserver", resolver.resolverPath))
	}
	if len(addresses) > maximumNameServers {
		parseErrors = append(parseErrors, fmt.Errorf("nameserver count %d exceeds limit %d", len(addresses), maximumNameServers))
	}
	if err := errors.Join(parseErrors...); err != nil {
		return nil, err
	}
	return addresses, nil
}

type nameServerLookup struct {
	address  netip.Addr
	resolver lookupResolver
}

type nameServerPool struct {
	servers []nameServerLookup
}

func newNameServerPool(addresses []netip.Addr) lookupResolver {
	pool := &nameServerPool{servers: make([]nameServerLookup, 0, len(addresses))}
	for _, address := range addresses {
		endpoint := net.JoinHostPort(address.String(), "53")
		dialer := &net.Dialer{}
		lookup := &net.Resolver{
			PreferGo:     true,
			StrictErrors: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				if network != "udp" && network != "tcp" {
					return nil, fmt.Errorf("unsupported DNS transport %q", network)
				}
				return dialer.DialContext(ctx, network, endpoint)
			},
		}
		pool.servers = append(pool.servers, nameServerLookup{address: address, resolver: lookup})
	}
	return pool
}

func (pool *nameServerPool) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if len(pool.servers) == 0 {
		return nil, errors.New("resolver pool contains no nameservers")
	}
	var lookupErrors []error
	for index, server := range pool.servers {
		attemptContext, cancel := resolverAttemptContext(ctx, len(pool.servers)-index)
		addresses, err := server.resolver.LookupNetIP(attemptContext, network, host)
		cancel()
		if err == nil && len(addresses) > 0 {
			return addresses, nil
		}
		if err == nil {
			err = errors.New("resolver returned no addresses")
		}
		lookupErrors = append(lookupErrors, fmt.Errorf("query DNS nameserver %s: %w", server.address, err))
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	return nil, errors.Join(lookupErrors...)
}

func resolverAttemptContext(ctx context.Context, remainingServers int) (context.Context, context.CancelFunc) {
	deadline, bounded := ctx.Deadline()
	if !bounded || remainingServers <= 1 {
		return context.WithCancel(ctx)
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, remaining/time.Duration(remainingServers))
}

func normalizeAddresses(addresses []netip.Addr) []netip.Addr {
	result := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if address.IsValid() && address.Zone() == "" {
			result = append(result, address)
		}
	}
	slices.SortFunc(result, func(left, right netip.Addr) int { return left.Compare(right) })
	return slices.Compact(result)
}

func uniqueAddresses(addresses []netip.Addr) []netip.Addr {
	result := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsValid() || address.Zone() != "" {
			continue
		}
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		result = append(result, address)
	}
	return result
}
