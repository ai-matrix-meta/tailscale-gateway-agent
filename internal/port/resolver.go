package port

import (
	"context"
	"net/netip"
)

type DNSResolver interface {
	Snapshot(context.Context) (DNSResolverSnapshot, error)
}

type DNSResolverSnapshot interface {
	NameServers() []netip.Addr
	Resolve(context.Context, string) ([]netip.Addr, error)
}
