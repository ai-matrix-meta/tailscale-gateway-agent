//go:build !linux

package nftables

import (
	"context"
	"errors"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
)

var errUnsupported = errors.New("nftables is supported only on Linux")

type Store struct{}

func New() *Store { return &Store{} }
func (s *Store) Observe(context.Context, domain.PacketFilterPolicy) (domain.PacketFilterObservation, error) {
	return domain.PacketFilterObservation{}, errUnsupported
}
func (s *Store) Apply(context.Context, domain.PacketFilterPolicy, domain.PacketFilterObservation) error {
	return errUnsupported
}
