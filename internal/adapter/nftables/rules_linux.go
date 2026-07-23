//go:build linux

package nftables

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"slices"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	gnft "github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

const (
	nfprotoIPv4   = 2
	nfprotoIPv6   = 10
	ipProtocolTCP = 6
	ipProtocolUDP = 17
)

type ruleSpec struct {
	expressions []expr.Any
	userData    []byte
}

type setSpec struct {
	name     string
	keyType  gnft.SetDatatype
	elements []gnft.SetElement
	comment  string
}

func filterSetSpecs(policy domain.PacketFilterPolicy) []setSpec {
	if !policy.LocalEgress.Enabled {
		return nil
	}
	revision := policy.FilterRevision()
	var specifications []setSpec
	if len(policy.LocalEgress.IPv4) > 0 {
		specifications = append(specifications, setSpec{
			name: policy.LocalEgressIPv4Set, keyType: gnft.TypeIPAddr,
			elements: addressSetElements(policy.LocalEgress.IPv4), comment: setComment("filter", revision, policy.LocalEgressIPv4Set),
		})
	}
	if len(policy.LocalEgress.IPv6) > 0 {
		specifications = append(specifications, setSpec{
			name: policy.LocalEgressIPv6Set, keyType: gnft.TypeIP6Addr,
			elements: addressSetElements(policy.LocalEgress.IPv6), comment: setComment("filter", revision, policy.LocalEgressIPv6Set),
		})
	}
	return specifications
}

func filterRuleSpecs(policy domain.PacketFilterPolicy, sets map[string]*gnft.Set) (map[string][]ruleSpec, error) {
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("validate filter policy: %w", err)
	}
	result := map[string][]ruleSpec{
		policy.ForwardGuardChain: nil,
		policy.LocalEgressChain:  nil,
	}
	if policy.GateClosed {
		result[policy.ForwardGuardChain] = []ruleSpec{
			{expressions: prefixVerdictExpressions(policy.TailnetIPv4Prefix, true, expr.VerdictDrop)},
			{expressions: prefixVerdictExpressions(policy.TailnetIPv4Prefix, false, expr.VerdictDrop)},
			{expressions: prefixVerdictExpressions(policy.TailnetIPv6Prefix, true, expr.VerdictDrop)},
			{expressions: prefixVerdictExpressions(policy.TailnetIPv6Prefix, false, expr.VerdictDrop)},
		}
	}
	if policy.LocalEgress.Enabled {
		families := []struct {
			addresses []netip.Addr
			setName   string
		}{
			{addresses: policy.LocalEgress.IPv4, setName: policy.LocalEgressIPv4Set},
			{addresses: policy.LocalEgress.IPv6, setName: policy.LocalEgressIPv6Set},
		}
		protocols := slices.Clone(policy.LocalEgress.Protocols)
		slices.Sort(protocols)
		ports := slices.Clone(policy.LocalEgress.Ports)
		slices.Sort(ports)
		for _, family := range families {
			if len(family.addresses) == 0 {
				continue
			}
			set := sets[family.setName]
			if set == nil {
				return nil, fmt.Errorf("required nftables set %s is unavailable", family.setName)
			}
			for _, protocol := range protocols {
				for _, port := range ports {
					result[policy.LocalEgressChain] = append(result[policy.LocalEgressChain], ruleSpec{
						expressions: localEgressExpressions(family.addresses[0], set, protocol, port, policy.LocalEgress.Mark),
					})
				}
			}
		}
	}
	for chainName, specifications := range result {
		for index := range specifications {
			specifications[index].userData = ruleUserData("filter", chainName, policy.FilterRevision(), index)
		}
		result[chainName] = specifications
	}
	return result, nil
}

func natRuleSpecs(policy domain.PacketFilterPolicy) ([]ruleSpec, error) {
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("validate NAT policy: %w", err)
	}
	targets := slices.Clone(policy.DNSTargets)
	slices.SortFunc(targets, compareDNSMasqueradeTargets)
	var specifications []ruleSpec
	for _, target := range targets {
		prefix := policy.TailnetIPv6Prefix
		if target.Address.Is4() {
			prefix = policy.TailnetIPv4Prefix
		}
		for _, protocol := range []domain.TransportProtocol{domain.TransportTCP, domain.TransportUDP} {
			specifications = append(specifications, ruleSpec{
				expressions: dnsMasqueradeExpressions(prefix, target.Address.Unmap(), target.OutputInterface, protocol),
			})
		}
	}
	for index := range specifications {
		specifications[index].userData = ruleUserData("nat", policy.DNSMasqueradeChain, policy.NATRevision(), index)
	}
	return specifications, nil
}

func prefixVerdictExpressions(prefix netip.Prefix, source bool, verdict expr.VerdictKind) []expr.Any {
	prefix = prefix.Masked()
	address := prefix.Addr()
	offset := uint32(16)
	nfproto := byte(nfprotoIPv4)
	if source {
		offset = 12
	}
	if address.Is6() {
		nfproto = nfprotoIPv6
		offset = 24
		if source {
			offset = 8
		}
	}
	mask := []byte(net.CIDRMask(prefix.Bits(), address.BitLen()))
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{nfproto}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: uint32(len(address.AsSlice()))},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: uint32(len(mask)), Mask: mask, Xor: make([]byte, len(mask))},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: address.AsSlice()},
		&expr.Verdict{Kind: verdict},
	}
}

func localEgressExpressions(address netip.Addr, set *gnft.Set, protocol domain.TransportProtocol, port uint16, mark uint32) []expr.Any {
	offset := uint32(16)
	nfproto := byte(nfprotoIPv4)
	if address.Is6() {
		offset = 24
		nfproto = nfprotoIPv6
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{nfproto}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: uint32(len(address.AsSlice()))},
		&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocolNumber(protocol)}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, port)},
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(^domain.LocalEgressPacketMarkMask),
			Xor:            binaryutil.NativeEndian.PutUint32(mark),
		},
		&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 1},
	}
}

func dnsMasqueradeExpressions(sourcePrefix netip.Prefix, destination netip.Addr, outputInterface string, protocol domain.TransportProtocol) []expr.Any {
	sourcePrefix = sourcePrefix.Masked()
	sourceOffset := uint32(12)
	destinationOffset := uint32(16)
	nfproto := byte(nfprotoIPv4)
	if destination.Is6() {
		sourceOffset = 8
		destinationOffset = 24
		nfproto = nfprotoIPv6
	}
	mask := []byte(net.CIDRMask(sourcePrefix.Bits(), sourcePrefix.Addr().BitLen()))
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{nfproto}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: sourceOffset, Len: uint32(len(sourcePrefix.Addr().AsSlice()))},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: uint32(len(mask)), Mask: mask, Xor: make([]byte, len(mask))},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: sourcePrefix.Addr().AsSlice()},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: destinationOffset, Len: uint32(len(destination.AsSlice()))},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: destination.AsSlice()},
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: interfaceNameBytes(outputInterface)},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocolNumber(protocol)}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, 53)},
		&expr.Masq{},
	}
}

func metadataRuleSpec(component, revision string) ruleSpec {
	return ruleSpec{
		expressions: []expr.Any{&expr.Verdict{Kind: expr.VerdictReturn}},
		userData:    []byte(fmt.Sprintf("tailscale-gateway-agent:v1:%s:%s:metadata", component, revision)),
	}
}

func ruleUserData(component, chain, revision string, index int) []byte {
	return []byte(fmt.Sprintf("tailscale-gateway-agent:v1:%s:%s:%s:%04d", component, chain, revision, index))
}

func setComment(component, revision, name string) string {
	return fmt.Sprintf("tailscale-gateway-agent:v1:%s:%s:%s", component, revision, name)
}

func addressSetElements(addresses []netip.Addr) []gnft.SetElement {
	addresses = slices.Clone(addresses)
	slices.SortFunc(addresses, func(left, right netip.Addr) int { return left.Compare(right) })
	addresses = slices.Compact(addresses)
	result := make([]gnft.SetElement, 0, len(addresses))
	for _, address := range addresses {
		result = append(result, gnft.SetElement{Key: slices.Clone(address.AsSlice())})
	}
	return result
}

func compareDNSMasqueradeTargets(left, right domain.DNSMasqueradeTarget) int {
	if comparison := left.Address.Unmap().Compare(right.Address.Unmap()); comparison != 0 {
		return comparison
	}
	if left.OutputInterface < right.OutputInterface {
		return -1
	}
	if left.OutputInterface > right.OutputInterface {
		return 1
	}
	return 0
}

func protocolNumber(protocol domain.TransportProtocol) byte {
	if protocol == domain.TransportUDP {
		return ipProtocolUDP
	}
	return ipProtocolTCP
}

func interfaceNameBytes(name string) []byte {
	result := make([]byte, domain.MaximumInterfaceNameBytes+1)
	copy(result, name)
	return result
}
