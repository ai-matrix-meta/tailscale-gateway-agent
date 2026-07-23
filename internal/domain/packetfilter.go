package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

const (
	ReservedPacketFilterMetadataChain        = "_agent_metadata"
	LocalEgressPacketMarkMask         uint32 = 0x0000ffff
)

type TransportProtocol string

const (
	TransportTCP TransportProtocol = "tcp"
	TransportUDP TransportProtocol = "udp"
)

type DNSMasqueradeTarget struct {
	Address         netip.Addr
	OutputInterface string
}

type LocalEgressPolicy struct {
	Enabled   bool
	IPv4      []netip.Addr
	IPv6      []netip.Addr
	Protocols []TransportProtocol
	Ports     []uint16
	Mark      uint32
}

type PacketFilterPolicy struct {
	FilterTable        string
	ForwardGuardChain  string
	LocalEgressChain   string
	LocalEgressIPv4Set string
	LocalEgressIPv6Set string
	NATTable           string
	DNSMasqueradeChain string
	GateClosed         bool
	TailnetIPv4Prefix  netip.Prefix
	TailnetIPv6Prefix  netip.Prefix
	DNSTargets         []DNSMasqueradeTarget
	LocalEgress        LocalEgressPolicy
}

func (policy PacketFilterPolicy) Validate() error {
	var validationErrors []error
	identifiers := []struct {
		name  string
		value string
	}{
		{name: "filter table", value: policy.FilterTable},
		{name: "forward guard chain", value: policy.ForwardGuardChain},
		{name: "local-egress chain", value: policy.LocalEgressChain},
		{name: "local-egress IPv4 set", value: policy.LocalEgressIPv4Set},
		{name: "local-egress IPv6 set", value: policy.LocalEgressIPv6Set},
		{name: "NAT table", value: policy.NATTable},
		{name: "DNS masquerade chain", value: policy.DNSMasqueradeChain},
	}
	seenIdentifiers := map[string]string{ReservedPacketFilterMetadataChain: "reserved metadata chain"}
	for _, identifier := range identifiers {
		if !nftIdentifierPattern.MatchString(identifier.value) {
			validationErrors = append(validationErrors, fmt.Errorf("%s %q is not a valid nftables identifier", identifier.name, identifier.value))
		}
		if previous, exists := seenIdentifiers[identifier.value]; exists {
			validationErrors = append(validationErrors, fmt.Errorf("%s and %s must use distinct nftables identifiers", previous, identifier.name))
		}
		seenIdentifiers[identifier.value] = identifier.name
	}
	if !validMaskedPrefix(policy.TailnetIPv4Prefix, IPv4) {
		validationErrors = append(validationErrors, fmt.Errorf("tailnet IPv4 prefix %q is invalid", policy.TailnetIPv4Prefix))
	}
	if !validMaskedPrefix(policy.TailnetIPv6Prefix, IPv6) {
		validationErrors = append(validationErrors, fmt.Errorf("tailnet IPv6 prefix %q is invalid", policy.TailnetIPv6Prefix))
	}

	seenTargets := make(map[netip.Addr]string, len(policy.DNSTargets))
	for _, target := range policy.DNSTargets {
		address := target.Address.Unmap()
		if !address.IsValid() || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
			validationErrors = append(validationErrors, fmt.Errorf("DNS masquerade target address %q is invalid", target.Address))
		}
		if err := (LinkIdentity{Index: 1, Name: target.OutputInterface}).Validate(); err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("DNS masquerade target %s has invalid output interface: %w", address, err))
		}
		if previousInterface, duplicate := seenTargets[address]; duplicate {
			validationErrors = append(validationErrors, fmt.Errorf("DNS masquerade address %s has multiple output interfaces %q and %q", address, previousInterface, target.OutputInterface))
		}
		seenTargets[address] = target.OutputInterface
	}

	local := policy.LocalEgress
	if local.Enabled {
		if len(local.IPv4)+len(local.IPv6) == 0 {
			validationErrors = append(validationErrors, errors.New("enabled local-egress policy requires at least one destination address"))
		}
		if len(local.Protocols) == 0 || len(local.Ports) == 0 || local.Mark == 0 {
			validationErrors = append(validationErrors, errors.New("enabled local-egress policy requires protocols, ports, and a non-zero mark"))
		}
		if local.Mark&^LocalEgressPacketMarkMask != 0 {
			validationErrors = append(validationErrors, errors.New("local-egress mark must be within the low 16 bits"))
		}
	} else if len(local.IPv4) != 0 || len(local.IPv6) != 0 || len(local.Protocols) != 0 || len(local.Ports) != 0 || local.Mark != 0 {
		validationErrors = append(validationErrors, errors.New("disabled local-egress policy must not carry addresses, protocols, ports, or a mark"))
	}
	if err := validateAddressFamilyList("local-egress IPv4 address", local.IPv4, IPv4); err != nil {
		validationErrors = append(validationErrors, err)
	}
	if err := validateAddressFamilyList("local-egress IPv6 address", local.IPv6, IPv6); err != nil {
		validationErrors = append(validationErrors, err)
	}
	seenProtocols := make(map[TransportProtocol]struct{}, len(local.Protocols))
	for _, protocol := range local.Protocols {
		if protocol != TransportTCP && protocol != TransportUDP {
			validationErrors = append(validationErrors, fmt.Errorf("local-egress protocol %q is unsupported", protocol))
		}
		if _, duplicate := seenProtocols[protocol]; duplicate {
			validationErrors = append(validationErrors, fmt.Errorf("local-egress protocol %q is duplicated", protocol))
		}
		seenProtocols[protocol] = struct{}{}
	}
	seenPorts := make(map[uint16]struct{}, len(local.Ports))
	for _, port := range local.Ports {
		if port == 0 {
			validationErrors = append(validationErrors, errors.New("local-egress port must be non-zero"))
		}
		if _, duplicate := seenPorts[port]; duplicate {
			validationErrors = append(validationErrors, fmt.Errorf("local-egress port %d is duplicated", port))
		}
		seenPorts[port] = struct{}{}
	}
	return errors.Join(validationErrors...)
}

type PacketFilterObservation struct {
	FilterTableExists bool
	FilterRevision    string
	NATTableExists    bool
	NATRevision       string
}

func (policy PacketFilterPolicy) FilterRevision() string {
	fields := []string{
		policy.FilterTable,
		policy.ForwardGuardChain,
		policy.LocalEgressChain,
		policy.LocalEgressIPv4Set,
		policy.LocalEgressIPv6Set,
		fmt.Sprintf("gate=%t", policy.GateClosed),
		policy.TailnetIPv4Prefix.String(),
		policy.TailnetIPv6Prefix.String(),
		fmt.Sprintf("local-enabled=%t", policy.LocalEgress.Enabled),
	}
	if policy.LocalEgress.Enabled {
		fields = append(fields, fmt.Sprintf("mark=%d", policy.LocalEgress.Mark))
		for _, address := range sortedAddresses(policy.LocalEgress.IPv4) {
			fields = append(fields, "ipv4="+address.String())
		}
		for _, address := range sortedAddresses(policy.LocalEgress.IPv6) {
			fields = append(fields, "ipv6="+address.String())
		}
		protocols := slices.Clone(policy.LocalEgress.Protocols)
		slices.Sort(protocols)
		for _, protocol := range protocols {
			fields = append(fields, "protocol="+string(protocol))
		}
		ports := slices.Clone(policy.LocalEgress.Ports)
		slices.Sort(ports)
		for _, port := range ports {
			fields = append(fields, fmt.Sprintf("port=%d", port))
		}
	}
	return fingerprint(fields)
}

func (policy PacketFilterPolicy) NATRevision() string {
	targets := slices.Clone(policy.DNSTargets)
	slices.SortFunc(targets, compareDNSMasqueradeTargets)
	fields := []string{policy.NATTable, policy.DNSMasqueradeChain, policy.TailnetIPv4Prefix.String(), policy.TailnetIPv6Prefix.String()}
	for _, target := range targets {
		fields = append(fields, target.Address.Unmap().String()+"@"+target.OutputInterface)
	}
	return fingerprint(fields)
}

func (observation PacketFilterObservation) Matches(policy PacketFilterPolicy) bool {
	return observation.FilterMatches(policy) && observation.NATMatches(policy)
}

func (observation PacketFilterObservation) FilterMatches(policy PacketFilterPolicy) bool {
	return observation.FilterTableExists && observation.FilterRevision == policy.FilterRevision()
}

func (observation PacketFilterObservation) NATMatches(policy PacketFilterPolicy) bool {
	if len(policy.DNSTargets) == 0 {
		return !observation.NATTableExists
	}
	return observation.NATTableExists && observation.NATRevision == policy.NATRevision()
}

func compareDNSMasqueradeTargets(left, right DNSMasqueradeTarget) int {
	if comparison := left.Address.Unmap().Compare(right.Address.Unmap()); comparison != 0 {
		return comparison
	}
	return compareStrings(left.OutputInterface, right.OutputInterface)
}

func validateAddressFamilyList(label string, values []netip.Addr, family AddressFamily) error {
	var validationErrors []error
	seen := make(map[netip.Addr]struct{}, len(values))
	for _, value := range values {
		address := value.Unmap()
		if !address.IsValid() || address.Zone() != "" || FamilyOfAddress(address) != family || address.IsUnspecified() || address.IsMulticast() {
			validationErrors = append(validationErrors, fmt.Errorf("%s %q is invalid", label, value))
			continue
		}
		if _, duplicate := seen[address]; duplicate {
			validationErrors = append(validationErrors, fmt.Errorf("%s %s is duplicated", label, address))
		}
		seen[address] = struct{}{}
	}
	return errors.Join(validationErrors...)
}

func fingerprint(fields []string) string {
	var canonical strings.Builder
	for _, field := range fields {
		fmt.Fprintf(&canonical, "%d:%s;", len(field), field)
	}
	digest := sha256.Sum256([]byte(canonical.String()))
	return hex.EncodeToString(digest[:])
}
