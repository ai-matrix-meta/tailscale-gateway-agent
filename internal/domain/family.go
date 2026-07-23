package domain

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

const MaximumInterfaceNameBytes = 15

type AddressFamily uint8

const (
	IPv4 AddressFamily = 4
	IPv6 AddressFamily = 6
)

type LinkIdentity struct {
	Index int
	Name  string
}

func (link LinkIdentity) Validate() error {
	switch {
	case link.Index <= 0:
		return fmt.Errorf("link index %d must be positive", link.Index)
	case link.Name == "":
		return errors.New("link name must not be empty")
	case len(link.Name) > MaximumInterfaceNameBytes:
		return fmt.Errorf("link name %q exceeds %d bytes", link.Name, MaximumInterfaceNameBytes)
	case link.Name == "." || link.Name == "..":
		return fmt.Errorf("link name %q is reserved", link.Name)
	case strings.ContainsAny(link.Name, "/:"):
		return fmt.Errorf("link name %q contains a prohibited delimiter", link.Name)
	default:
		for _, character := range []byte(link.Name) {
			if character <= ' ' || character == 0x7f {
				return fmt.Errorf("link name %q contains whitespace or a control byte", link.Name)
			}
		}
		return nil
	}
}

func (link LinkIdentity) Valid() bool { return link.Validate() == nil }

type RouteDisposition string

const (
	RouteUnicast     RouteDisposition = "unicast"
	RouteBlackhole   RouteDisposition = "blackhole"
	RouteUnreachable RouteDisposition = "unreachable"
	RouteProhibit    RouteDisposition = "prohibit"
	RouteThrow       RouteDisposition = "throw"
	RouteUnknown     RouteDisposition = "unknown"
)

func DefaultPrefix(family AddressFamily) netip.Prefix {
	if family == IPv4 {
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	}
	return netip.PrefixFrom(netip.IPv6Unspecified(), 0)
}

func FamilyOfAddress(address netip.Addr) AddressFamily {
	if address.Unmap().Is4() {
		return IPv4
	}
	return IPv6
}

func FamilyOfPrefix(prefix netip.Prefix) AddressFamily { return FamilyOfAddress(prefix.Addr()) }

func validInterfaceAddressPrefix(prefix netip.Prefix) bool {
	if !prefix.IsValid() || prefix.Bits() == 0 || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
		return false
	}
	return prefix.Bits() <= prefix.Addr().BitLen()
}

func validMaskedPrefix(prefix netip.Prefix, family AddressFamily) bool {
	return prefix.IsValid() && prefix == prefix.Masked() && FamilyOfPrefix(prefix) == family
}

func prefixesOverlap(left, right netip.Prefix) bool {
	if !left.IsValid() || !right.IsValid() || FamilyOfPrefix(left) != FamilyOfPrefix(right) {
		return false
	}
	return left.Contains(right.Addr()) || right.Contains(left.Addr())
}

func validateUniqueAddresses(label string, values []netip.Addr, requireNonEmpty bool) error {
	var validationErrors []error
	if requireNonEmpty && len(values) == 0 {
		validationErrors = append(validationErrors, fmt.Errorf("at least one %s is required", label))
	}
	seen := make(map[netip.Addr]struct{}, len(values))
	for _, value := range values {
		address := value.Unmap()
		if !address.IsValid() || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
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

func validateUniquePrefixes(label string, values []netip.Prefix) error {
	var validationErrors []error
	seen := make(map[netip.Prefix]struct{}, len(values))
	for index, value := range values {
		if !value.IsValid() || value.Bits() == 0 || value != value.Masked() {
			validationErrors = append(validationErrors, fmt.Errorf("%s %q must be a masked non-default prefix", label, value))
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			validationErrors = append(validationErrors, fmt.Errorf("%s %s is duplicated", label, value))
		}
		seen[value] = struct{}{}
		for _, previous := range values[:index] {
			if value != previous && prefixesOverlap(value, previous) {
				validationErrors = append(validationErrors, fmt.Errorf("%s values %s and %s overlap", label, previous, value))
			}
		}
	}
	return errors.Join(validationErrors...)
}

func validateUniquePositiveIntegers(label string, values []int) error {
	var validationErrors []error
	seen := make(map[int]struct{}, len(values))
	for _, value := range values {
		if value <= 0 {
			validationErrors = append(validationErrors, fmt.Errorf("%s %d must be positive", label, value))
		}
		if _, duplicate := seen[value]; duplicate {
			validationErrors = append(validationErrors, fmt.Errorf("%s %d is duplicated", label, value))
		}
		seen[value] = struct{}{}
	}
	return errors.Join(validationErrors...)
}

func sortedAddresses(values []netip.Addr) []netip.Addr {
	result := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		result = append(result, value.Unmap())
	}
	slices.SortFunc(result, func(left, right netip.Addr) int { return left.Compare(right) })
	return slices.Compact(result)
}

func compareStrings(left, right string) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}
