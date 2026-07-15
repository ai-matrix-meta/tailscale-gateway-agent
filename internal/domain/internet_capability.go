package domain

import (
	"errors"
	"fmt"
	"time"
)

type InternetFamilyCapability struct {
	Initialized bool
	Available   bool
	ObservedAt  time.Time
	ValidUntil  time.Time
}

func (capability InternetFamilyCapability) Validate(family AddressFamily) error {
	if family != IPv4 && family != IPv6 {
		return fmt.Errorf("internet capability has unsupported address family %d", family)
	}
	if !capability.Initialized {
		if capability.Available || !capability.ObservedAt.IsZero() || !capability.ValidUntil.IsZero() {
			return fmt.Errorf("uninitialized IPv%d Internet capability carries observed state", family)
		}
		return nil
	}
	if capability.ObservedAt.IsZero() {
		return fmt.Errorf("initialized IPv%d Internet capability has no observation time", family)
	}
	if capability.Available {
		if !capability.ValidUntil.After(capability.ObservedAt) {
			return fmt.Errorf("available IPv%d Internet capability has an invalid validity window", family)
		}
	} else if !capability.ValidUntil.IsZero() {
		return fmt.Errorf("unavailable IPv%d Internet capability carries a validity deadline", family)
	}
	return nil
}

func (capability InternetFamilyCapability) Fresh(now time.Time) bool {
	return capability.Initialized && capability.Available &&
		!now.Before(capability.ObservedAt) && !now.After(capability.ValidUntil)
}

type InternetCapabilitySnapshot struct {
	ProxyLink LinkIdentity
	IPv4      InternetFamilyCapability
	IPv6      InternetFamilyCapability
}

func (snapshot InternetCapabilitySnapshot) Validate() error {
	var validationErrors []error
	if err := snapshot.IPv4.Validate(IPv4); err != nil {
		validationErrors = append(validationErrors, err)
	}
	if err := snapshot.IPv6.Validate(IPv6); err != nil {
		validationErrors = append(validationErrors, err)
	}
	if snapshot.ProxyLink.Valid() {
		return errors.Join(validationErrors...)
	}
	if snapshot.ProxyLink != (LinkIdentity{}) {
		validationErrors = append(validationErrors, errors.New("internet capability snapshot has an invalid proxy link"))
	}
	if snapshot.IPv4.Initialized || snapshot.IPv6.Initialized {
		validationErrors = append(validationErrors, errors.New("observed Internet capability requires a valid proxy link"))
	}
	return errors.Join(validationErrors...)
}

func (snapshot InternetCapabilitySnapshot) AvailableExitDefaultRoutes(now time.Time, proxyLink LinkIdentity) ExitDefaultRouteSet {
	if snapshot.Validate() != nil || !proxyLink.Valid() || snapshot.ProxyLink != proxyLink {
		return ExitDefaultRouteSet{}
	}
	return ExitDefaultRouteSet{
		IPv4: snapshot.IPv4.Fresh(now),
		IPv6: snapshot.IPv6.Fresh(now),
	}
}
