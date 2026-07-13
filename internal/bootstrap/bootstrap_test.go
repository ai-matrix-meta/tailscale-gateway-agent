package bootstrap

import (
	"strings"
	"testing"
	"time"
)

func TestConfigureInternetProberFollowsTheExitAdvertisementContract(t *testing.T) {
	prober, err := configureInternetProber(false, "", "", 5*time.Second)
	if err != nil || prober != nil {
		t.Fatalf("disabled Exit configured a prober: prober=%T err=%v", prober, err)
	}

	prober, err = configureInternetProber(
		true,
		"https://ipv4.probe.example.com/status",
		"https://ipv6.probe.example.com/status",
		5*time.Second,
	)
	if err != nil || prober == nil {
		t.Fatalf("enabled Exit did not configure a prober: prober=%T err=%v", prober, err)
	}

	if _, err := configureInternetProber(
		true,
		"http://ipv4.probe.example.com/status",
		"https://ipv6.probe.example.com/status",
		5*time.Second,
	); err == nil || !strings.Contains(err.Error(), "scheme must be exactly https") {
		t.Fatalf("invalid endpoint crossed the bootstrap boundary: %v", err)
	}
}
