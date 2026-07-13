//go:build linux

package nftables

import (
	"testing"

	gnft "github.com/google/nftables"
)

func TestValidSetDefinitionAcceptsSupportedKernelReadback(t *testing.T) {
	table := &gnft.Table{Name: "gateway_filter", Family: gnft.TableFamilyINet}
	specification := setSpec{
		name:     "proxy_targets_v4",
		keyType:  gnft.TypeIPAddr,
		elements: []gnft.SetElement{{Key: []byte{192, 0, 2, 10}}},
		comment:  "tailscale-gateway-agent:test-comment",
	}

	for _, size := range []uint32{0, 1} {
		observed := &gnft.Set{
			Table:    table,
			Name:     specification.name,
			Constant: true,
			KeyType:  specification.keyType,
			Comment:  "",
			Size:     size,
		}
		if !validSetDefinition(observed, table, specification) {
			t.Fatalf("supported kernel readback with size %d was rejected", size)
		}
	}
}

func TestValidSetDefinitionRejectsSemanticDrift(t *testing.T) {
	table := &gnft.Table{Name: "gateway_filter", Family: gnft.TableFamilyINet}
	specification := setSpec{
		name:     "proxy_targets_v4",
		keyType:  gnft.TypeIPAddr,
		elements: []gnft.SetElement{{Key: []byte{192, 0, 2, 10}}},
	}
	valid := gnft.Set{
		Table:    table,
		Name:     specification.name,
		Constant: true,
		KeyType:  specification.keyType,
		Size:     1,
	}

	tests := map[string]func(*gnft.Set){
		"wrong table":    func(set *gnft.Set) { set.Table = &gnft.Table{Name: "foreign", Family: gnft.TableFamilyINet} },
		"wrong name":     func(set *gnft.Set) { set.Name = "foreign" },
		"mutable":        func(set *gnft.Set) { set.Constant = false },
		"interval":       func(set *gnft.Set) { set.Interval = true },
		"map":            func(set *gnft.Set) { set.IsMap = true },
		"timeout":        func(set *gnft.Set) { set.HasTimeout = true },
		"dynamic":        func(set *gnft.Set) { set.Dynamic = true },
		"wrong key type": func(set *gnft.Set) { set.KeyType = gnft.TypeIP6Addr },
		"wrong size":     func(set *gnft.Set) { set.Size = 2 },
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			observed := valid
			mutate(&observed)
			if validSetDefinition(&observed, table, specification) {
				t.Fatal("semantic drift was accepted")
			}
		})
	}
}
