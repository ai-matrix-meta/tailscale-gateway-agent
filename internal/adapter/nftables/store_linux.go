//go:build linux

package nftables

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/ai-matrix-meta/tailscale-gateway-agent/internal/domain"
	gnft "github.com/google/nftables"
	mdnetlink "github.com/mdlayher/netlink"
)

type Store struct{}

const maximumNetlinkOperationDuration = 10 * time.Second

func New() *Store { return &Store{} }

func (store *Store) Observe(ctx context.Context, policy domain.PacketFilterPolicy) (domain.PacketFilterObservation, error) {
	if err := ctx.Err(); err != nil {
		return domain.PacketFilterObservation{}, err
	}
	if err := policy.Validate(); err != nil {
		return domain.PacketFilterObservation{}, fmt.Errorf("validate nftables policy: %w", err)
	}
	connection, err := newConnection(ctx)
	if err != nil {
		return domain.PacketFilterObservation{}, fmt.Errorf("open nftables connection: %w", err)
	}
	tables, err := connection.ListTables()
	if err != nil {
		return domain.PacketFilterObservation{}, fmt.Errorf("list nftables tables: %w", err)
	}
	chains, err := connection.ListChains()
	if err != nil {
		return domain.PacketFilterObservation{}, fmt.Errorf("list nftables chains: %w", err)
	}

	observation := domain.PacketFilterObservation{}
	filterTable, filterRevision, err := observeNamedTable(connection, tables, chains, policy.FilterTable, "filter")
	if err != nil {
		return domain.PacketFilterObservation{}, err
	}
	if filterTable != nil {
		observation.FilterTableExists = true
		if filterRevision == policy.FilterRevision() {
			valid, validateErr := validateFilterTable(connection, filterTable, chains, policy)
			if validateErr != nil {
				return domain.PacketFilterObservation{}, validateErr
			}
			if valid {
				observation.FilterRevision = filterRevision
			}
		}
	}

	natTable, natRevision, err := observeNamedTable(connection, tables, chains, policy.NATTable, "nat")
	if err != nil {
		return domain.PacketFilterObservation{}, err
	}
	if natTable != nil {
		observation.NATTableExists = true
		if natRevision == policy.NATRevision() {
			valid, validateErr := validateNATTable(connection, natTable, chains, policy)
			if validateErr != nil {
				return domain.PacketFilterObservation{}, validateErr
			}
			if valid {
				observation.NATRevision = natRevision
			}
		}
	}
	return observation, nil
}

func (store *Store) Apply(ctx context.Context, policy domain.PacketFilterPolicy, observation domain.PacketFilterObservation) error {
	if err := policy.Validate(); err != nil {
		return fmt.Errorf("validate nftables policy: %w", err)
	}
	filterChanged := !observation.FilterMatches(policy)
	natChanged := !observation.NATMatches(policy)
	if !filterChanged && !natChanged {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	connection, err := newConnection(ctx)
	if err != nil {
		return fmt.Errorf("open nftables connection: %w", err)
	}
	tables, err := connection.ListTables()
	if err != nil {
		return fmt.Errorf("list nftables tables before update: %w", err)
	}
	chains, err := connection.ListChains()
	if err != nil {
		return fmt.Errorf("list nftables chains before update: %w", err)
	}

	if filterChanged {
		existing, _, observeErr := observeNamedTable(connection, tables, chains, policy.FilterTable, "filter")
		if observeErr != nil {
			return observeErr
		}
		if existing != nil {
			connection.DelTable(existing)
		}
		if err := addFilterTable(connection, policy); err != nil {
			return err
		}
	}
	if natChanged {
		existing, _, observeErr := observeNamedTable(connection, tables, chains, policy.NATTable, "nat")
		if observeErr != nil {
			return observeErr
		}
		if existing != nil {
			connection.DelTable(existing)
		}
		if len(policy.DNSTargets) > 0 {
			if err := addNATTable(connection, policy); err != nil {
				return err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := connection.Flush(); err != nil {
		return fmt.Errorf("commit atomic nftables update: %w", err)
	}
	return nil
}

func newConnection(ctx context.Context) (*gnft.Conn, error) {
	deadline := time.Now().Add(maximumNetlinkOperationDuration)
	if contextDeadline, exists := ctx.Deadline(); exists && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	return gnft.New(gnft.WithSockOptions(func(connection *mdnetlink.Conn) error {
		return connection.SetDeadline(deadline)
	}))
}

func observeNamedTable(connection *gnft.Conn, tables []*gnft.Table, chains []*gnft.Chain, name, component string) (*gnft.Table, string, error) {
	matches := tablesNamed(tables, name)
	if len(matches) == 0 {
		return nil, "", nil
	}
	if len(matches) != 1 || matches[0].Family != gnft.TableFamilyINet {
		return nil, "", fmt.Errorf("nftables table name %q is not uniquely owned in the inet family", name)
	}
	revision, err := ownershipRevision(connection, matches[0], chains, component)
	if err != nil {
		return nil, "", fmt.Errorf("nftables table %q conflicts with Agent ownership: %w", name, err)
	}
	return matches[0], revision, nil
}

func ownershipRevision(connection *gnft.Conn, table *gnft.Table, allChains []*gnft.Chain, component string) (string, error) {
	metadataChain := findChain(chainsOfTable(allChains, table), domain.ReservedPacketFilterMetadataChain)
	if metadataChain == nil || metadataChain.Hooknum != nil || metadataChain.Priority != nil || metadataChain.Type != "" || metadataChain.Policy != nil || metadataChain.Device != "" {
		return "", fmt.Errorf("required ownership metadata chain is absent or invalid")
	}
	rules, err := connection.GetRules(table, metadataChain)
	if err != nil {
		return "", fmt.Errorf("read ownership metadata: %w", err)
	}
	if len(rules) != 1 || !reflect.DeepEqual(rules[0].Exprs, metadataRuleSpec(component, "").expressions) {
		return "", fmt.Errorf("ownership metadata rule is absent or invalid")
	}
	parts := strings.Split(string(rules[0].UserData), ":")
	if len(parts) != 5 || parts[0] != "tailscale-gateway-agent" || parts[1] != "v1" || parts[2] != component || parts[4] != "metadata" {
		return "", fmt.Errorf("ownership metadata value is invalid")
	}
	digest, err := hex.DecodeString(parts[3])
	if err != nil || len(digest) != sha256.Size {
		return "", fmt.Errorf("ownership revision is invalid")
	}
	return parts[3], nil
}

func validateFilterTable(connection *gnft.Conn, table *gnft.Table, allChains []*gnft.Chain, policy domain.PacketFilterPolicy) (bool, error) {
	if table.Flags != 0 {
		return false, nil
	}
	chains := chainsOfTable(allChains, table)
	if len(chains) != 3 {
		return false, nil
	}
	forward := findChain(chains, policy.ForwardGuardChain)
	local := findChain(chains, policy.LocalEgressChain)
	metadata := findChain(chains, domain.ReservedPacketFilterMetadataChain)
	if !validBaseChain(forward, gnft.ChainTypeFilter, gnft.ChainHookForward, gnft.ChainPriorityFilter) ||
		!validBaseChain(local, gnft.ChainTypeRoute, gnft.ChainHookOutput, gnft.ChainPriorityMangle) || metadata == nil {
		return false, nil
	}
	sets, setMap, err := validateSets(connection, table, filterSetSpecs(policy))
	if err != nil || !sets {
		return false, err
	}
	expected, err := filterRuleSpecs(policy, setMap)
	if err != nil {
		return false, err
	}
	for _, chain := range []*gnft.Chain{forward, local} {
		rules, listErr := connection.GetRules(table, chain)
		if listErr != nil {
			return false, fmt.Errorf("list nftables rules in %s/%s: %w", table.Name, chain.Name, listErr)
		}
		if !rulesEqual(rules, expected[chain.Name], "filter", chain.Name, policy.FilterRevision()) {
			return false, nil
		}
	}
	return validMetadataRevision(connection, table, metadata, "filter", policy.FilterRevision())
}

func validateNATTable(connection *gnft.Conn, table *gnft.Table, allChains []*gnft.Chain, policy domain.PacketFilterPolicy) (bool, error) {
	if table.Flags != 0 {
		return false, nil
	}
	chains := chainsOfTable(allChains, table)
	if len(chains) != 2 {
		return false, nil
	}
	data := findChain(chains, policy.DNSMasqueradeChain)
	metadata := findChain(chains, domain.ReservedPacketFilterMetadataChain)
	if !validBaseChain(data, gnft.ChainTypeNAT, gnft.ChainHookPostrouting, gnft.ChainPriorityNATSource) || metadata == nil {
		return false, nil
	}
	sets, _, err := validateSets(connection, table, nil)
	if err != nil || !sets {
		return false, err
	}
	expected, err := natRuleSpecs(policy)
	if err != nil {
		return false, err
	}
	rules, err := connection.GetRules(table, data)
	if err != nil {
		return false, fmt.Errorf("list nftables rules in %s/%s: %w", table.Name, data.Name, err)
	}
	if !rulesEqual(rules, expected, "nat", data.Name, policy.NATRevision()) {
		return false, nil
	}
	return validMetadataRevision(connection, table, metadata, "nat", policy.NATRevision())
}

func validateSets(connection *gnft.Conn, table *gnft.Table, expected []setSpec) (bool, map[string]*gnft.Set, error) {
	observed, err := connection.GetSets(table)
	if err != nil {
		return false, nil, fmt.Errorf("list nftables sets in %s: %w", table.Name, err)
	}
	if len(observed) != len(expected) {
		return false, nil, nil
	}
	observedByName := make(map[string]*gnft.Set, len(observed))
	for _, set := range observed {
		if _, duplicate := observedByName[set.Name]; duplicate {
			return false, nil, nil
		}
		observedByName[set.Name] = set
	}
	for _, specification := range expected {
		set := observedByName[specification.name]
		if !validSetDefinition(set, table, specification) {
			return false, nil, nil
		}
		elements, elementErr := connection.GetSetElements(set)
		if elementErr != nil {
			return false, nil, fmt.Errorf("list nftables set %s elements: %w", set.Name, elementErr)
		}
		if !setElementsEqual(elements, specification.elements) {
			return false, nil, nil
		}
	}
	return true, observedByName, nil
}

func validSetDefinition(set *gnft.Set, table *gnft.Table, specification setSpec) bool {
	if set == nil || set.Table == nil || set.Table.Name != table.Name || set.Table.Family != table.Family {
		return false
	}
	if set.Name != specification.name || !set.Constant || set.Anonymous || set.Interval || set.AutoMerge || set.IsMap || set.HasTimeout || set.Counter || set.Dynamic || set.Concatenation {
		return false
	}
	if set.KeyType.Name != specification.keyType.Name || set.KeyType.Bytes != specification.keyType.Bytes {
		return false
	}
	// google/nftables v0.3.0 does not decode set comments and reports the
	// constant-set element count through Size on kernels that echo its descriptor.
	return set.Size == 0 || uint64(set.Size) == uint64(len(specification.elements))
}

func setElementsEqual(observed, expected []gnft.SetElement) bool {
	if len(observed) != len(expected) {
		return false
	}
	observed = slices.Clone(observed)
	expected = slices.Clone(expected)
	slices.SortFunc(observed, func(left, right gnft.SetElement) int { return bytes.Compare(left.Key, right.Key) })
	slices.SortFunc(expected, func(left, right gnft.SetElement) int { return bytes.Compare(left.Key, right.Key) })
	for index := range expected {
		item := observed[index]
		if !bytes.Equal(item.Key, expected[index].Key) || len(item.Val) != 0 || len(item.KeyEnd) != 0 || item.IntervalEnd || item.VerdictData != nil || item.Timeout != 0 || item.Expires != 0 || item.Counter != nil || item.Comment != "" {
			return false
		}
	}
	return true
}

func addFilterTable(connection *gnft.Conn, policy domain.PacketFilterPolicy) error {
	table := connection.AddTable(&gnft.Table{Name: policy.FilterTable, Family: gnft.TableFamilyINet})
	sets := make(map[string]*gnft.Set)
	for _, specification := range filterSetSpecs(policy) {
		set := &gnft.Set{Table: table, Name: specification.name, Constant: true, KeyType: specification.keyType, Comment: specification.comment}
		if err := connection.AddSet(set, specification.elements); err != nil {
			return fmt.Errorf("add nftables set %s: %w", specification.name, err)
		}
		sets[specification.name] = set
	}
	specifications, err := filterRuleSpecs(policy, sets)
	if err != nil {
		return err
	}
	forward := addBaseChain(connection, table, policy.ForwardGuardChain, gnft.ChainTypeFilter, gnft.ChainHookForward, gnft.ChainPriorityFilter)
	local := addBaseChain(connection, table, policy.LocalEgressChain, gnft.ChainTypeRoute, gnft.ChainHookOutput, gnft.ChainPriorityMangle)
	metadata := connection.AddChain(&gnft.Chain{Name: domain.ReservedPacketFilterMetadataChain, Table: table})
	addRules(connection, table, forward, specifications[forward.Name])
	addRules(connection, table, local, specifications[local.Name])
	addMetadataRule(connection, table, metadata, "filter", policy.FilterRevision())
	return nil
}

func addNATTable(connection *gnft.Conn, policy domain.PacketFilterPolicy) error {
	specifications, err := natRuleSpecs(policy)
	if err != nil {
		return err
	}
	table := connection.AddTable(&gnft.Table{Name: policy.NATTable, Family: gnft.TableFamilyINet})
	data := addBaseChain(connection, table, policy.DNSMasqueradeChain, gnft.ChainTypeNAT, gnft.ChainHookPostrouting, gnft.ChainPriorityNATSource)
	metadata := connection.AddChain(&gnft.Chain{Name: domain.ReservedPacketFilterMetadataChain, Table: table})
	addRules(connection, table, data, specifications)
	addMetadataRule(connection, table, metadata, "nat", policy.NATRevision())
	return nil
}

func addBaseChain(connection *gnft.Conn, table *gnft.Table, name string, chainType gnft.ChainType, hook *gnft.ChainHook, priority *gnft.ChainPriority) *gnft.Chain {
	accept := gnft.ChainPolicyAccept
	return connection.AddChain(&gnft.Chain{Name: name, Table: table, Type: chainType, Hooknum: hook, Priority: priority, Policy: &accept})
}

func addRules(connection *gnft.Conn, table *gnft.Table, chain *gnft.Chain, specifications []ruleSpec) {
	for _, specification := range specifications {
		connection.AddRule(&gnft.Rule{Table: table, Chain: chain, Exprs: specification.expressions, UserData: specification.userData})
	}
}

func addMetadataRule(connection *gnft.Conn, table *gnft.Table, chain *gnft.Chain, component, revision string) {
	metadata := metadataRuleSpec(component, revision)
	connection.AddRule(&gnft.Rule{Table: table, Chain: chain, Exprs: metadata.expressions, UserData: metadata.userData})
}

func validBaseChain(chain *gnft.Chain, chainType gnft.ChainType, hook *gnft.ChainHook, priority *gnft.ChainPriority) bool {
	return chain != nil && chain.Type == chainType && pointerEqual(chain.Hooknum, hook) && pointerEqual(chain.Priority, priority) && chain.Policy != nil && *chain.Policy == gnft.ChainPolicyAccept && chain.Device == ""
}

func validMetadataRevision(connection *gnft.Conn, table *gnft.Table, chain *gnft.Chain, component, revision string) (bool, error) {
	rules, err := connection.GetRules(table, chain)
	if err != nil {
		return false, fmt.Errorf("list nftables metadata rules in %s: %w", table.Name, err)
	}
	expected := metadataRuleSpec(component, revision)
	return len(rules) == 1 && bytes.Equal(rules[0].UserData, expected.userData) && reflect.DeepEqual(rules[0].Exprs, expected.expressions), nil
}

func tablesNamed(tables []*gnft.Table, name string) []*gnft.Table {
	var matches []*gnft.Table
	for _, table := range tables {
		if table.Name == name {
			matches = append(matches, table)
		}
	}
	return matches
}

func chainsOfTable(chains []*gnft.Chain, table *gnft.Table) []*gnft.Chain {
	var matches []*gnft.Chain
	for _, chain := range chains {
		if chain.Table != nil && chain.Table.Name == table.Name && chain.Table.Family == table.Family {
			matches = append(matches, chain)
		}
	}
	return matches
}

func findChain(chains []*gnft.Chain, name string) *gnft.Chain {
	for _, chain := range chains {
		if chain.Name == name {
			return chain
		}
	}
	return nil
}

func rulesEqual(observed []*gnft.Rule, expected []ruleSpec, component, chain, revision string) bool {
	if len(observed) != len(expected) {
		return false
	}
	for index := range expected {
		if !bytes.Equal(observed[index].UserData, ruleUserData(component, chain, revision, index)) || !reflect.DeepEqual(observed[index].Exprs, expected[index].expressions) {
			return false
		}
	}
	return true
}

func pointerEqual[T comparable](left, right *T) bool {
	return left != nil && right != nil && *left == *right
}
