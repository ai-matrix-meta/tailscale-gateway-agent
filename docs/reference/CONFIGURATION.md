# Configuration Reference

## Contract

The Agent reads configuration once at process start from environment variables
whose names begin with `TAILSCALE_GATEWAY_`. The API version is `v1`; there are
no aliases, compatibility variables, runtime overlays, or interface-name
settings.

Unknown owned variables, explicit empty values that violate a field contract,
invalid types, duplicate list entries, conflicting ownership, and cross-field
errors terminate the process before coordination or network writes. Variables
outside the owned prefix are ignored by Agent parsing.

Boolean values are exactly `true` or `false` (case-insensitive); numeric and
single-letter aliases are rejected. Integer fields are decimal unless their
contract explicitly permits a `0x`-prefixed hexadecimal value. Leading zeroes
do not change decimal radix.

## Required Values

- `TAILSCALE_GATEWAY_PROXY_TUNNEL_ADDRESSES`: comma-separated IPv4 and IPv6
  prefixes assigned to one healthy proxy TUN. There is no default.
- `TAILSCALE_GATEWAY_COORDINATION_BACKEND`: `file-lock` for `run` or
  `kubernetes-lease` for `supervise-containerboot`. There is no default.

## Network Ownership

- `TAILSCALE_GATEWAY_TAILNET_IPV4_PREFIX`: `100.64.0.0/10`.
- `TAILSCALE_GATEWAY_TAILNET_IPV6_PREFIX`: `fd7a:115c:a1e0::/48`.
- `TAILSCALE_GATEWAY_EXIT_ROUTE_TABLE`: `100`.
- `TAILSCALE_GATEWAY_EXIT_RULE_PRIORITY`: `99`.
- `TAILSCALE_GATEWAY_LOCAL_EGRESS_ROUTE_TABLE`: `101`.
- `TAILSCALE_GATEWAY_LOCAL_EGRESS_RULE_PRIORITY`: `90`.
- `TAILSCALE_GATEWAY_LOCAL_EGRESS_PACKET_MARK`: `0x11`; must be non-zero and
  contained in the Agent-owned low 16 bits.
- `TAILSCALE_GATEWAY_ACTIVE_ROUTE_METRIC`: `100`; applied explicitly to every
  managed IPv4 and IPv6 unicast route.
- `TAILSCALE_GATEWAY_FAIL_CLOSED_ROUTE_METRIC`: `32760`.

The two tables and priorities must be distinct. Linux-reserved route tables and
rule priorities outside the supported range are rejected. Both route metrics
must be positive and the active metric must be lower than the fail-closed
blackhole metric; zero is prohibited because Linux does not preserve an omitted
IPv6 route priority with the same semantics as IPv4. Metrics are bounded to
`1..2147483647`, the range represented consistently by the configuration parser
and netlink dependency on every supported build architecture.

## Nftables Ownership

- `TAILSCALE_GATEWAY_NFTABLES_FILTER_TABLE`: `tailscale_gateway`.
- `TAILSCALE_GATEWAY_NFTABLES_FORWARD_GUARD_CHAIN`:
  `tailnet_forward_guard`.
- `TAILSCALE_GATEWAY_NFTABLES_LOCAL_EGRESS_CHAIN`:
  `local_egress_proxy_output`.
- `TAILSCALE_GATEWAY_NFTABLES_LOCAL_EGRESS_IPV4_SET`: `local_egress_ipv4`.
- `TAILSCALE_GATEWAY_NFTABLES_LOCAL_EGRESS_IPV6_SET`: `local_egress_ipv6`.
- `TAILSCALE_GATEWAY_NFTABLES_NAT_TABLE`: `tailscale_gateway_nat`.
- `TAILSCALE_GATEWAY_NFTABLES_DNS_SNAT_CHAIN`: `cluster_dns_snat`.

Identifiers must be valid, unique nftables names and cannot use the reserved
ownership metadata chain.

## Local Control Egress

- `TAILSCALE_GATEWAY_LOCAL_EGRESS_ENABLED`: `false`.
- `TAILSCALE_GATEWAY_LOCAL_EGRESS_DOMAINS`: empty comma-separated DNS names.
- `TAILSCALE_GATEWAY_LOCAL_EGRESS_PROTOCOLS`: `tcp`.
- `TAILSCALE_GATEWAY_LOCAL_EGRESS_PORTS`: `443`.
- `TAILSCALE_GATEWAY_LOCAL_EGRESS_REFRESH_INTERVAL`: `5m`.
- `TAILSCALE_GATEWAY_LOCAL_EGRESS_MAXIMUM_STALENESS`: `1h`.

Enabling the feature requires at least one domain, protocol, and port. DNS
refresh failures may retain the last-known-good set only within maximum
staleness; after that deadline reconciliation fails closed.

## Tailnet Ownership

- `TAILSCALE_GATEWAY_TAILSCALE_SOCKET_PATH`:
  `/var/run/tailscale/tailscaled.sock`.
- `TAILSCALE_GATEWAY_ADVERTISE_ROUTES`: empty comma-separated non-default
  prefixes.
- `TAILSCALE_GATEWAY_ADVERTISE_EXIT_NODE`: `false`.
- `TAILSCALE_GATEWAY_PREFERENCE_AUDIT_INTERVAL`: `30s`.
- `TAILSCALE_GATEWAY_TAILSCALE_OPERATION_TIMEOUT`: `20s`.

Advertised prefixes must be masked, non-overlapping, outside Tailnet and proxy
TUN ranges, and resolvable to deterministic direct kernel paths. LocalAPI bus
events provide low-latency hints, while this audit interval is the authoritative
maximum polling window for control-plane approval changes.

## Exit Internet Capability

- `TAILSCALE_GATEWAY_CAPABILITY_PROBE_IPV4_URL`: no default.
- `TAILSCALE_GATEWAY_CAPABILITY_PROBE_IPV6_URL`: no default.
- `TAILSCALE_GATEWAY_CAPABILITY_PROBE_INTERVAL`: `30s`.
- `TAILSCALE_GATEWAY_CAPABILITY_PROBE_TIMEOUT`: `5s`.
- `TAILSCALE_GATEWAY_CAPABILITY_PROBE_VALIDITY`: `2m`.
- `TAILSCALE_GATEWAY_CAPABILITY_PROBE_SUCCESS_THRESHOLD`: `2`.
- `TAILSCALE_GATEWAY_CAPABILITY_PROBE_FAILURE_THRESHOLD`: `2`.

When Exit advertisement is enabled, both endpoint URLs are required because the
Agent must independently observe both address families. When it is disabled,
both variables must be absent. Endpoints have no program default and remain
cluster-owned production decisions. Their static URL, timing, and threshold
contracts and their runtime DNS/TLS/HTTP requirements are defined in
[Exit capability and route approval](../architecture/EXIT-CAPABILITY.md).
The two fields may use the same dual-stack URL; each probe resolves and dials
only its requested address family. A failed family does not block the healthy
family from activating its Exit route. Tailnet advertisement remains an atomic
pair of IPv4 and IPv6 defaults because that is the Tailscale Exit Node
recognition contract; unavailable-family traffic terminates at the managed
blackhole.

## Reconciliation Runtime

- `TAILSCALE_GATEWAY_AUDIT_INTERVAL`: `5m`.
- `TAILSCALE_GATEWAY_RECONCILE_TIMEOUT`: `2m`.
- `TAILSCALE_GATEWAY_EVENT_DEBOUNCE`: `500ms`.
- `TAILSCALE_GATEWAY_READINESS_MAXIMUM_AGE`: `10m`.
- `TAILSCALE_GATEWAY_DNS_LOOKUP_TIMEOUT`: `10s`.
- `TAILSCALE_GATEWAY_SHUTDOWN_TIMEOUT`: `30s`.
- `TAILSCALE_GATEWAY_HEALTH_LISTEN_ADDRESS`: `127.0.0.1:8080`.
- `TAILSCALE_GATEWAY_RESOLVER_PATH`: `/etc/resolv.conf`.
- `TAILSCALE_GATEWAY_LOG_LEVEL`: `info`; accepted values are `debug`, `info`,
  `warn`, and `error`.

The reconcile deadline covers startup preparation and each full pass. It must
be shorter than the audit interval. Readiness maximum age must exceed the audit
interval, and individual DNS and LocalAPI deadlines must fit inside a pass.
The health listener must use a numeric port within `1..65535`. The host-local
default is safe for VM and LXC service mode; deployments that require remote
scraping must explicitly choose a non-loopback bind address and enforce a
network access policy. The configured resolver file is authoritative for both
nameserver route discovery and DNS lookups. Each pass reads it exactly once and
binds an immutable snapshot to both operations. Lookups use its nameservers in
declaration order and query configured domains as absolute DNS names, so a
mid-pass replacement or different search-domain configuration cannot change
the destination contract.
Native netlink and nftables adapters apply bounded socket deadlines, so
cancellation and the configured pass deadline are not merely advisory.

## Coordination

- `TAILSCALE_GATEWAY_COORDINATION_RESOURCE_NAME`:
  `tailscale-gateway-identity`.
- `TAILSCALE_GATEWAY_COORDINATION_NAMESPACE_PATH`:
  `/var/run/secrets/kubernetes.io/serviceaccount/namespace`.
- `TAILSCALE_GATEWAY_COORDINATION_LOCK_FILE`:
  `/run/tailscale-gateway-agent.lock`.
- `TAILSCALE_GATEWAY_COORDINATION_LEASE_DURATION`: `90s`.
- `TAILSCALE_GATEWAY_COORDINATION_RENEW_DEADLINE`: `45s`.
- `TAILSCALE_GATEWAY_COORDINATION_RETRY_PERIOD`: `2s`.
- `TAILSCALE_GATEWAY_COORDINATION_ACQUIRE_TIMEOUT`: `5m`.

Lease timing must satisfy lease duration greater than renew deadline greater
than retry period. A lost Lease cancels the owned Supervisor run and completes
fail-closed shutdown before releasing process control.

## Containerboot Boundary

Supervised containerboot receives an exact allowlist of process, proxy,
Kubernetes service-discovery, and documented `TS_` variables. Agent variables
and unrelated ambient values are not forwarded. `TS_ROUTES` is always rejected,
including an explicit empty value. Route or exit-node advertisement flags in
`TS_EXTRA_ARGS` and `TS_TAILSCALED_EXTRA_ARGS` are also rejected.

Credentials are not Agent configuration. Kubernetes injects `TS_AUTHKEY` only
into the supervisor container, which passes it to containerboot without logging
or transforming the value.
