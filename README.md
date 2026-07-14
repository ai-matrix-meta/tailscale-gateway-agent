# Tailscale Gateway Agent

`tailscale-gateway-agent` is the control plane for a Linux Tailscale egress
gateway. It observes a network namespace and reconciles policy routing,
Agent-owned nftables objects, and Tailscale advertisement preferences. It does
not read, copy, or process data-plane packets.

The binary is runtime-neutral. Kubernetes is one lifecycle adapter, not a core
assumption. The same `run` mode can be managed by a VM or LXC service manager.

## Traffic Contract

```text
Tailnet ingress -> exit policy table
                  |-- Tailnet and advertised prefixes -> discovered direct path
                  `-- all other destinations -> proxy TUN -> sing-box -> SOCKS

Selected local control traffic -> packet mark -> local-egress policy table
                               -> proxy TUN -> sing-box -> SOCKS
```

Clients that do not select this node as an exit node retain normal Tailnet and
advertised-subnet behavior. The Agent publishes subnet advertisements only
after routing and packet-filter state has converged and has been read back
successfully. Both Exit defaults additionally require fresh IPv4 and IPv6
Internet capability through the discovered proxy TUN.

## Runtime Requirements

- Linux with rtnetlink, nftables, TUN, and dual-stack forwarding enabled.
- The Agent, tailscaled, and sing-box share one network namespace.
- Tailscaled exposes its LocalAPI Unix socket in that namespace.
- The process has the capabilities required for route, rule, and nftables
  updates.
- Exactly one configured coordination backend owns all writes.

Release images support `linux/amd64` and `linux/arm64`. The ARM64 image is
intended for Linux virtual machines or Kubernetes nodes on Apple Silicon,
including Mac mini hosts. Native macOS is not supported because the control
plane depends on Linux rtnetlink, nftables, policy routing, and TUN semantics.

Interface names are never configured or guessed. The Tailnet TUN is identified
from LocalAPI node addresses. The proxy TUN is identified from its explicitly
configured dual-stack addresses, kernel link type, and operational state.

## Commands

- `run`: use a Linux file lock and leave tailscaled and sing-box lifecycle to an
  external service manager.
- `supervise-containerboot`: use a Kubernetes Lease and supervise the official
  `/usr/local/bin/containerboot` process.
- `install`: atomically install the current static executable at
  `/tools/tailscale-gateway-agent`.
- `version`: print the immutable version, commit, and build timestamp.

Execution mode is explicit because inferring an orchestrator from cgroups,
hostnames, or ambient variables is not a reliable ownership decision.

## Configuration

Configuration is read once from environment variables with the
`TAILSCALE_GATEWAY_` prefix. Unknown variables under that prefix, invalid
types, duplicate list members, ambiguous ownership, and incomplete cross-field
contracts are rejected before coordination or network access.

The following values are required for every runtime:

- `TAILSCALE_GATEWAY_PROXY_TUNNEL_ADDRESSES`: comma-separated IPv4 and IPv6
  prefixes assigned to the proxy TUN. These are deployment facts and have no
  program default.
- `TAILSCALE_GATEWAY_COORDINATION_BACKEND`: `file-lock` for `run` or
  `kubernetes-lease` for `supervise-containerboot`.

Each name above is prefixed with `TAILSCALE_GATEWAY_`. Defaults are centralized
in `internal/domain.DefaultConfiguration`; behavior-sensitive Kubernetes values
are also declared explicitly in the workload ConfigMaps.

The complete v1 field catalog, defaults, validation rules, and containerboot
environment boundary are documented in
[docs/reference/CONFIGURATION.md](docs/reference/CONFIGURATION.md).

In supervised mode, the child process receives a separate exact allowlist of
containerboot variables. `TS_ROUTES` is rejected, and advertisement flags in
extra arguments are rejected, so containerboot cannot share the Agent's
`AdvertiseRoutes` ownership.

## Reconciliation

- Kernel link, address, and route events immediately revoke readiness and
  schedule a debounced full observation.
- Low-frequency audits cover lost events, nftables drift, forwarding sysctls,
  LocalAPI preferences, and resolver changes.
- One goroutine serializes every route, nftables, and LocalAPI write.
- Equal desired and observed state performs zero writes.
- Before supervised containerboot starts, the Agent installs quarantine,
  discovers the proxy TUN, establishes table 101, and marks the selected
  control-plane destinations. This prevents the first Tailscale connection
  from escaping the configured proxy path.
- The Agent owns only the low 16 packet-mark bits. Marking preserves Tailscale's
  upper mark bytes, and policy rules match the same low-bit mask.
- Any detected drift is handled as one ordered transaction: close forwarding,
  clear advertisements, converge and verify routing, converge and verify
  nftables, reopen forwarding, verify again, then republish advertisements.
- A live technical failure always closes forwarding, blackholes Exit selectors,
  and clears advertisements. It retains the bounded local-control path only
  after revalidating DNS freshness, the proxy TUN, packet marking, routing
  readback, and kernel prerequisites; otherwise table 101 is blackholed too.
- Shutdown and coordination loss always blackhole both managed policy tables.

`/livez` reports process health. `/readyz` is successful only after the latest
complete reconciliation and becomes false immediately when a newer network
event is observed. `/metrics` exposes bounded Prometheus metrics.

## Verification

```text
go test ./...
go test -race ./...
go vet ./...
staticcheck ./...
govulncheck ./...
go mod verify
```

Linux integration tests use the `integration` build tag and require an isolated
network namespace with network-administration privileges. CI creates that
namespace explicitly and verifies real netlink and nftables convergence.

Release tags produce a signed multi-platform scratch image for `linux/amd64`
and `linux/arm64`. Every workflow attempt publishes a unique candidate. The
public semver tag is the final external write and is promoted only after source,
integration, platform, metadata, SBOM, provenance, signature, and runtime
verification. Kubernetes configuration uses the reported immutable OCI digest,
never a mutable image tag.

## Documentation

- [Documentation index](docs/README.md): category ownership and authoritative
  document map.
- [Architecture](docs/architecture/ARCHITECTURE.md): ownership, dependency,
  discovery, fail-closed, and release invariants.
- [Configuration reference](docs/reference/CONFIGURATION.md): complete v1
  environment contract and defaults.
- [Operations runbook](docs/runbooks/OPERATIONS.md): health interpretation,
  incident handling, credential rotation, and release handoff.
- [Security policy](SECURITY.md): vulnerability reporting and trust model.
