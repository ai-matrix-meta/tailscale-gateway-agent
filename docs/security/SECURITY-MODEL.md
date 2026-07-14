# Security Model

## Privilege Boundary

The Agent is privileged Linux control-plane software. Compromise can change
routing, nftables policy, and Tailscale advertisements inside its network
namespace. It must run with only the network capabilities and object-scoped API
permissions required by the workload.

The Agent does not process packets, accept credentials in its configuration
API, or execute command-line networking tools. Bootstrap is the sole composition
root, and architecture tests prevent reverse layer dependencies and peer
adapter calls.

## State Ownership

- One configured coordinator owns all netlink, nftables, and LocalAPI writes.
- Route tables, rule priorities, route protocol, nftables names, and ownership
  metadata define the exact writable identity set.
- Foreign state inside an owned identity is a conflict and is never adopted or
  deleted.
- Live failures close forwarding, blackhole Exit selectors, and clear
  advertisements. The local-control recovery lane remains active only after
  fresh resolver, proxy-TUN, marking, routing-readback, and kernel validation.
- Lost coordination and shutdown always blackhole both managed policy tables;
  they never retain the live recovery lane.
- No-drift reconciliation invokes no writer.

## Packet Mark Ownership

The Agent owns only the low 16 packet-mark bits. Nftables preserves the upper
bits while setting the configured local-egress mark, and policy rules match the
same low-bit mask. This keeps the Agent disjoint from Tailscale's Linux mark
bytes.

## Kubernetes API

The service-account token is projected only into the supervisor container. The
Role is restricted to get/update/patch on one pre-created Tailscale state Secret
and get/update on one pre-created identity Lease. It has no Pod, Event, or
namespace-wide Create permission.

Deleting the Lease or losing renewal cancels the owned runtime. Fail-closed
cleanup and containerboot termination complete before coordination returns.

## Secrets

Agent configuration contains no credentials. The external credential Secret is
defined by a SecretContract and injected by exact key. Config rendering receives
only proxy listener credentials; `TS_AUTHKEY` is visible only to the supervisor
and its allowlisted containerboot child environment.

The Tailscale state Secret is runtime-owned. Its declarative manifest omits
`data`, and GitOps must never apply an empty state payload or source it from
credential values. Logs and validation errors never include child-process
environment values, raw LocalAPI payloads, auth keys, or Kubernetes tokens.
Operational failures necessarily identify managed prefixes, targets, and link
names; logs are therefore internal telemetry and require access control.

## Capability Probe Egress

The in-process capability monitor sends only bounded HTTPS GET requests to the
two statically configured, externally approved endpoints. It sends no
credentials, cookies, request body, authorization, or ambient proxy headers.
Redirects and environment proxies are disabled, normal hostname and TLS 1.2+
verification is mandatory, and the scratch image carries the CA bundle copied
from its pinned build image.

Every DNS result must be exclusively in the requested family and must be a
public Internet destination. The adapter rejects private, loopback, link-local,
multicast, CGNAT, benchmark, documentation, NAT64, transition, and other
special-purpose ranges. Connections are pinned to the validated addresses to
prevent DNS rebinding while preserving the configured hostname for SNI. Linux
sockets receive both the Agent-owned low-bit packet mark and the discovered
proxy TUN device binding before connect. Neither URLs nor resolved addresses
become metric labels or routine log fields.

## Release Trust

Release jobs rerun source and isolated Linux integration gates. They publish a
two-platform OCI index, SBOM, provenance, and keyless signature under an
immutable digest. Each attempt has a unique candidate tag. The public semver tag
is promoted by digest only after complete registry and runtime readback and is
the job's final external write.

Manual releases can run only from `main`. Signature and provenance verification
binds the certificate to the exact release workflow identity on `main` or the
triggering release tag; identities from other branches or tags are rejected.

Kubernetes deployments trust the real OCI digest from completed release
metadata. Candidate tags, signature artifact tags, mutable tags, and prior
digests are not deployment identities.
