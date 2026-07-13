# Security Policy

Report vulnerabilities through GitHub private vulnerability reporting for
`ai-matrix-meta/tailscale-gateway-agent`. Do not include live credentials,
Tailscale auth keys, Kubernetes tokens, LocalAPI responses, or production
network topology in public issues or reproductions.

The authoritative trust boundaries, privilege model, secret ownership, and
supply-chain controls are documented in
[docs/security/SECURITY-MODEL.md](docs/security/SECURITY-MODEL.md).

The supported code is the latest released digest and the current `main` branch.
Security fixes are delivered as a new release and a new immutable digest; image
tags are not a deployment trust boundary.
