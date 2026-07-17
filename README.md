# APIPact Agent

A small, self-updating **remote API-test executor** that runs inside a
customer's network. A cloud control plane dispatches HTTP request specifications;
this agent executes them from the network's own vantage point — exercising the
same DNS, TLS, routing, latency, and reachability a real caller there would — and
reports structured results back. It is a **distributed HTTP probe**, not a CI
runner.

The agent is designed to be **comfortable to run**: it makes authenticated calls
on command, so it is open-source, end-to-end encrypted, egress-guarded, and
self-maintaining. The cloud control plane is separate and closed (open-core).

> Transport is [PushFlo](https://github.com/PushFlo/pushflo-go), an
> outbound-initiated pub/sub WebSocket relay — **no inbound ports** in the
> customer's network. The relay is treated as untrusted; every payload is sealed
> and signed (its `envelope` package: NaCl sealed box + Ed25519).

## Why this shape

| Property | How |
|---|---|
| Firewall-friendly | Agent dials out; cloud never dials in. |
| Untrusted relay | Every message end-to-end encrypted **and** signed; replays/forgeries rejected. |
| Faithful execution | Verbatim headers, Host/SNI override, no auto UA/gzip, per-layer timeouts, cold-connection option, full timing + TLS capture. Handles Akamai/CDN "special header" cases. |
| SSRF-safe | Post-DNS egress guard blocks metadata/link-local/RFC1918 by default. |
| Hands-free updates | Supervisor + worker split; signed manifest → verify → atomic swap → health-check → rollback. |
| Fleet-aware | Many agents per cloud; every message carries an opaque `context` echoed back. |

## Architecture

Two processes — a running process can't reliably overwrite and restart itself:

- **supervisor** (`cmd/supervisor`) — tiny, rarely changes. Owns the worker
  lifecycle and self-update. No test logic.
- **worker** (`cmd/worker`) — does the execution. Replaced on each update.
- **agentctl** (`cmd/agentctl`) — operator CLI: `enroll`, `keygen`, `status`.

```
cloud ──seal(job)──▶ PushFlo relay ──▶ agent-<id>-jobs ──▶ worker ──HTTP──▶ target API
                                                              │
cloud ◀─open(result)── results channel / HTTPS POST ◀──seal(result)◀───────┘
```

Packages: [`internal/protocol`](internal/protocol) (the wire contract, mirrored
by the cloud), `executor` (HTTP engine + egress guard), `secure` (envelope
wiring), `transport` (PushFlo client), `reporter` (result return: channel/HTTP),
`update` + `supervisor` (self-update), `enroll`, `config`, `store` (dedupe).

The full interface the cloud implements is in **[api/CONTRACT.md](api/CONTRACT.md)**.

## Documentation

| Doc | For |
|---|---|
| [api/CONTRACT.md](api/CONTRACT.md) | The cloud team — the exact wire contract to implement |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Operators — config reference, cloud association, provisioning |
| [docs/DISTRIBUTION.md](docs/DISTRIBUTION.md) | Operators — install methods, updates, running as a service |
| [docs/RELEASING.md](docs/RELEASING.md) | Maintainers — versioning, channels, cutting a release |
| [TRUST.md](TRUST.md) / [SECURITY.md](SECURITY.md) | Security reviewers — what it does, threat model |

## Install

```bash
# bare host / VM: downloads binaries, verifies checksums, optional systemd service
curl -fsSL https://raw.githubusercontent.com/APIpact/apipact-agent/main/scripts/install.sh | sh -s -- --systemd

# then associate this agent with your cloud account (one-time token):
apipact-agentctl enroll --token <TOKEN> --server https://cloud.example --name prod-eu-dc1
sudo systemctl enable --now apipact-agent
```

Containers, manual installs, and air-gapped provisioning are in
[docs/DISTRIBUTION.md](docs/DISTRIBUTION.md) and [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Quick start (development)

```bash
make build            # builds bin/apipact-{supervisor,worker,agentctl,release-sign}

# 1. Enroll against your control plane (writes a 0600 config):
bin/agentctl enroll --token <TOKEN> --server https://cloud.example [--pin <SPKI-SHA256>]

# 2. Run under the supervisor (self-update on), or the worker directly:
bin/apipact-supervisor                 # production entrypoint
bin/apipact-worker --health-addr 127.0.0.1:9099   # standalone

bin/agentctl status
```

No control plane yet? Generate a key set and drive the agent locally:

```bash
bin/agentctl keygen                    # prints both directions of keys
# hand-write a config (see internal/config.Config), then:
go run ./examples/mock-cloud --agent <id> --secret sec_… \
  --agent-recipient-public <…> --cloud-sign-private <…> --url https://httpbin.org/get
```

## Self-update

The supervisor polls a signed release manifest and applies eligible updates:
verify Ed25519 signature → download worker → verify SHA-256 → `worker --selfcheck`
→ atomic swap (keep `.prev`) → restart → health-check `/readyz` → rollback on
failure. Sign releases with `bin/release-sign` (see [api/CONTRACT.md §8](api/CONTRACT.md)).

Container deployments set `update.mode = "external"`: the supervisor just
supervises; "update" is an image-tag pull by the orchestrator. See the
[Dockerfile](Dockerfile).

## Security posture

- **E2E encryption + authenticity** on every message; the relay is a dumb pipe.
- **Egress guard** (default): block cloud-metadata, link-local, loopback, and
  RFC1918 after DNS resolution; operator opts specific ranges back in.
- **Secrets at rest**: config is `0600`; logs never print header values or bodies.
- **Supply chain**: reproducible builds (`CGO_ENABLED=0`, `-trimpath`, pinned
  deps); the auto-updater verifies Ed25519 signature + SHA-256 before executing
  anything.

## Trust & auditing

Deciding whether to run this inside your network? Start with **[TRUST.md](TRUST.md)** —
a reviewer's guide covering exactly what the agent does and does not do, the
egress/permission model, data flows, the crypto and update trust chains, the
(small) dependency footprint, and how to verify a binary matches this source.
See also [SECURITY.md](SECURITY.md) (threat model) and [NOTICE](NOTICE)
(third-party attribution). Reproduce build provenance with:

```bash
make checksums   # sha256 of each binary
make sbom        # version-pinned module inventory per binary
make verify      # gofmt + vet + full test suite (incl. live self-update/rollback)
```

## Testing

```bash
make test     # unit + integration (httptest echo/redirect/TLS/truncation,
              # egress table, envelope round-trip/replay/forgery, update swap/rollback,
              # and a full sealed-job → execute → sealed-HTTP-result flow)
```

## License

Apache-2.0. See [LICENSE](LICENSE).
