# Agent Configuration Reference

This is the operator's reference for configuring an APIPact agent: how it is
associated with your cloud account, where the config lives, every field, the
environment variables, and how to provision it (enrollment, containers, air-gap).

The config is the source of truth the agent runs from. It contains **private
keys**, so it is always written `0600` and owned by the account the agent runs as.

---

## 1. How the agent is associated with your cloud service

An agent becomes *your* agent through a **one-time enrollment token**. This is the
binding — there is no other coupling in the source (no baked-in account id, no
shared global endpoint).

```
Cloud console                         Host inside your network
─────────────                         ────────────────────────
1. Create agent → mint a one-time,    2. agentctl enroll --token <T> --server <cloud>
   tenant-scoped token  ─────────────▶    - generates keypairs locally
                                           - POSTs token + public keys (pinned TLS)
3. Validate token, bind the new       ◀──  - receives agentId, keys, channels, policy
   agentId to your account/tenant,          - writes /etc/apipact/agent.json (0600)
   return identity + channel context
```

- The **token** is issued by your control plane, scoped to a tenant/account (and
  optionally to a location, environment, or expiry). Redeeming it is what ties the
  agent's new `agentId` to your account on the cloud side.
- The token is **single-use and short-lived**. It authorizes *registration only* —
  it is not a long-lived credential and is never stored on the host.
- After enrollment the association is durable and cryptographic: the agent holds
  its `agentId`, its private keys, and your cloud's public keys. From then on every
  message is sealed/verified against those keys, and the agent listens only on its
  own `agent-<id>-*` channels. See [api/CONTRACT.md §7](../api/CONTRACT.md).
- **Fleet model:** one cloud account can enroll many agents (each gets a distinct
  `agentId` and its own channels). The relationship is many-to-many; nothing about
  the agent is 1:1 with the cloud. Correlation across the fleet rides in each job's
  opaque `context`.
- **Re-association / decommission:** to move an agent to another account or rotate
  it, enroll again with a new token (writes a fresh config) — or delete the config
  and the agent can no longer act. Revoking the agent in the console stops the cloud
  from sealing jobs to it.

> The enrollment endpoint, contract, and response fields the cloud must implement
> are specified in [api/CONTRACT.md §7](../api/CONTRACT.md). The cloud is the party
> that decides token scope and lifetime.

---

## 2. Where the config lives

| | Path |
|---|---|
| Default (Linux, per-user) | `$XDG_CONFIG_HOME/apipact/agent.json` → typically `~/.config/apipact/agent.json` |
| System service (systemd) | `/etc/apipact/agent.json` |
| Container | mounted at `/etc/apipact/agent.json` (via `APIPACT_CONFIG`) |
| Override | any path via `--config` or `$APIPACT_CONFIG` |

Alongside it the agent keeps a small **state file** (`dedupe.json` by default, next
to the config) holding processed job ids for restart-safe idempotency. It contains
no secrets but should persist across restarts.

---

## 3. Environment variables

The agent is configured by file, not env; only these operational knobs are read
from the environment:

| Variable | Used by | Meaning | Default |
|---|---|---|---|
| `APIPACT_CONFIG` | all | config file path | per-user / `/etc/apipact/agent.json` |
| `APIPACT_LOG_LEVEL` | all | `debug`\|`info`\|`warn`\|`error` | `info` |
| `APIPACT_HEALTH_ADDR` | supervisor | loopback health address passed to the worker | `127.0.0.1:9099` |
| `APIPACT_WORKER_BIN` | supervisor | path to the worker binary it manages | sibling `apipact-worker` |

Command-line flags (`--config`, `--state`, `--health-addr`, `--worker`,
`--version`, `--selfcheck`) take precedence over the environment.

---

## 4. Config file schema

A complete `agent.json`. Fields marked *(enrollment)* are populated automatically
by `agentctl enroll`; you only hand-edit them for air-gapped provisioning.

```jsonc
{
  "agentId": "7f3a9c2b1d",              // (enrollment) unique slug-safe id; derives channel names
  "name": "prod-eu-dc1",                // human-friendly display name (differentiates agents in the UI)
  "labels": { "env": "prod", "region": "eu" }, // operator tags for grouping/filtering
  "cloudBaseUrl": "https://cloud.example", // (enrollment) control-plane REST base (re-enroll, rotate)

  "pushflo": {                           // (enrollment) relay credentials
    "baseUrl": "",                       //   blank => https://api.pushflo.dev
    "publishKey": "pub_...",             //   subscribe to jobs/control (required)
    "secretKey": "sec_..."               //   publish results (required for channel return)
  },

  "keys": {                              // (enrollment) sealed-envelope key material
    "recipientPublic":  "base64",        //   agent X25519 public  (jobs sealed to it)
    "recipientPrivate": "base64",        //   agent X25519 private (never leaves host)
    "cloudSigners": { "cloud-1": "base64" }, // skid -> cloud Ed25519 public (verify jobs)
    "cloudPublic":  "base64",            //   cloud X25519 public  (seal results to it)
    "signPrivate":  "base64",            //   agent Ed25519 private (sign results)
    "signKeyId":    "agent-...-1",       //   this agent's skid on outbound messages
    "recipientKeyId":   "",              //   optional kid/epoch for rotation
    "cloudRecipientId": "cloud-1"        //   optional cloud kid/epoch
  },

  "egress": {                            // operator-owned SSRF policy (cloud cannot loosen it)
    "allowPrivate": false,               //   allow RFC1918/loopback targets globally
    "allow": ["10.1.0.0/16"],            //   CIDRs/hosts explicitly permitted
    "block": []                          //   extra CIDRs explicitly denied
  },                                     //   metadata (169.254.169.254) is ALWAYS blocked

  "return": {                            // default result-return path (a job may override)
    "transport": "channel",              //   "channel" | "http"
    "resultUrl": "https://cloud.example/api/v1/results", // for transport=http / oversized diversion
    "resultToken": "...",                //   bearer token for the result endpoint
    "inlineMaxBytes": 204800             //   channel results above this switch to HTTP (~200KB)
  },

  "update": {                            // (enrollment) self-update settings
    "mode": "binary",                    //   "binary" (self-update) | "external" (container/orchestrator)
    "channel": "stable",                 //   release channel
    "manifestUrl": "https://updates.example/stable/linux-amd64.json",
    "releaseSigner": "base64",           //   Ed25519 public key that signs manifests
    "pinnedVersion": "",                 //   if set, do not update past this exact version
    "pollInterval": "5m"                 //   how often the supervisor checks
  },

  "limits": {
    "maxConcurrency": 8,                 //   in-flight requests cap
    "maxBodyBytes": 1048576,             //   response body cap (1 MiB)
    "clockSkewSec": 120,                 //   envelope freshness window
    "replayTtlSec": 600,                 //   replay-cache retention
    "heartbeatSec": 60                   //   version/liveness heartbeat interval (0 disables)
  }
}
```

### Field notes

- **Required to start:** `agentId`, `pushflo.publishKey`. Channel return also needs
  `pushflo.secretKey`; HTTP return needs `return.resultUrl`. Validation runs on load
  (`config.Validate`) and fails fast with a clear message.
- **Defaults** are applied on load: `maxConcurrency=8`, `maxBodyBytes=1 MiB`,
  `clockSkewSec=120`, `replayTtlSec=600`, `update.mode=binary`,
  `return.transport=channel`.
- **`egress`** is the one section you may want to tune per site (see §6). It is
  deliberately operator-owned; the cloud cannot widen it remotely.
- **`update.mode="external"`** disables binary self-update entirely — use it in
  containers where the orchestrator pulls new image tags.

---

## 5. Provisioning methods

### A. Online enrollment (recommended)

```bash
agentctl enroll --token <TOKEN> --server https://cloud.example \
  --name prod-eu-dc1 --label env=prod --label region=eu \
  [--pin <SERVER_SPKI_SHA256_BASE64>] [--config /etc/apipact/agent.json]
```

`--name` and `--label` (repeatable) set the agent's display name and tags so you
can tell agents apart in the console; the cloud may override the name. The agent's
live build **version** is reported continuously to the cloud via heartbeats (it
changes automatically after a self-update), so you never set it by hand.

Generates keys locally, registers, and writes the full `0600` config. `--pin`
defends first contact against a MITM by requiring the server's certificate public
key to match. This is the flow the [install script](../scripts/install.sh) and the
[systemd unit](../deploy/systemd/apipact-agent.service) expect.

### B. Air-gapped / config-management (offline)

When a host cannot reach the console interactively, provision the file directly:

1. Generate a key set out-of-band: `agentctl keygen` (prints both directions).
2. Have the cloud register the agent's public keys and allocate an `agentId`.
3. Hand-write `agent.json` (schema above) and deliver it via your config-management
   tool (Ansible/Chef/Puppet) or a mounted secret. Keep it `0600`.

### C. Container / Kubernetes

Mount the config as a secret at `/etc/apipact/agent.json`:

```yaml
# Kubernetes: config from a Secret, self-update handled by image tags
volumes:
  - name: agent-config
    secret: { secretName: apipact-agent-config, defaultMode: 0400 }
volumeMounts:
  - { name: agent-config, mountPath: /etc/apipact, readOnly: true }
env:
  - { name: APIPACT_CONFIG, value: /etc/apipact/agent.json }
```

Set `update.mode: "external"` in the config so the supervisor supervises but does
not self-replace; roll out new versions by bumping the image tag. A
[docker-compose example](../deploy/docker-compose.yml) is included.

---

## 6. Tuning the egress policy

Out of the box the agent blocks cloud-metadata, link-local, loopback, and RFC1918
targets (after DNS resolution). To test internal endpoints, widen it deliberately:

```jsonc
"egress": { "allowPrivate": false, "allow": ["10.20.0.0/16", "192.168.50.10/32"] }
```

- Prefer a tight `allow` list over `allowPrivate: true`.
- `169.254.169.254` (and IMDSv6) stay blocked even with `allowPrivate: true`.
- A blocked target surfaces as `error.kind = "blocked"` in the result — not a silent drop.

See [TRUST.md §4](../TRUST.md) for the guarantees and `internal/executor/egress.go`
for the enforcement.

---

## 7. Verifying a config

```bash
agentctl status --config /etc/apipact/agent.json   # identity + channels + egress summary
apipact-worker --selfcheck --config /etc/apipact/agent.json   # validates keys + policy, exits 0/1
```

`--selfcheck` is the same gate the supervisor runs on a freshly downloaded worker
before promoting an update, so it is a faithful "will this config actually run" check.
