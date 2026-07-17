# Trust & Auditing Guide

You are about to run software **inside your network** that makes **authenticated
HTTP calls on command** and **updates itself**. That is exactly the profile where
"you can read precisely what it does" should turn a cautious *no* into a *yes*.
This document is written for the security reviewer who has to sign off. Every
claim points at the code that backs it, so you can verify rather than trust.

- **Source**: this repository. **License**: Apache-2.0 ([LICENSE](LICENSE)).
- **Size to review**: ~3,500 lines of Go (implementation), ~1,300 lines of tests.
  Small enough to read end to end in an afternoon.
- **Threat model & controls**: [SECURITY.md](SECURITY.md).
- **The exact cloud interface**: [api/CONTRACT.md](api/CONTRACT.md).

---

## 1. What the agent does — and does not do

**It does, and only does, four things** (`internal/worker/worker.go`):

1. Holds one outbound WebSocket connection to the PushFlo relay.
2. Receives request specifications, **proves they came from your cloud**, decrypts them.
3. Executes the HTTP calls under an egress policy and a bounded worker pool.
4. Returns a structured, sealed result.

**It deliberately does NOT:**

| Not this | Why you can be sure |
|---|---|
| Open any inbound port / listen for the internet | The only listener is a **loopback-only** health server (`startHealthServer`, bound to `127.0.0.1`). All cloud traffic is agent-initiated outbound. |
| Run shell commands, scripts, or arbitrary code from the cloud | There is no `exec`, `eval`, or plugin path in the worker. The only thing it does with a job is build an `http.Request` (`internal/executor`). |
| Execute a job it cannot cryptographically attribute to your cloud | `Opener.Open` verifies the Ed25519 signature, checks freshness, and rejects replays *before* decrypting (`internal/secure`, `worker.onJob`). |
| Reach cloud-metadata or internal ranges by default | The egress guard blocks them after DNS resolution (`internal/executor/egress.go`). |
| Read or write files outside its config/state dir | It touches only the config (`0600`) and a dedupe state file. No traversal of the host FS. |
| Phone home anywhere except the relay, the result endpoint, and the update manifest | All three URLs come from *your* enrollment response and live in the config you can inspect. |
| Send secrets to the relay or to logs | Payloads are end-to-end encrypted; logs never print header values or bodies (`internal/obs`). |

The `supervisor` process (`cmd/supervisor`) does one extra thing — self-update —
covered in §6.

## 2. Data flows — what touches what

```
your cloud ──seal+sign──▶ PushFlo relay ──▶ agent  (relay sees only ciphertext)
   ▲                                          │
   │                                          ▼  builds http.Request, egress-guarded
   │                                     target API (inside your network)
   │                                          │
   └──open+verify◀── results channel / HTTPS POST ◀──seal+sign── result
```

- **To the relay**: opaque ciphertext only. The relay is treated as **untrusted**
  infrastructure — it can drop/delay/duplicate/reorder, but cannot read or forge.
- **To target APIs**: exactly the request your cloud specified — nothing added,
  nothing logged. Response bodies are captured, size-capped, and sealed back.
- **At rest on the host**: the config file (agent private keys, relay keys),
  written `0600`; and a small dedupe state file (job ids only).
- **In logs**: structured events with URLs redacted and no header/body values.

## 3. Network posture

- **Outbound-only.** The agent dials the relay (`wss://…`); the cloud never dials
  in. No inbound firewall changes are required or wanted. See `internal/transport`.
- **Endpoints are enrollment-scoped.** The relay URL, result endpoint, and update
  manifest URL all come from the enrollment response and are stored in the config.
  There are no hardcoded callback hosts in the source.
- **TLS everywhere**, verification on by default. The enrollment/update endpoints
  can be **certificate-pinned** (`enroll.Options.PinSHA256`).

## 4. The permission / egress model (the SSRF story)

The agent is an SSRF engine by design, so containment is explicit and
**operator-owned — the cloud cannot loosen it remotely.**

- Default policy blocks, *after DNS resolution*: cloud-metadata
  (`169.254.169.254`, IMDSv6), link-local, loopback, and RFC1918/ULA ranges
  (`internal/executor/egress.go`, `alwaysBlocked` + `isPrivate`).
- The guard **dials the vetted IP directly**, so a hostname that resolves to a
  blocked address cannot be swapped afterward — DNS rebinding is closed
  (`Engine.guardedDial`).
- Operators opt specific hosts/CIDRs back in via the config `egress.allow`.
  Cloud-metadata stays blocked even with `allowPrivate` set.
- A denied target returns a structured `error.kind = "blocked"` — visible, not silent.

Verify it yourself: `internal/executor/egress_test.go` is a truth table
(metadata / RFC1918 / public / allowlisted) plus a live blocked-dial test.

## 5. Cryptography

Not hand-rolled. The agent uses the vetted `pushflo/envelope` package:
**NaCl sealed box (X25519) for confidentiality + Ed25519 signature over all
metadata and ciphertext for authenticity**, with replay rejection.

- Four keypairs, established at **enrollment** over the direct authenticated
  channel — never through the relay. Agent private keys are generated on the host
  and never leave it (`internal/enroll`, `secure.GenerateAgentKeys`).
- The signature covers routing metadata too, so the relay cannot even alter which
  agent or channel a message targets.
- Freshness (`clockSkewSec`) + replay cache (`mid`) + persistent job-id dedupe
  give at-least-once idempotency without trusting the transport.

Tests: `internal/secure/secure_test.go` proves round-trip, **replay rejection**,
and **forged-signature rejection** (even reusing a known key id).

## 6. The update channel (supply chain)

The auto-updater is a remote-code-execution channel *by design*, so it is the
most scrutinized path (`internal/update`, `internal/supervisor`):

1. The supervisor polls a release **manifest** and verifies its **Ed25519
   signature** against the release key pinned at enrollment. A wrong key ⇒ refuse.
2. It downloads the worker and verifies the **SHA-256** named in the signed
   manifest.
3. It runs the new binary's `--selfcheck` before trusting it.
4. It swaps **atomically**, keeping the previous binary, restarts, and **health-checks**.
5. On any failure it **rolls back** to the previous binary.

This is exercised with real processes end to end:
`internal/supervisor/supervisor_test.go` covers both a successful signed update
and a forced-unhealthy update that rolls back.

Container deployments can sidestep binary self-update entirely
(`update.mode = "external"`): the supervisor only supervises; image-tag pulls are
your orchestrator's job.

## 7. Dependency footprint (what you actually audit)

Intentionally tiny. Beyond the Go standard library, the runtime pulls only:

| Module | Purpose | License |
|---|---|---|
| `github.com/PushFlo/pushflo-go` | pub/sub SDK + envelope crypto | MIT |
| `github.com/gorilla/websocket` | WebSocket transport | BSD-2 |
| `golang.org/x/crypto` | NaCl box, ed25519, curve25519 | BSD-3 |
| `golang.org/x/sys` | syscall support | BSD-3 |

No web framework, no reflection-heavy config libs, no telemetry SDK. Regenerate
the exact version-pinned inventory for a given build with `make sbom`.

## 8. Verifying the binary matches this source

Builds are reproducible: `CGO_ENABLED=0`, `-trimpath`, and pinned module versions
(`go.mod`/`go.sum`). To confirm a binary you were given matches the public source:

```bash
make build                 # builds with -trimpath, no cgo, pinned deps
make checksums             # sha256 of each binary in bin/
make sbom                  # per-binary module inventory (go version -m)
```

Rebuild from a clean checkout at the same Go version and tag; the SHA-256 should
match the release artifact. The update manifest's `sha256` is what the supervisor
enforces, so a tampered binary is rejected before it ever runs (§6).

## 9. How to read the code (entry points)

- `internal/protocol` — the entire wire contract in ~2 files. Start here.
- `internal/worker/worker.go` — `onJob` is the whole receive→execute→return path.
- `internal/executor/executor.go` + `egress.go` — every HTTP behavior and the SSRF guard.
- `internal/secure/secure.go` — the crypto wiring (thin; the primitives are in `envelope`).
- `internal/supervisor` + `internal/update` — the self-update path.
- `cmd/*` — thin mains; no logic hidden here.

Run the full test suite (`go test ./...`) to see the behaviors asserted against
real HTTP servers, real crypto, and real update/rollback with live processes.

## 10. Reporting a vulnerability

Report privately to the maintainers (see [SECURITY.md](SECURITY.md)) rather than
via public issues. Signed, reproducible builds mean a reviewer can always confirm
that the running binary is the code reviewed here.
