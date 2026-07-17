# APIPact Agent ↔ Cloud Contract (v1)

This is the authoritative interface between the **cloud control plane** and a
**local executor agent**. The agent owns this contract; the cloud mirrors it.
The Go source of truth is [`internal/protocol`](../internal/protocol); this
document is the human-readable spec plus the parts that live outside the message
types (channels, enrollment, envelope, result endpoint, update manifest).

Everything sensitive is end-to-end encrypted. The PushFlo relay and any HTTP
intermediary only ever see ciphertext. Treat the relay as **untrusted** — it can
delay, drop, duplicate, or reorder, but it cannot read or forge messages.

---

## 1. Identity, channels, and fleet context

One cloud drives **many** agents across different networks — the relationship is
many-to-many, never 1:1. Each agent has three identity elements:

- **`agentId`** — the unique, slug-safe machine id (lowercase letters, digits,
  non-repeating hyphens; ≤100 chars) minted at enrollment. It is what
  differentiates agents on the wire and derives their channel names. Immutable.
- **`name`** — an optional human-friendly display name (e.g. `prod-eu-dc1`) the
  operator sets at enrollment (the cloud may assign/override it). For the UI.
- **`labels`** — optional operator tags (`env=prod`, `region=eu`) for grouping.

Channels are derived from the `agentId` (PushFlo slugs forbid dots/uppercase):

| Purpose | Channel | Direction |
|---|---|---|
| Jobs | `agent-<id>-jobs` | cloud → agent |
| Results | `agent-<id>-results` | agent → cloud |
| Control / heartbeat | `agent-<id>-control` | both |

Correlation across the fleet is carried **inside** each job: the `context` field
is opaque to the agent and echoed **verbatim** in the result. Put whatever the
cloud needs there (tenant, run id, scheduler cursor, target infra) — the agent
never inspects it.

**Live build version.** The agent reports its running version continuously (see
§5), not just at enrollment — because it **changes on auto-update**. The cloud
should treat the latest heartbeat as the source of truth for an agent's version.

---

## 2. The encryption envelope

Every message (job, result, control, ack) is a `pushflo/envelope.Envelope`
(JSON), whose plaintext is one of the types below. The envelope is a NaCl sealed
box (X25519) for confidentiality plus an Ed25519 signature over **all** metadata
+ ciphertext for authenticity. Wire fields (clear, for routing only):

```
v, alg, kid (recipient key epoch), skid (signer key id),
mid (message id), ts (unix ms), ch (channel), cty (content type),
ct (base64 sealed box), sig (base64 ed25519)
```

Content types (`cty`) — the agent dispatches on these, not on the event type:

| `cty` | plaintext |
|---|---|
| `application/apipact.job+json` | `Job` |
| `application/apipact.result+json` | `Result` |
| `application/apipact.control+json` | `ControlMessage` |
| `application/apipact.ack+json` | `Ack` |

**Keys (four total).** Cloud seals jobs to the **agent's X25519** key and signs
with the **cloud's Ed25519** key. Agent seals results to the **cloud's X25519**
key and signs with the **agent's Ed25519** key. `skid`/`kid` allow rotation:
the agent accepts multiple cloud signer epochs; a rotation nudge (control) makes
the agent register a fresh recipient key and the cloud starts sealing to the new
`kid` with an overlap window.

**The cloud MUST:**
- set a unique `mid` per message (used for replay dedupe within the skew window);
- set `ts` to real send time (agent rejects outside ±`clockSkewSec`, default 120s);
- sign with a `skid` the agent knows (from enrollment);
- set `cty` correctly.

The agent verifies signature → checks freshness → rejects replays → decrypts,
and refuses to act on anything it cannot prove originated from the cloud.

---

## 3. Job (cloud → agent)

```jsonc
{
  "jobId": "string",            // idempotency/dedupe key — REQUIRED, unique
  "agentId": "7f3a9c2b1d",      // must equal the target agent (else ignored)
  "issuedAt": "2026-07-14T12:00:00Z",
  "deadline": "2026-07-14T12:00:30Z", // optional; agent skips if already past
  "context": { "anything": "opaque, echoed back verbatim" },
  "return": {                   // optional; falls back to agent enrollment default
    "transport": "channel|http",
    "channel": "agent-<id>-results", // for transport=channel
    "url": "https://cloud/api/v1/results", // for transport=http
    "inlineMaxBytes": 204800    // channel results larger than this divert to http
  },
  "execution": { "maxConcurrency": 1, "stopOnError": false },
  "requests": [ RequestSpec, ... ]  // executed in order (or bounded-concurrent)
}
```

### RequestSpec

```jsonc
{
  "id": "r1",
  "method": "GET",
  "url": "https://api.example.com/v1/thing?a=1",
  "headers": [ {"name":"X-Akamai-Test","value":"edge-1"}, ... ], // ORDERED, may repeat
  "hostOverride": "www.protected.example",   // sets Host header (+ SNI unless sni set)
  "sni": "edge.example",                      // TLS ServerName override
  "query": [ {"name":"page","value":"2"} ],   // appended to url in order
  "bodyBase64": "…",
  "followRedirects": false,                    // default false: capture the 3xx + Location
  "maxRedirects": 10,
  "insecureSkipVerify": false,                 // for self-signed staging certs
  "timeouts": { "connectMs":0, "tlsMs":0, "responseHeaderMs":0, "totalMs":30000 },
  "maxBodyBytes": 1048576,                     // 0 => agent default (1 MiB)
  "reuseConnection": false,                    // false => cold connection (no keep-alive)
  "http2": "auto|force|disable",
  "acceptEncoding": "asis|identity|gzip",      // default "asis" (verbatim, no auto-decode)
  "captureCertChain": false
}
```

**Faithful execution — how the agent handles the tricky cases:**

- **Headers are sent verbatim** (exact names, values, repetition). Go's default
  `User-Agent` is **suppressed** unless a header sets it. A `Host` header maps to
  the real Host. This is how Akamai/CDN "special header" requirements
  (`True-Client-IP`, `Pragma: akamai-*`, custom auth headers) are satisfied.
- **`acceptEncoding: "asis"` (default)** sends only the headers you specify and
  never auto-decodes, so the reported body is the literal bytes on the wire and
  the `Content-Encoding` header is preserved — the right choice for edge testing.
  Use `"gzip"` for transparent decompression, `"identity"` to force uncompressed.
- **Redirects are not followed by default** — you get the 3xx and its `Location`.
  When `followRedirects` is true, the full chain is captured (`redirectChain`).
- **Per-layer timeouts** (connect, tls, responseHeader, total) and a body cap.
- **`insecureSkipVerify`** is a deliberate per-request opt-in for staging.
- **Egress guard:** the agent blocks cloud-metadata (`169.254.169.254`),
  link-local, loopback, and RFC1918 targets **after DNS resolution** (closing
  DNS-rebinding), unless the operator allowlisted them. Denied targets return
  `error.kind = "blocked"`. Note the cloud cannot override this remotely — it is
  operator-owned by design.

Not the agent's job: assertions. The agent reports facts; the cloud decides
pass/fail.

---

## 4. Result (agent → cloud)

Sealed and signed identically to a job, delivered over the results channel or by
HTTP POST (see §6).

```jsonc
{
  "jobId": "…", "agentId": "…",
  "context": { … },              // echoed verbatim from the job
  "agentVersion": "v1.2.3", "workerVersion": "v1.2.3",
  "startedAt": "…", "finishedAt": "…",
  "responses": [ ResponseResult, ... ]  // index-aligned to job.requests
}
```

### ResponseResult

```jsonc
{
  "requestId": "r1",
  "status": 201,
  "proto": "HTTP/2.0",
  "headers": [ {"name":"Content-Type","value":"application/json"}, ... ], // multimap, order preserved
  "bodyEncoding": "base64|truncated",
  "bodyBase64": "…",
  "bodyTruncated": false,
  "bodyBytes": 1234,
  "timing": { "dnsMs":1.2, "connectMs":3.4, "tlsMs":9.0, "ttfbMs":42.1, "totalMs":55.9 },
  "redirectChain": [ {"status":302,"location":"/b","url":"https://…/a"} ],
  "tls": { "version":"TLS 1.3","cipherSuite":"…","alpn":"h2","serverName":"…",
           "issuer":"…","subject":"…","dnsNames":["…"],"notBefore":"…","notAfter":"…",
           "peerCertsPem":["-----BEGIN CERTIFICATE-----…"] },  // chain only if captureCertChain
  "error": { "kind":"dns|connect|tls|timeout|http|blocked|invalid", "message":"…", "retryable":true }
}
```

On a transport failure, `status` is 0 and `error` is set; otherwise `error` is
absent. `error.kind` is a stable enum — reason on it programmatically rather than
string-matching `message`.

---

## 5. Control channel & version exchange

The control channel carries cloud→agent instructions and agent→cloud heartbeats.
Both are sealed like everything else.

### Heartbeats (agent → cloud) — how the cloud tracks live version

The agent publishes a sealed `Ack` on the control channel:

- **once on every (re)connect** (`kind:"hello"`) — including right after an
  auto-update, when the fresh worker connects and announces its **new** version;
- **periodically** while running (`kind:"heartbeat"`, default every 60s,
  `limits.heartbeatSec`);
- **in reply to a ping** (`kind:"pong"`, `inReplyTo` = the ping's `mid`).

`Ack` (cty `application/apipact.ack+json`):

```jsonc
{
  "kind": "hello|heartbeat|pong",
  "agentId": "7f3a9c2b1d",
  "name": "prod-eu-dc1",              // display name (may be absent)
  "labels": { "env": "prod" },        // operator tags (may be absent)
  "agentVersion": "v1.2.3",           // the LIVE running build — changes on auto-update
  "workerVersion": "v1.2.3",
  "sentAt": "2026-07-15T12:00:00Z",
  "inFlight": 0,
  "inReplyTo": "<ping mid>"           // only on kind=pong
}
```

The cloud should treat the **most recent heartbeat** as the authoritative version
and liveness for an agent. (Version also appears on every `Result`, so an actively
working agent reports it there too.) Agents configured for HTTP-only return with no
publish key cannot send channel heartbeats — for those, rely on `Result.agentVersion`.

### Control messages (cloud → agent)

`ControlMessage` (sealed, cty `application/apipact.control+json`):

```jsonc
{ "type": "ping|rotate-keys|update|config", "issuedAt": "…", "payload": { … } }
```

- **`ping`** — agent replies with a `pong` Ack.
- **`rotate-keys`** — nudge; the agent generates a new recipient key and
  re-registers it via REST (§7). Cloud keeps sealing to the old `kid` until it
  sees the new one.
- **`update`** — nudge the supervisor to check the release channel immediately.
- **`config`** — a policy/threshold delta (v1: logged; applied on next restart).

---

## 6. Result HTTP endpoint (large results & the "not-WebSocket" path)

Results can travel back by HTTP instead of the channel — per job
(`return.transport = "http"`) or as the agent's enrolled default. A
channel-bound result larger than `inlineMaxBytes` (~200 KB) is **automatically**
diverted to HTTP so multi-MB bodies never clog the control channel.

**Request the cloud must accept:**

```
POST <return.url>
Content-Type: application/apipact.envelope+json
Authorization: Bearer <resultToken>      // from enrollment
X-APIPact-Agent: <agentId>               // clear routing
X-APIPact-Job: <jobId>                    // clear routing / idempotency
<body> = the sealed envelope JSON (ciphertext)
```

Respond `2xx` on success. The body is a sealed `Result` — open it with the
cloud's recipient private key and verify the agent's signature, exactly like a
channel result. `4xx` (except `429`) is treated as permanent; `429`/`5xx`/network
errors are retried with jittered backoff. Idempotency key: `jobId`.

---

## 7. Enrollment (REST) — how an agent is associated with the cloud

The **enrollment token is the association**. It is the only coupling: there is no
baked-in account id or shared endpoint in the agent. The operator creates an agent
in the console (minting a one-time, tenant-scoped token) and runs
`agentctl enroll --token … --server …`. Redeeming the token is what binds the new
`agentId` to that account.

The agent generates its key pairs locally (private halves never leave the host)
and calls:

```
POST <cloudBaseUrl>/api/v1/agents/enroll     (over pinned TLS if a pin is given)
Content-Type: application/json
{
  "token": "…",
  "name": "prod-eu-dc1",                     // optional operator display name
  "labels": { "env":"prod", "region":"eu" }, // optional operator tags
  "recipientPublic": "<agent X25519 public, base64>",
  "signPublic": "<agent Ed25519 public, base64>",
  "hostname": "…", "os": "linux", "arch": "amd64", "agentVersion": "v1.2.3"
}
```

**Association essentials — the minimum the cloud must return** so the agent can
identify itself and exchange sealed messages:

```jsonc
{
  "agentId": "7f3a9c2b1d",                 // slug-safe; the agent enforces this — REQUIRED
  "name": "prod-eu-dc1",                   // optional; cloud may assign/override the display name
  "pushflo": { "publishKey":"pub_…", "secretKey":"sec_…" },  // relay creds — REQUIRED
  "cloudPublic": "<cloud X25519 public, base64>",            // seal results to this — REQUIRED
  "cloudSigners": { "cloud-1": "<cloud Ed25519 public, base64>" } // verify jobs — REQUIRED
}
```

**Operational settings — optional, cloud-managed.** Everything below is a policy
the cloud *may* set at enrollment and can change later (via a `config` control
message or a re-enroll). They are not part of the association and all have safe
defaults if omitted, so keep the association response lean and manage these
wherever your cloud keeps agent settings:

```jsonc
{
  "recipientKeyId": "agent-…-1", "cloudRecipientId": "cloud-1",  // key epochs (rotation)
  "egress": { "allowPrivate": false, "allow": ["10.1.0.0/16"], "block": [] },
  "return": { "transport":"channel", "resultUrl":"https://…", "resultToken":"…", "inlineMaxBytes":204800 },
  "update": { "mode":"binary", "channel":"stable", "manifestUrl":"https://…/manifest.json",
              "releaseSigner":"<Ed25519 public, base64>", "pollInterval":"5m" },
  "limits": { "maxConcurrency":8, "maxBodyBytes":1048576, "clockSkewSec":120, "replayTtlSec":600, "heartbeatSec":60 }
}
```

> Note: `update.releaseSigner` must be present for binary self-update to work, and
> `return.resultUrl` is required if you choose HTTP result return — but both are
> policy choices, not part of the identity binding.

The agent writes all of this (plus its local private keys) to a `0600` config.
After enrollment the association is durable and cryptographic: the agent's
`agentId` + private keys + the cloud's public keys. To decommission, revoke the
agent in the console (the cloud stops sealing jobs to it) and/or delete the config.

---

## 8. Self-update manifest

The supervisor polls `update.manifestUrl` and verifies it against
`update.releaseSigner`. The endpoint returns a **signed** manifest:

```jsonc
{
  "payload": "<base64 of the manifest JSON below>",
  "signature": "<base64 Ed25519 signature over the decoded payload>"
}
```

Manifest payload:

```jsonc
{
  "version": "v1.2.3", "channel": "stable", "os": "linux", "arch": "amd64",
  "worker": { "url":"https://cdn/…/worker-linux-amd64", "sha256":"<hex>", "size":12345678 },
  "releasedAt": "2026-07-14T00:00:00Z"
}
```

The supervisor verifies the signature, downloads the worker, verifies the
SHA-256, self-checks the new binary, swaps atomically (keeping the previous for
rollback), restarts, health-checks, and rolls back on failure. Serve a
per-`os`/`arch` manifest URL. Use `cmd/release-sign` to produce these.

---

## 9. Delivery semantics

- **At-least-once.** The cloud may redeliver; the agent dedupes on `jobId`
  (persisted across restarts) and on envelope `mid` (replay cache). Re-use the
  same `jobId` for a retry of the *same* job; use a new one for a genuinely new
  run.
- **Ordering is not guaranteed** by the relay. If order matters, put multiple
  requests in one job (they run in order unless `maxConcurrency > 1`).
- **Backpressure.** The agent caps in-flight requests (`limits.maxConcurrency`);
  a burst queues rather than exhausting connections.
