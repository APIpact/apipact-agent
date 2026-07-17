# Security Model

The agent runs inside a customer network and makes authenticated HTTP calls on
command. That makes trust a first-class requirement. This document states the
threat model and the controls.

## Threat model

- **The PushFlo relay is untrusted.** It can deliver, delay, drop, duplicate, or
  reorder messages, but it must never read or forge them.
- **The agent is an SSRF engine by design.** It calls arbitrary endpoints from
  inside the network. A compromised relay must not be able to redirect that
  capability.
- **The auto-updater is a remote-code-execution channel by design.** It must only
  ever run artifacts proven to originate from the release signing key.

## Controls

1. **End-to-end encryption + authenticity.** Every job/result/control message is
   a NaCl sealed box (X25519) signed with Ed25519 over all metadata + ciphertext
   (`pushflo/envelope`). The agent verifies the signature, checks freshness
   (`clockSkewSec`), rejects replays (`mid` + persistent `jobId` dedupe), then
   decrypts. It acts only on messages it can prove came from the cloud.
2. **Keys established at enrollment**, never through the relay. Private keys are
   generated on the host and never leave it. `kid`/`skid` support rotation.
3. **Egress guard.** After DNS resolution, the agent refuses to connect to
   cloud-metadata (`169.254.169.254`), link-local, loopback, and RFC1918 targets
   unless the operator allowlisted them. It dials the vetted IP directly, so DNS
   rebinding cannot bypass the check. This is operator-owned; the cloud cannot
   relax it remotely.
4. **TLS.** Verification is on by default; `insecureSkipVerify` is a deliberate
   per-request opt-in for staging. Enrollment/update endpoints can be TLS-pinned.
5. **Secrets at rest.** Config is written `0600`. Logs never print header values
   or response bodies; URLs are redacted.
6. **Supply chain.** Releases are signed; the supervisor verifies the manifest
   signature and the worker SHA-256, and runs `--selfcheck` before promoting. It
   keeps the previous binary and rolls back on an unhealthy update. Goal:
   reproducible builds + SBOM so a reviewer can confirm the running binary
   matches public source.

## Residual exposure

The relay can still observe **metadata**: message sizes, timing, and which
channels are active. Contents remain opaque. Padding/batching are available
mitigations if that ever matters.

## Reporting

Report vulnerabilities privately to the maintainers rather than via public
issues.
