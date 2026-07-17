# Distribution & Installation

How the agent is built, published, and installed, and how it stays up to date.

## What ships

Every tagged release publishes, for `linux/{amd64,arm64}`, `darwin/{amd64,arm64}`,
and `windows/amd64`:

- **Binaries** — `apipact-supervisor`, `apipact-worker`, `apipact-agentctl`
  (per platform, as GitHub Release assets).
- **`SHA256SUMS`** — checksums for every binary.
- **Signed update manifests** — published to the update channel (GitHub Pages),
  so already-installed agents can self-update (see below).
- **Container image** — multi-arch `ghcr.io/apipact/apipact-agent`, tagged with the
  version, the channel (`stable`/`beta`), and `latest` (stable only).

The release pipeline is [`.github/workflows/release.yml`](../.github/workflows/release.yml);
maintainer steps are in [RELEASING.md](RELEASING.md).

## Install methods

### 1. Install script (bare host / VM)

**Full setup in one line** — install, enroll, boot-persistent service, start
(the token comes from the console, Settings → Agents → New Agent):

```bash
curl -fsSL https://raw.githubusercontent.com/APIpact/apipact-agent/main/scripts/install.sh \
  | sh -s -- --token <TOKEN> --server https://console.apipact.dev
```

On Linux this installs a hardened systemd service; on macOS a launchd daemon.
Both start at boot and keep the agent running.

Binaries only (no enroll, no service):

```bash
curl -fsSL https://raw.githubusercontent.com/APIpact/apipact-agent/main/scripts/install.sh | sh
# pin a version / add the service without enrolling:
curl -fsSL .../scripts/install.sh | sh -s -- --version v1.2.3 --service
```

**Uninstall** the same way (config/keys survive unless you `--purge`):

```bash
curl -fsSL .../scripts/install.sh | sh -s -- --uninstall          # keep enrollment config
curl -fsSL .../scripts/install.sh | sh -s -- --uninstall --purge  # remove everything
```

It detects your OS/arch, downloads the three binaries, **verifies their SHA-256**
against the release `SHA256SUMS`, and installs them to `/usr/local/bin`. The
Linux service is the hardened [unit file](../deploy/systemd/apipact-agent.service)
running as the dedicated `apipact` system user.

### 2. Manual binary install

Download the three `apipact-*-<os>-<arch>` assets and `SHA256SUMS` from the
[Releases page](https://github.com/APIpact/apipact-agent/releases), verify, and
place them on `PATH`. Then enroll (§ below).

### 3. Container / Kubernetes

```bash
docker compose -f deploy/docker-compose.yml up -d   # see deploy/docker-compose.yml
```

Mount an enrolled `agent.json` (with `update.mode: "external"`). Updates are image
-tag pulls; the supervisor supervises the worker but does not self-replace.

## Enroll (associate with your cloud)

Installation puts binaries in place; **enrollment** ties the agent to your cloud
account via a one-time token:

```bash
apipact-agentctl enroll --token <TOKEN> --server https://cloud.example \
  --name prod-eu-dc1 --label env=prod --config /etc/apipact/agent.json
```

Full details, including air-gapped provisioning, are in
[CONFIGURATION.md](CONFIGURATION.md).

## Running as a service (systemd)

```bash
sudo systemctl enable --now apipact-agent
sudo systemctl status apipact-agent
journalctl -u apipact-agent -f
```

The unit runs the **supervisor** as an unprivileged `apipact` user with a hardened
sandbox. The self-updated **worker** lives in `/var/lib/apipact/` (writable,
agent-owned) so binary self-update can swap it atomically while `/usr` stays
read-only.

## Staying up to date

- **Binary mode** (`update.mode: "binary"`, default for host installs): the
  supervisor polls the signed manifest for its channel, verifies signature +
  checksum, and swaps the worker with health-gated rollback. Nothing to do.
- **External mode** (containers): pull a newer image tag and restart.
- **Channels**: `stable` (default) and `beta`. An agent follows the channel set in
  its config (`update.channel`). Pin an exact version with `update.pinnedVersion`.
- **Version visibility**: each agent reports its **live** running version to the
  cloud via heartbeats, so the fleet's versions are always current — including
  right after an auto-update.

## Verifying what you run

```bash
# checksums of installed binaries vs the release SHA256SUMS
sha256sum /usr/local/bin/apipact-*
# module inventory embedded in a binary
go version -m /usr/local/bin/apipact-worker
```

See [TRUST.md](../TRUST.md) for the full "does this binary match the source" story.
