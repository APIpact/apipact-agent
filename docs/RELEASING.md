# Releasing

Maintainer guide for cutting a release. The pipeline is
[`.github/workflows/release.yml`](../.github/workflows/release.yml).

## Versioning

- **Semantic versioning**, tag form `vMAJOR.MINOR.PATCH` (e.g. `v1.4.2`).
- **Pre-releases** use a suffix: `v1.5.0-beta.1`, `v1.5.0-rc.1`.
- The tag is injected into the binary at build time (`internal/version`), so
  `apipact-worker --version` and the update-eligibility check reflect it.

## Channels

The channel is derived from the tag automatically:

| Tag | Channel | GitHub Release | Container tags |
|---|---|---|---|
| `v1.4.2` | `stable` | normal | `:v1.4.2`, `:stable`, `:latest` |
| `v1.5.0-beta.1` | `beta` | prerelease | `:v1.5.0-beta.1`, `:beta` |

Agents follow the channel in their config (`update.channel`). Manifests are
published per channel and per platform to GitHub Pages:

```
https://<org>.github.io/apipact-agent/<channel>/<os>-<arch>.json
```

Publishing is **additive** (`keep_files: true`), so cutting a beta never disturbs
the stable manifests, and vice-versa.

## One-time setup

1. **Generate the release signing key** (Ed25519). This key signs update
   manifests; its public half is what agents verify against.
   ```bash
   apipact-agentctl release-keygen
   ```
2. Add the **private** half as the repo secret `RELEASE_SIGN_PRIVATE_B64`
   (Settings → Secrets → Actions). Never commit it.
3. Hand the **public** half to the cloud team: it must be returned to agents as
   `update.releaseSigner` in the enrollment response so their supervisors accept
   signed manifests. Rotating this key requires re-enrolling agents (or a
   cloud-pushed config update), so treat it as long-lived and store it securely
   (HSM / secrets manager) — losing it breaks self-update for the fleet.
4. Enable **GitHub Pages** for the repo (source: `gh-pages` branch).

## Cutting a release

```bash
git switch main && git pull
git tag v1.4.2                 # or v1.5.0-beta.1 for a prerelease
git push origin v1.4.2
```

The workflow then:

1. resolves version + channel from the tag;
2. cross-compiles the three binaries for all platforms (reproducible flags:
   `CGO_ENABLED=0`, `-trimpath`, pinned deps);
3. generates `SHA256SUMS`;
4. **signs** a per-platform update manifest with `RELEASE_SIGN_PRIVATE_B64`,
   pointing each manifest's `worker.url` at the release asset;
5. creates the GitHub Release (prerelease for beta) with all assets;
6. publishes the signed manifests to the channel path on GitHub Pages;
7. builds and pushes the multi-arch container image to GHCR.

You can also run it manually from the Actions tab (`workflow_dispatch`) with a tag
input to re-publish.

## Rollout & rollback

- **Staged rollout**: cut a `-beta` first; a subset of agents on the `beta` channel
  pick it up. Promote to `stable` once healthy.
- **Version pinning**: hold specific agents back with `update.pinnedVersion` in
  their config — they update only to that exact version.
- **Agent-side rollback**: if a new worker fails its post-update health check, the
  supervisor automatically rolls back to the previous binary (kept as
  `apipact-worker.prev`). No manual action needed.
- **Pulling a bad release**: publishing a newer signed manifest supersedes it. For
  a hard stop, remove/replace the channel manifest on `gh-pages`; agents will not
  "update" to an older version (the eligibility check only moves forward).

## Verifying a release

```bash
# in a clean checkout at the tag, with the same Go version:
make checksums    # compare against the release SHA256SUMS
make sbom         # module inventory
```

Reproducible flags mean a rebuild should match the published artifact byte-for-byte
(modulo the injected version/commit/date). See [TRUST.md §8](../TRUST.md).
