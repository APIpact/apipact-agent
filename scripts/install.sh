#!/usr/bin/env sh
# APIPact agent installer.
#
# Downloads the supervisor, worker, and agentctl binaries for this host from
# GitHub Releases, verifies their SHA-256 against the published SHA256SUMS, and
# installs them. Optionally installs a systemd service.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/APIpact/apipact-agent/main/scripts/install.sh | sh
#   ...or with options:
#   sh install.sh --version v1.2.3 --prefix /usr/local/bin --systemd
#
# Env / flags:
#   REPO           GitHub repo (default APIpact/apipact-agent)
#   --version      release tag to install (default: latest)
#   --prefix DIR   install dir (default /usr/local/bin)
#   --systemd      install and enable the systemd service (needs root)
set -eu

REPO="${REPO:-APIpact/apipact-agent}"
VERSION=""
PREFIX="/usr/local/bin"
WITH_SYSTEMD=0

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --prefix)  PREFIX="$2"; shift 2 ;;
    --systemd) WITH_SYSTEMD=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

die() { echo "install: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# --- detect platform --------------------------------------------------------
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$os" in
  linux) os=linux ;;
  darwin) os=darwin ;;
  *) die "unsupported OS: $os (use the container image on this platform)" ;;
esac
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die "unsupported architecture: $arch" ;;
esac
plat="${os}-${arch}"

# --- resolve version --------------------------------------------------------
api="https://api.github.com/repos/${REPO}"
if [ -z "$VERSION" ]; then
  have curl || die "curl is required"
  VERSION="$(curl -fsSL "${api}/releases/latest" | grep -m1 '"tag_name"' | cut -d '"' -f4)"
  [ -n "$VERSION" ] || die "could not resolve the latest release; pass --version"
fi
echo "installing apipact-agent ${VERSION} for ${plat} -> ${PREFIX}"

base="https://github.com/${REPO}/releases/download/${VERSION}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# --- download binaries + checksums -----------------------------------------
bins="apipact-supervisor apipact-worker apipact-agentctl"
for b in $bins; do
  echo "  downloading ${b}-${plat}"
  curl -fsSL -o "${tmp}/${b}" "${base}/${b}-${plat}" || die "download failed: ${b}-${plat}"
done
curl -fsSL -o "${tmp}/SHA256SUMS" "${base}/SHA256SUMS" || die "download failed: SHA256SUMS"

# --- verify checksums -------------------------------------------------------
echo "  verifying checksums"
( cd "$tmp" && for b in $bins; do
    want="$(grep " ${b}-${plat}\$" SHA256SUMS | awk '{print $1}')"
    [ -n "$want" ] || { echo "no checksum for ${b}-${plat}" >&2; exit 1; }
    if have sha256sum; then got="$(sha256sum "$b" | awk '{print $1}')";
    else got="$(shasum -a 256 "$b" | awk '{print $1}')"; fi
    [ "$want" = "$got" ] || { echo "checksum mismatch for ${b}: want ${want} got ${got}" >&2; exit 1; }
  done ) || die "checksum verification failed"

# --- install ----------------------------------------------------------------
SUDO=""
[ -w "$PREFIX" ] || { have sudo && SUDO="sudo" || die "no write access to ${PREFIX} and sudo not found"; }
$SUDO mkdir -p "$PREFIX"
for b in $bins; do
  $SUDO install -m 0755 "${tmp}/${b}" "${PREFIX}/${b}"
done
echo "installed: $bins"

# --- optional systemd -------------------------------------------------------
if [ "$WITH_SYSTEMD" = "1" ]; then
  have systemctl || die "--systemd requested but systemctl not found"
  echo "installing systemd service"
  $SUDO useradd --system --no-create-home --shell /usr/sbin/nologin apipact 2>/dev/null || true
  $SUDO mkdir -p /etc/apipact /var/lib/apipact
  # The managed (self-updated) worker lives in the writable, agent-owned state
  # dir; the supervisor stays in ${PREFIX}. Seed the worker copy there.
  $SUDO install -m 0755 "${PREFIX}/apipact-worker" /var/lib/apipact/apipact-worker
  $SUDO chown -R apipact:apipact /var/lib/apipact
  curl -fsSL "https://raw.githubusercontent.com/${REPO}/${VERSION}/deploy/systemd/apipact-agent.service" \
    | $SUDO tee /etc/systemd/system/apipact-agent.service >/dev/null
  $SUDO systemctl daemon-reload
  echo "systemd unit installed. Enroll, then start:"
else
  echo
  echo "Next steps:"
fi

cat <<EOF
  1. Enroll this agent with your cloud (writes /etc/apipact/agent.json, 0600):
       ${PREFIX}/apipact-agentctl enroll --token <TOKEN> --server <CLOUD_URL> \\
         --name <display-name> --config /etc/apipact/agent.json
  2. Run it:
$( [ "$WITH_SYSTEMD" = "1" ] \
     && echo "       sudo systemctl enable --now apipact-agent" \
     || echo "       ${PREFIX}/apipact-supervisor --config /etc/apipact/agent.json" )

  See https://github.com/${REPO}/blob/${VERSION}/docs/CONFIGURATION.md
EOF
