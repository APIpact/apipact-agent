#!/usr/bin/env sh
# APIPact agent installer / uninstaller.
#
# One-liner install (binaries only):
#   curl -fsSL https://raw.githubusercontent.com/APIpact/apipact-agent/main/scripts/install.sh | sh
#
# One-liner full setup — install, enroll, boot-persistent service, start:
#   curl -fsSL .../install.sh | sh -s -- --token <TOKEN> --server https://console.apipact.dev
#
# One-liner uninstall (mirror of the install):
#   curl -fsSL .../install.sh | sh -s -- --uninstall            # keeps the enrollment config
#   curl -fsSL .../install.sh | sh -s -- --uninstall --purge    # also removes config + keys + state
#
# Downloads the supervisor, worker, and agentctl binaries for this host from
# GitHub Releases and verifies their SHA-256 against the published SHA256SUMS.
# With --token it also enrolls against your cloud console and installs a
# service that starts at boot: systemd on Linux, launchd on macOS.
#
# Env / flags:
#   REPO           GitHub repo (default APIpact/apipact-agent)
#   --version      release tag to install (default: latest, pre-releases included)
#   --prefix DIR   install dir (default /usr/local/bin)
#   --token TOK    one-time enrollment token from the console (enables full setup)
#   --server URL   cloud console base URL (required with --token)
#   --name NAME    display name for this agent (optional)
#   --service      install + enable the boot service (implied by --token)
#   --no-service   skip the service even when --token is given
#   --systemd      deprecated alias of --service
#   --uninstall    stop the service and remove binaries/unit (config survives)
#   --purge        with --uninstall: also delete /etc/apipact (keys!) and state
set -eu

REPO="${REPO:-APIpact/apipact-agent}"
VERSION=""
PREFIX="/usr/local/bin"
TOKEN=""
SERVER=""
NAME=""
WITH_SERVICE=""
UNINSTALL=0
PURGE=0

CONFIG_DIR="/etc/apipact"
CONFIG="${CONFIG_DIR}/agent.json"
STATE_DIR="/var/lib/apipact"
UNIT="/etc/systemd/system/apipact-agent.service"
PLIST_LABEL="dev.apipact.agent"
PLIST="/Library/LaunchDaemons/${PLIST_LABEL}.plist"

while [ $# -gt 0 ]; do
  case "$1" in
    --version)   VERSION="$2"; shift 2 ;;
    --prefix)    PREFIX="$2"; shift 2 ;;
    --token)     TOKEN="$2"; shift 2 ;;
    --server)    SERVER="$2"; shift 2 ;;
    --name)      NAME="$2"; shift 2 ;;
    --service|--systemd) WITH_SERVICE=1; shift ;;
    --no-service) WITH_SERVICE=0; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge)     PURGE=1; shift ;;
    -h|--help)   grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

die() { echo "install: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$os" in
  linux) os=linux ;;
  darwin) os=darwin ;;
  *) die "unsupported OS: $os (use the container image on this platform)" ;;
esac

SUDO=""
if [ "$(id -u)" != "0" ]; then
  have sudo && SUDO="sudo" || die "root privileges required (install sudo or run as root)"
fi

# --- uninstall --------------------------------------------------------------
if [ "$UNINSTALL" = "1" ]; then
  echo "uninstalling apipact-agent"
  if [ "$os" = "linux" ] && have systemctl; then
    $SUDO systemctl disable --now apipact-agent 2>/dev/null || true
    $SUDO rm -f "$UNIT"
    $SUDO systemctl daemon-reload 2>/dev/null || true
  fi
  if [ "$os" = "darwin" ] && [ -f "$PLIST" ]; then
    $SUDO launchctl bootout system "$PLIST" 2>/dev/null || true
    $SUDO rm -f "$PLIST"
  fi
  for b in apipact-supervisor apipact-worker apipact-agentctl; do
    $SUDO rm -f "${PREFIX}/${b}"
  done
  if [ "$PURGE" = "1" ]; then
    $SUDO rm -rf "$CONFIG_DIR" "$STATE_DIR"
    echo "removed binaries, service, config, and state."
    echo "Remember to revoke this agent in the console (Settings -> Agents)."
  else
    $SUDO rm -rf "$STATE_DIR"
    echo "removed binaries and service."
    [ -f "$CONFIG" ] && echo "kept ${CONFIG} (enrollment keys) — re-run with --purge to remove it."
  fi
  exit 0
fi

[ -n "$TOKEN" ] && [ -z "$SERVER" ] && die "--token requires --server"
# Full setup is the default when a token is provided
[ -z "$WITH_SERVICE" ] && { [ -n "$TOKEN" ] && WITH_SERVICE=1 || WITH_SERVICE=0; }

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die "unsupported architecture: $arch" ;;
esac
plat="${os}-${arch}"

# --- resolve version --------------------------------------------------------
api="https://api.github.com/repos/${REPO}"
have curl || die "curl is required"
if [ -z "$VERSION" ]; then
  # /releases/latest excludes pre-releases; fall back to the newest release of any kind
  VERSION="$(curl -fsSL "${api}/releases/latest" 2>/dev/null | grep -m1 '"tag_name"' | cut -d '"' -f4 || true)"
  if [ -z "$VERSION" ]; then
    VERSION="$(curl -fsSL "${api}/releases?per_page=1" | grep -m1 '"tag_name"' | cut -d '"' -f4)"
  fi
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
$SUDO mkdir -p "$PREFIX"
for b in $bins; do
  $SUDO install -m 0755 "${tmp}/${b}" "${PREFIX}/${b}"
done
echo "installed: $bins"

# --- service (boot-persistent) ---------------------------------------------
SERVICE_READY=0
if [ "$WITH_SERVICE" = "1" ]; then
  $SUDO mkdir -p "$CONFIG_DIR" "$STATE_DIR"
  # The managed (self-updated) worker lives in the writable state dir; the
  # supervisor stays in ${PREFIX}. Seed the worker copy there.
  $SUDO install -m 0755 "${PREFIX}/apipact-worker" "${STATE_DIR}/apipact-worker"

  if [ "$os" = "linux" ]; then
    have systemctl || die "service setup requires systemd (re-run with --no-service)"
    echo "installing systemd service"
    $SUDO useradd --system --no-create-home --shell /usr/sbin/nologin apipact 2>/dev/null || true
    $SUDO chown -R apipact:apipact "$STATE_DIR"
    curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/deploy/systemd/apipact-agent.service" \
      | $SUDO tee "$UNIT" >/dev/null
    $SUDO systemctl daemon-reload
    SERVICE_READY=1
  else
    echo "installing launchd daemon"
    $SUDO tee "$PLIST" >/dev/null <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${PLIST_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${PREFIX}/apipact-supervisor</string>
    <string>--config</string><string>${CONFIG}</string>
    <string>--state</string><string>${STATE_DIR}/dedupe.json</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>APIPACT_WORKER_BIN</key><string>${STATE_DIR}/apipact-worker</string>
    <key>APIPACT_HEALTH_ADDR</key><string>127.0.0.1:9099</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/apipact-agent.log</string>
  <key>StandardErrorPath</key><string>/var/log/apipact-agent.log</string>
</dict>
</plist>
PLISTEOF
    SERVICE_READY=1
  fi
fi

# --- enroll -----------------------------------------------------------------
ENROLLED=0
if [ -n "$TOKEN" ]; then
  if [ -f "$CONFIG" ]; then
    echo "already enrolled (${CONFIG} exists) — skipping enrollment."
    echo "To re-enroll: uninstall with --purge first, or run agentctl enroll --force manually."
    ENROLLED=1
  else
    echo "enrolling against ${SERVER}"
    $SUDO mkdir -p "$CONFIG_DIR"
    if [ -n "$NAME" ]; then
      $SUDO "${PREFIX}/apipact-agentctl" enroll \
        --token "$TOKEN" --server "$SERVER" --config "$CONFIG" --name "$NAME" \
        || die "enrollment failed (is the token still valid? tokens are single-use and expire in 24h)"
    else
      $SUDO "${PREFIX}/apipact-agentctl" enroll \
        --token "$TOKEN" --server "$SERVER" --config "$CONFIG" \
        || die "enrollment failed (is the token still valid? tokens are single-use and expire in 24h)"
    fi
    if [ "$os" = "linux" ] && id apipact >/dev/null 2>&1; then
      $SUDO chown apipact:apipact "$CONFIG"
    fi
    $SUDO chmod 600 "$CONFIG"
    ENROLLED=1
  fi
fi

# --- start ------------------------------------------------------------------
if [ "$SERVICE_READY" = "1" ] && [ "$ENROLLED" = "1" ]; then
  echo "starting the agent"
  if [ "$os" = "linux" ]; then
    $SUDO systemctl enable --now apipact-agent
    echo
    echo "Done. The agent runs as a systemd service and starts at boot."
    echo "  status:    systemctl status apipact-agent"
    echo "  logs:      journalctl -u apipact-agent -f"
  else
    $SUDO launchctl bootout system "$PLIST" 2>/dev/null || true
    $SUDO launchctl bootstrap system "$PLIST"
    echo
    echo "Done. The agent runs as a launchd daemon and starts at boot."
    echo "  status:    sudo launchctl print system/${PLIST_LABEL} | head"
    echo "  logs:      tail -f /var/log/apipact-agent.log"
  fi
  echo "  uninstall: re-run this script with --uninstall [--purge]"
  echo
  echo "It should appear as Online in the console within a minute."
  exit 0
fi

# --- manual next steps (no token / no service) ------------------------------
cat <<EOF

Next steps:
  1. Enroll this agent with your cloud (writes ${CONFIG}, 0600):
       ${PREFIX}/apipact-agentctl enroll --token <TOKEN> --server <CLOUD_URL> \\
         --name <display-name> --config ${CONFIG}
  2. Run it:
$( [ "$SERVICE_READY" = "1" ] \
     && { [ "$os" = "linux" ] \
            && echo "       sudo systemctl enable --now apipact-agent" \
            || echo "       sudo launchctl bootstrap system ${PLIST}"; } \
     || echo "       ${PREFIX}/apipact-supervisor --config ${CONFIG}" )

  Tip: re-run with --token <TOKEN> --server <CLOUD_URL> to do all of this in one go.
  See https://github.com/${REPO}/blob/${VERSION}/docs/CONFIGURATION.md
EOF
