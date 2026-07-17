// Package update implements the supervisor's self-update: it polls a signed
// release manifest, downloads and verifies a new worker binary, and hands the
// verified path to the supervisor for an atomic swap.
//
// Trust chain: the manifest is Ed25519-signed by the release key the agent
// pinned at enrollment. The manifest names the worker's SHA-256, so a verified
// manifest transitively authenticates the binary. The auto-updater is a
// remote-code-execution channel by design, so nothing is executed until both
// the signature and the checksum verify.
package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Manifest describes the current release on a channel for one os/arch.
type Manifest struct {
	Version    string         `json:"version"`
	Channel    string         `json:"channel"`
	OS         string         `json:"os"`
	Arch       string         `json:"arch"`
	Worker     WorkerArtifact `json:"worker"`
	ReleasedAt string         `json:"releasedAt,omitempty"`
}

// WorkerArtifact points at a downloadable worker binary and its checksum.
type WorkerArtifact struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"` // hex
	Size   int64  `json:"size,omitempty"`
}

// SignedManifest is the wire wrapper: a base64 manifest payload plus a detached
// Ed25519 signature over the exact payload bytes.
type SignedManifest struct {
	Payload   string `json:"payload"`   // base64(std) of the manifest JSON
	Signature string `json:"signature"` // base64(std) Ed25519 signature over the decoded payload
}

// FetchManifest downloads and verifies the signed manifest at url against the
// release signing key.
func FetchManifest(ctx context.Context, hc *http.Client, url string, releaseKey ed25519.PublicKey) (*Manifest, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest fetch returned %s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	var sm SignedManifest
	if err := json.Unmarshal(raw, &sm); err != nil {
		return nil, fmt.Errorf("parse signed manifest: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(sm.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode manifest payload: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(sm.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode manifest signature: %w", err)
	}
	if len(releaseKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("no valid release signing key configured")
	}
	if !ed25519.Verify(releaseKey, payload, sig) {
		return nil, fmt.Errorf("manifest signature verification failed")
	}

	var m Manifest
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if m.Worker.URL == "" || m.Worker.SHA256 == "" {
		return nil, fmt.Errorf("manifest missing worker url/sha256")
	}
	return &m, nil
}

// DownloadAndVerify fetches the worker artifact to w, verifying its SHA-256
// against the manifest. It returns the number of bytes written.
func DownloadAndVerify(ctx context.Context, hc *http.Client, m *Manifest, w io.Writer) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.Worker.URL, nil)
	if err != nil {
		return 0, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, fmt.Errorf("download worker: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("worker download returned %s", resp.Status)
	}

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), resp.Body)
	if err != nil {
		return n, fmt.Errorf("stream worker: %w", err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, m.Worker.SHA256) {
		return n, fmt.Errorf("worker checksum mismatch: manifest=%s got=%s", m.Worker.SHA256, got)
	}
	if m.Worker.Size > 0 && n != m.Worker.Size {
		return n, fmt.Errorf("worker size mismatch: manifest=%d got=%d", m.Worker.Size, n)
	}
	return n, nil
}

// ShouldUpdate decides whether m supersedes the currently running version under
// the given pin. A pinned version updates only to that exact version.
func ShouldUpdate(current, pinned string, m *Manifest) bool {
	if pinned != "" {
		return m.Version == pinned && m.Version != current
	}
	return isNewer(m.Version, current)
}

// isNewer reports whether a is a newer semantic version than b. Non-semver
// strings compare by inequality (any difference is treated as an update).
func isNewer(a, b string) bool {
	pa, oka := parseSemver(a)
	pb, okb := parseSemver(b)
	if !oka || !okb {
		return a != b && a != "" && a != "dev"
	}
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func parseSemver(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i] // drop pre-release / build metadata
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}
