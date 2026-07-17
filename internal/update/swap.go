package update

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

// prevSuffix is appended to keep the previous worker binary for rollback.
const prevSuffix = ".prev"

// StageWorker downloads and verifies the manifest's worker into a temp file
// next to dest (same filesystem, so the later rename is atomic) and returns the
// temp path. The caller is responsible for promoting or removing it.
func StageWorker(ctx context.Context, hc *http.Client, m *Manifest, dest string) (string, error) {
	dir := filepath.Dir(dest)
	tmp, err := os.CreateTemp(dir, ".worker-new-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	if _, err := DownloadAndVerify(ctx, hc, m, tmp); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return "", err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return "", err
	}
	return tmpName, nil
}

// Promote atomically swaps staged into dest, preserving the current dest as
// dest.prev for rollback.
func Promote(staged, dest string) error {
	if _, err := os.Stat(dest); err == nil {
		if err := os.Rename(dest, dest+prevSuffix); err != nil {
			return fmt.Errorf("save previous worker: %w", err)
		}
	}
	if err := os.Rename(staged, dest); err != nil {
		// Best-effort restore of the previous binary.
		_ = os.Rename(dest+prevSuffix, dest)
		return fmt.Errorf("install new worker: %w", err)
	}
	return nil
}

// Rollback restores the previous worker binary saved by Promote.
func Rollback(dest string) error {
	prev := dest + prevSuffix
	if _, err := os.Stat(prev); err != nil {
		return fmt.Errorf("no previous worker to roll back to: %w", err)
	}
	return os.Rename(prev, dest)
}

// HasRollback reports whether a previous worker binary is available.
func HasRollback(dest string) bool {
	_, err := os.Stat(dest + prevSuffix)
	return err == nil
}

// DecodeReleaseKey decodes a base64 Ed25519 release signing public key.
func DecodeReleaseKey(b64 string) (ed25519.PublicKey, error) {
	if b64 == "" {
		return nil, fmt.Errorf("empty release signing key")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode release key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("release key wrong size: got %d, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}
