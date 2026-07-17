package update

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func signedManifestServer(t *testing.T, m Manifest, key ed25519.PrivateKey) *httptest.Server {
	t.Helper()
	payload, _ := json.Marshal(m)
	sig := ed25519.Sign(key, payload)
	sm := SignedManifest{
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
	body, _ := json.Marshal(sm)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
}

func TestFetchManifestValid(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := Manifest{Version: "v1.2.3", Channel: "stable", Worker: WorkerArtifact{URL: "http://x/w", SHA256: "abc"}}
	srv := signedManifestServer(t, m, priv)
	defer srv.Close()

	got, err := FetchManifest(context.Background(), srv.Client(), srv.URL, pub)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != "v1.2.3" {
		t.Errorf("version wrong: %s", got.Version)
	}
}

func TestFetchManifestWrongKeyRejected(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	m := Manifest{Version: "v1.0.0", Worker: WorkerArtifact{URL: "http://x/w", SHA256: "abc"}}
	srv := signedManifestServer(t, m, priv)
	defer srv.Close()

	if _, err := FetchManifest(context.Background(), srv.Client(), srv.URL, otherPub); err == nil {
		t.Fatal("expected signature verification failure")
	}
}

func TestDownloadAndVerifyChecksum(t *testing.T) {
	payload := []byte("#!/bin/true\n\x00\x01binary")
	sum := sha256.Sum256(payload)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(payload) }))
	defer srv.Close()

	// Correct checksum succeeds.
	m := &Manifest{Worker: WorkerArtifact{URL: srv.URL, SHA256: hex.EncodeToString(sum[:])}}
	var buf writeCounter
	if _, err := DownloadAndVerify(context.Background(), srv.Client(), m, &buf); err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	// Wrong checksum fails.
	m.Worker.SHA256 = "deadbeef"
	if _, err := DownloadAndVerify(context.Background(), srv.Client(), m, &writeCounter{}); err == nil {
		t.Fatal("expected checksum mismatch")
	}
}

func TestShouldUpdate(t *testing.T) {
	cases := []struct {
		current, pinned, manifest string
		want                      bool
	}{
		{"v1.0.0", "", "v1.0.1", true},
		{"v1.0.1", "", "v1.0.0", false},
		{"v1.0.0", "", "v1.0.0", false},
		{"v1.2.0", "", "v1.10.0", true},       // numeric, not lexical
		{"v1.0.0", "v1.5.0", "v1.2.0", false}, // pinned: only v1.5.0
		{"v1.0.0", "v1.5.0", "v1.5.0", true},
		{"dev", "", "v0.1.0", true},
	}
	for _, tc := range cases {
		m := &Manifest{Version: tc.manifest}
		if got := ShouldUpdate(tc.current, tc.pinned, m); got != tc.want {
			t.Errorf("ShouldUpdate(cur=%s pin=%s man=%s)=%v want %v", tc.current, tc.pinned, tc.manifest, got, tc.want)
		}
	}
}

func TestPromoteAndRollback(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "worker")
	if err := os.WriteFile(dest, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(dir, ".worker-new")
	if err := os.WriteFile(staged, []byte("NEW"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := Promote(staged, dest); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "NEW" {
		t.Errorf("expected NEW after promote, got %q", b)
	}
	if !HasRollback(dest) {
		t.Fatal("expected a rollback copy")
	}
	if err := Rollback(dest); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dest); string(b) != "OLD" {
		t.Errorf("expected OLD after rollback, got %q", b)
	}
}

// writeCounter is an io.Writer that discards but counts.
type writeCounter struct{ n int64 }

func (w *writeCounter) Write(p []byte) (int, error) { w.n += int64(len(p)); return len(p), nil }
