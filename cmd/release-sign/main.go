// Command release-sign produces a signed release manifest for the self-update
// channel. Given a worker binary and the release signing private key, it emits
// the SignedManifest JSON the supervisor fetches and verifies.
//
// Usage:
//
//	release-sign \
//	  --worker ./apipact-worker --url https://cdn/apipact/1.2.3/worker-linux-amd64 \
//	  --version v1.2.3 --channel stable --os linux --arch amd64 \
//	  --key "$RELEASE_SIGN_PRIVATE_B64" > manifest.json
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/APIpact/apipact-agent/internal/update"
)

func main() {
	var (
		workerPath = flag.String("worker", "", "path to the worker binary to hash")
		url        = flag.String("url", "", "public download URL for the worker binary")
		ver        = flag.String("version", "", "release version, e.g. v1.2.3")
		channel    = flag.String("channel", "stable", "release channel")
		goos       = flag.String("os", "", "target GOOS")
		arch       = flag.String("arch", "", "target GOARCH")
		releasedAt = flag.String("released-at", "", "RFC3339 release timestamp (optional)")
		keyB64     = flag.String("key", os.Getenv("RELEASE_SIGN_PRIVATE_B64"), "base64 Ed25519 private key (or RELEASE_SIGN_PRIVATE_B64)")
	)
	flag.Parse()

	if *workerPath == "" || *url == "" || *ver == "" || *keyB64 == "" {
		fmt.Fprintln(os.Stderr, "release-sign requires --worker, --url, --version, and --key")
		os.Exit(2)
	}

	data, err := os.ReadFile(*workerPath) // #nosec G304 -- operator-supplied build artifact
	if err != nil {
		fatal("read worker: %v", err)
	}
	sum := sha256.Sum256(data)

	m := update.Manifest{
		Version:    *ver,
		Channel:    *channel,
		OS:         *goos,
		Arch:       *arch,
		ReleasedAt: *releasedAt,
		Worker: update.WorkerArtifact{
			URL:    *url,
			SHA256: hex.EncodeToString(sum[:]),
			Size:   int64(len(data)),
		},
	}
	payload, err := json.Marshal(m)
	if err != nil {
		fatal("marshal manifest: %v", err)
	}

	privRaw, err := base64.StdEncoding.DecodeString(*keyB64)
	if err != nil {
		fatal("decode key: %v", err)
	}
	if len(privRaw) != ed25519.PrivateKeySize {
		fatal("release key must be a %d-byte ed25519 private key, got %d", ed25519.PrivateKeySize, len(privRaw))
	}
	sig := ed25519.Sign(ed25519.PrivateKey(privRaw), payload)

	out := update.SignedManifest{
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fatal("encode: %v", err)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
