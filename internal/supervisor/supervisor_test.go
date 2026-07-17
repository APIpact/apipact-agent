package supervisor

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
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/APIpact/apipact-agent/internal/config"
	"github.com/APIpact/apipact-agent/internal/obs"
	"github.com/APIpact/apipact-agent/internal/update"
)

// stubSource is a minimal stand-in for the worker binary. Its version and
// health behaviour are set at build time via -ldflags, letting us drive the
// supervisor's real process-management + update path end to end.
const stubSource = `package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

var version = "v0.0.0"
var mode = "ok" // ok | unhealthy | badselfcheck

func main() {
	healthAddr := flag.String("health-addr", "", "")
	_ = flag.String("config", "", "")
	_ = flag.String("state", "", "")
	selfcheck := flag.Bool("selfcheck", false, "")
	ver := flag.Bool("version", false, "")
	flag.Parse()

	if *ver {
		fmt.Println("apipact-worker", version, "(stub)")
		return
	}
	if *selfcheck {
		if mode == "badselfcheck" {
			os.Exit(1)
		}
		fmt.Println("selfcheck ok")
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if mode == "unhealthy" {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	})
	srv := &http.Server{Addr: *healthAddr, Handler: mux}
	go srv.ListenAndServe()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	<-ctx.Done()
}
`

func buildStub(t *testing.T, dir, name, version, mode string) string {
	t.Helper()
	src := filepath.Join(dir, name+".go")
	if err := os.WriteFile(src, []byte(stubSource), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, name)
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	ld := "-X main.version=" + version + " -X main.mode=" + mode
	cmd := exec.Command(goBin, "build", "-ldflags", ld, "-o", out, src)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GO111MODULE=off")
	if o, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build stub %s: %v\n%s", name, err, o)
	}
	return out
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o755); err != nil {
		t.Fatal(err)
	}
}

// serveRelease stands up an HTTP server exposing a signed manifest for the
// given worker binary and the binary itself.
func serveRelease(t *testing.T, workerBinPath, version string, priv ed25519.PrivateKey) (manifestURL string, close func()) {
	t.Helper()
	bin, err := os.ReadFile(workerBinPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bin)

	mux := http.NewServeMux()
	mux.HandleFunc("/worker", func(w http.ResponseWriter, r *http.Request) { w.Write(bin) })
	var base string
	mux.HandleFunc("/manifest", func(w http.ResponseWriter, r *http.Request) {
		m := update.Manifest{
			Version: version, Channel: "stable", OS: runtime.GOOS, Arch: runtime.GOARCH,
			Worker: update.WorkerArtifact{URL: base + "/worker", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(bin))},
		}
		payload, _ := json.Marshal(m)
		sig := ed25519.Sign(priv, payload)
		sm := update.SignedManifest{
			Payload:   base64.StdEncoding.EncodeToString(payload),
			Signature: base64.StdEncoding.EncodeToString(sig),
		}
		json.NewEncoder(w).Encode(sm)
	})
	srv := httptest.NewServer(mux)
	base = srv.URL
	return srv.URL + "/manifest", srv.Close
}

func newTestSupervisor(t *testing.T, dir, workerBin, manifestURL, healthAddr string, releasePub ed25519.PublicKey) *Supervisor {
	cfgPath := filepath.Join(dir, "agent.json")
	if err := os.WriteFile(cfgPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Update.Mode = "binary"
	cfg.Update.ManifestURL = manifestURL
	cfg.Update.ReleaseSignerB64 = base64.StdEncoding.EncodeToString(releasePub)
	return New(cfg, Options{
		ConfigPath: cfgPath,
		StatePath:  filepath.Join(dir, "dedupe.json"),
		WorkerBin:  workerBin,
		HealthAddr: healthAddr,
		Logger:     obs.New(obs.LevelFromEnv(), "supervisor-test"),
	})
}

// TestSelfUpdateSuccess drives the full happy path: a running v1 worker is
// swapped for a signed, checksum-verified v2 that passes selfcheck and becomes
// healthy.
func TestSelfUpdateSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("builds stub binaries; skipped in -short")
	}
	dir := t.TempDir()
	releasePub, releasePriv, _ := ed25519.GenerateKey(rand.Reader)

	workerBin := filepath.Join(dir, "apipact-worker")
	copyFile(t, buildStub(t, dir, "v1", "v1.0.0", "ok"), workerBin)
	v2 := buildStub(t, dir, "v2", "v2.0.0", "ok")
	manifestURL, closeSrv := serveRelease(t, v2, "v2.0.0", releasePriv)
	defer closeSrv()

	sup := newTestSupervisor(t, dir, workerBin, manifestURL, "127.0.0.1:19099", releasePub)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if err := sup.startChild(ctx); err != nil {
		t.Fatalf("start v1: %v", err)
	}
	defer sup.stopChild(syscall.SIGTERM, 5*time.Second)

	sup.checkAndApply(ctx, releasePub)

	if got := currentWorkerVersion(ctx, workerBin); got != "v2.0.0" {
		t.Fatalf("expected worker upgraded to v2.0.0, got %s", got)
	}
	if !update.HasRollback(workerBin) {
		t.Error("expected a .prev rollback copy to be kept")
	}
}

// TestSelfUpdateRollback drives a bad update: v2 installs but is unhealthy, so
// the supervisor must roll back to v1.
func TestSelfUpdateRollback(t *testing.T) {
	if testing.Short() {
		t.Skip("builds stub binaries; skipped in -short")
	}
	dir := t.TempDir()
	releasePub, releasePriv, _ := ed25519.GenerateKey(rand.Reader)

	workerBin := filepath.Join(dir, "apipact-worker")
	copyFile(t, buildStub(t, dir, "v1", "v1.0.0", "ok"), workerBin)
	badV2 := buildStub(t, dir, "v2bad", "v2.0.0", "unhealthy")
	manifestURL, closeSrv := serveRelease(t, badV2, "v2.0.0", releasePriv)
	defer closeSrv()

	sup := newTestSupervisor(t, dir, workerBin, manifestURL, "127.0.0.1:19100", releasePub)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if err := sup.startChild(ctx); err != nil {
		t.Fatalf("start v1: %v", err)
	}
	defer sup.stopChild(syscall.SIGTERM, 5*time.Second)

	sup.checkAndApply(ctx, releasePub)

	// After a failed health check the supervisor rolls back to v1.
	if got := currentWorkerVersion(ctx, workerBin); got != "v1.0.0" {
		t.Fatalf("expected rollback to v1.0.0, got %s", got)
	}
}
