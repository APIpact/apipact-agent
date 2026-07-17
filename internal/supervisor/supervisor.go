// Package supervisor is the tiny, rarely-changing bootstrapper. It owns the
// worker process lifecycle and, in binary mode, the self-update loop: poll a
// signed manifest, stage+verify a new worker, self-check it, atomically swap it
// in, restart, health-check, and roll back on failure. It contains no test
// logic — that lives entirely in the worker.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/APIpact/apipact-agent/internal/config"
	"github.com/APIpact/apipact-agent/internal/update"
)

// Options configures the supervisor.
type Options struct {
	ConfigPath string
	StatePath  string
	WorkerBin  string // path to the worker binary (managed/replaced in binary mode)
	HealthAddr string // loopback addr passed to the worker (e.g. 127.0.0.1:9099)
	Logger     *slog.Logger
}

// Supervisor manages one worker child.
type Supervisor struct {
	opts Options
	cfg  *config.Config
	log  *slog.Logger
	hc   *http.Client

	mu    sync.Mutex
	child *exec.Cmd
}

// New builds a Supervisor.
func New(cfg *config.Config, opts Options) *Supervisor {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.HealthAddr == "" {
		opts.HealthAddr = "127.0.0.1:9099"
	}
	return &Supervisor{
		opts: opts,
		cfg:  cfg,
		log:  opts.Logger,
		hc:   &http.Client{Timeout: 60 * time.Second},
	}
}

// Run starts the worker and supervises it until ctx is cancelled. In binary
// mode it also runs the update loop.
func (s *Supervisor) Run(ctx context.Context) error {
	if err := s.startChild(ctx); err != nil {
		return fmt.Errorf("start worker: %w", err)
	}

	var wg sync.WaitGroup
	if s.cfg.Update.Mode != "external" {
		wg.Add(1)
		go func() { defer wg.Done(); s.updateLoop(ctx) }()
	} else {
		s.log.Info("update mode external; self-update disabled (orchestrator manages image)")
	}

	// Supervise: if the child dies unexpectedly, restart it with backoff.
	wg.Add(1)
	go func() { defer wg.Done(); s.superviseLoop(ctx) }()

	<-ctx.Done()
	s.log.Info("supervisor shutting down; signalling worker")
	s.stopChild(syscall.SIGTERM, 35*time.Second)
	wg.Wait()
	return nil
}

// startChild launches the worker process.
func (s *Supervisor) startChild(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, s.opts.WorkerBin,
		"--config", s.opts.ConfigPath,
		"--state", s.opts.StatePath,
		"--health-addr", s.opts.HealthAddr,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// Do not let CommandContext kill the child abruptly; we manage SIGTERM/drain.
	cmd.Cancel = func() error { return nil }
	if err := cmd.Start(); err != nil {
		return err
	}
	s.mu.Lock()
	s.child = cmd
	s.mu.Unlock()
	s.log.Info("worker started", "pid", cmd.Process.Pid, "bin", s.opts.WorkerBin)
	return s.waitReady(ctx, 30*time.Second)
}

// superviseLoop restarts the child if it exits while ctx is still live.
func (s *Supervisor) superviseLoop(ctx context.Context) {
	backoff := time.Second
	for {
		s.mu.Lock()
		child := s.child
		s.mu.Unlock()
		if child == nil {
			return
		}
		err := child.Wait()
		if ctx.Err() != nil {
			return // shutting down
		}
		s.log.Warn("worker exited unexpectedly; restarting", "err", err, "backoff", backoff.String())
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
		if err := s.startChild(ctx); err != nil {
			s.log.Error("restart failed", "err", err)
			continue
		}
		backoff = time.Second
	}
}

// updateLoop polls the release manifest and applies eligible updates.
func (s *Supervisor) updateLoop(ctx context.Context) {
	if s.cfg.Update.ManifestURL == "" || s.cfg.Update.ReleaseSignerB64 == "" {
		s.log.Info("update loop disabled (no manifest URL or release key configured)")
		return
	}
	interval := 5 * time.Minute
	if s.cfg.Update.PollInterval != "" {
		if d, err := time.ParseDuration(s.cfg.Update.PollInterval); err == nil && d > 0 {
			interval = d
		}
	}
	releaseKey, err := update.DecodeReleaseKey(s.cfg.Update.ReleaseSignerB64)
	if err != nil {
		s.log.Error("invalid release signing key; update loop disabled", "err", err)
		return
	}

	t := time.NewTicker(interval)
	defer t.Stop()
	s.checkAndApply(ctx, releaseKey) // check once at startup
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.checkAndApply(ctx, releaseKey)
		}
	}
}

// checkAndApply performs one update cycle.
func (s *Supervisor) checkAndApply(ctx context.Context, releaseKey []byte) {
	m, err := update.FetchManifest(ctx, s.hc, s.cfg.Update.ManifestURL, releaseKey)
	if err != nil {
		s.log.Warn("manifest check failed", "err", err)
		return
	}
	if !update.ShouldUpdate(currentWorkerVersion(ctx, s.opts.WorkerBin), s.cfg.Update.PinnedVersion, m) {
		s.log.Debug("no update needed", "manifest", m.Version)
		return
	}
	s.log.Info("update available; staging", "version", m.Version)

	staged, err := update.StageWorker(ctx, s.hc, m, s.opts.WorkerBin)
	if err != nil {
		s.log.Error("stage worker failed", "err", err)
		return
	}
	defer os.Remove(staged) // no-op once promoted

	// Gate promotion on the new binary passing its own self-check.
	if err := s.selfCheck(ctx, staged); err != nil {
		s.log.Error("new worker failed selfcheck; not promoting", "err", err)
		return
	}

	// Swap: stop the running child, install the new binary, start it, health-check.
	s.stopChild(syscall.SIGTERM, 35*time.Second)
	if err := update.Promote(staged, s.opts.WorkerBin); err != nil {
		s.log.Error("promote failed; restarting previous worker", "err", err)
		_ = s.startChild(ctx)
		return
	}
	if err := s.startChild(ctx); err != nil || s.waitReady(ctx, 30*time.Second) != nil {
		s.log.Error("new worker unhealthy; rolling back", "err", err)
		s.stopChild(syscall.SIGTERM, 20*time.Second)
		if rbErr := update.Rollback(s.opts.WorkerBin); rbErr != nil {
			s.log.Error("rollback failed", "err", rbErr)
		}
		_ = s.startChild(ctx)
		return
	}
	s.log.Info("update applied successfully", "version", m.Version)
}

// selfCheck runs `<bin> --selfcheck` against the current config.
func (s *Supervisor) selfCheck(ctx context.Context, bin string) error {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, "--selfcheck", "--config", s.opts.ConfigPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(out))
	}
	return nil
}

// stopChild signals the child and waits up to timeout for it to drain.
func (s *Supervisor) stopChild(sig syscall.Signal, timeout time.Duration) {
	s.mu.Lock()
	child := s.child
	s.child = nil
	s.mu.Unlock()
	if child == nil || child.Process == nil {
		return
	}
	_ = child.Process.Signal(sig)
	done := make(chan struct{})
	go func() { _, _ = child.Process.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
		s.log.Warn("worker did not exit in time; killing", "pid", child.Process.Pid)
		_ = child.Process.Kill()
	}
}

// waitReady polls the worker's /readyz until it reports ready or times out.
func (s *Supervisor) waitReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	url := "http://" + s.opts.HealthAddr + "/readyz"
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := s.hc.Do(req)
		if err == nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<12)) //nolint:errcheck
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return errors.New("worker did not become ready in time")
}

// currentWorkerVersion asks the worker binary for its version string.
func currentWorkerVersion(ctx context.Context, bin string) string {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, bin, "--version").Output()
	if err != nil {
		return "unknown"
	}
	// Output form: "apipact-worker <version> (...)"
	fields := splitFields(string(out))
	if len(fields) >= 2 {
		return fields[1]
	}
	return "unknown"
}

func splitFields(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ' ' || r == '\n' || r == '\t' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
