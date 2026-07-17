// Command supervisor is the APIPact agent entrypoint. It owns the worker
// process: it launches it, restarts it if it crashes, and (in binary update
// mode) keeps it up to date from the signed release channel.
//
// Usage:
//
//	supervisor [--config PATH] [--worker BIN] [--health-addr ADDR] [--state PATH]
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/APIpact/apipact-agent/internal/config"
	"github.com/APIpact/apipact-agent/internal/obs"
	"github.com/APIpact/apipact-agent/internal/supervisor"
	"github.com/APIpact/apipact-agent/internal/version"
)

func main() {
	var (
		configPath = flag.String("config", config.DefaultPath(), "path to agent config")
		workerBin  = flag.String("worker", defaultWorkerBin(), "path to the worker binary")
		healthAddr = flag.String("health-addr", envOr("APIPACT_HEALTH_ADDR", "127.0.0.1:9099"), "loopback health address for the worker")
		statePath  = flag.String("state", "", "path to dedupe state file (default alongside config)")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("apipact-supervisor", version.String())
		return
	}

	log := obs.New(obs.LevelFromEnv(), "supervisor")

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Error("load config", "path", *configPath, "err", err)
		os.Exit(1)
	}

	state := *statePath
	if state == "" {
		state = filepath.Join(filepath.Dir(*configPath), "dedupe.json")
	}

	sup := supervisor.New(cfg, supervisor.Options{
		ConfigPath: *configPath,
		StatePath:  state,
		WorkerBin:  *workerBin,
		HealthAddr: *healthAddr,
		Logger:     log,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info("supervisor starting", "version", version.String(), "worker", *workerBin, "updateMode", cfg.Update.Mode)
	if err := sup.Run(ctx); err != nil {
		log.Error("supervisor exited with error", "err", err)
		os.Exit(1)
	}
}

// defaultWorkerBin looks for the worker binary next to the supervisor.
func defaultWorkerBin() string {
	if v := os.Getenv("APIPACT_WORKER_BIN"); v != "" {
		return v
	}
	exe, err := os.Executable()
	if err != nil {
		return "apipact-worker"
	}
	return filepath.Join(filepath.Dir(exe), "apipact-worker")
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
