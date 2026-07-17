// Command worker is the APIPact executor process. It is normally launched and
// supervised by the supervisor, but can be run standalone for development.
//
// Usage:
//
//	worker [--config PATH] [--state PATH] [--health-addr ADDR]
//	worker --selfcheck [--config PATH]   # validate config+keys, exit 0/1
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
	"github.com/APIpact/apipact-agent/internal/version"
	"github.com/APIpact/apipact-agent/internal/worker"
)

func main() {
	var (
		configPath = flag.String("config", config.DefaultPath(), "path to agent config")
		statePath  = flag.String("state", "", "path to dedupe state file (default alongside config)")
		healthAddr = flag.String("health-addr", "", "loopback address for the health server (e.g. 127.0.0.1:9099)")
		selfcheck  = flag.Bool("selfcheck", false, "validate config and keys, then exit")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("apipact-worker", version.String())
		return
	}

	log := obs.New(obs.LevelFromEnv(), "worker")

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Error("load config", "path", *configPath, "err", err)
		os.Exit(1)
	}

	state := *statePath
	if state == "" {
		state = filepath.Join(filepath.Dir(*configPath), "dedupe.json")
	}

	if *selfcheck {
		if err := worker.SelfCheck(cfg, state, log); err != nil {
			log.Error("selfcheck failed", "err", err)
			os.Exit(1)
		}
		fmt.Println("selfcheck ok:", version.String())
		return
	}

	w, err := worker.Build(cfg, state, log)
	if err != nil {
		log.Error("build worker", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := w.Run(ctx, *healthAddr); err != nil {
		log.Error("worker exited with error", "err", err)
		os.Exit(1)
	}
}
