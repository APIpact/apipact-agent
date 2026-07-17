// Package worker assembles the executor: it opens sealed jobs, runs their
// requests through the HTTP engine under a bounded pool, and returns sealed
// results. It also answers control pings and exposes a loopback health endpoint
// the supervisor uses to gate an update.
package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	pushflo "github.com/PushFlo/pushflo-go"
	"github.com/PushFlo/pushflo-go/envelope"

	"github.com/APIpact/apipact-agent/internal/config"
	"github.com/APIpact/apipact-agent/internal/executor"
	"github.com/APIpact/apipact-agent/internal/protocol"
	"github.com/APIpact/apipact-agent/internal/reporter"
	"github.com/APIpact/apipact-agent/internal/secure"
	"github.com/APIpact/apipact-agent/internal/store"
	"github.com/APIpact/apipact-agent/internal/transport"
	"github.com/APIpact/apipact-agent/internal/version"
)

// drainTimeout bounds how long in-flight jobs may finish after a shutdown
// signal before the worker exits anyway.
const drainTimeout = 30 * time.Second

// Worker is a running executor instance.
type Worker struct {
	cfg    *config.Config
	suite  *secure.Suite
	engine *executor.Engine
	rep    *reporter.Reporter
	dedupe *store.Dedupe
	pub    *pushflo.Publisher // for control acks (may be nil)
	log    *slog.Logger

	sem      chan struct{}
	wg       sync.WaitGroup
	inflight atomic.Int64
	draining atomic.Bool
	tr       atomic.Pointer[transport.Transport]
}

// Build constructs a Worker from config without connecting. It is the shared
// path for Run and SelfCheck.
func Build(cfg *config.Config, statePath string, log *slog.Logger) (*Worker, error) {
	replay := envelope.NewMemoryReplayCache(cfg.ReplayTTL())
	suite, err := secure.BuildSuite(cfg.Keys, cfg.ClockSkew(), replay)
	if err != nil {
		return nil, fmt.Errorf("build crypto suite: %w", err)
	}

	policy, err := cfg.EgressPolicy()
	if err != nil {
		return nil, err
	}
	engine := executor.New(policy, log)
	engine.DefaultMaxBody = cfg.Limits.MaxBodyBytes

	var pub *pushflo.Publisher
	if cfg.PushFlo.SecretKey != "" {
		pub, err = pushflo.NewPublisher(pushflo.PublisherOptions{
			SecretKey: cfg.PushFlo.SecretKey,
			BaseURL:   cfg.PushFlo.BaseURL,
		})
		if err != nil {
			return nil, fmt.Errorf("build publisher: %w", err)
		}
	}

	rep := reporter.New(reporter.Config{
		AgentID:          cfg.AgentID,
		DefaultTransport: cfg.Return.Transport,
		ResultsChannel:   protocol.ResultsChannel(cfg.AgentID),
		ResultURL:        cfg.Return.ResultURL,
		ResultToken:      cfg.Return.ResultToken,
		InlineMaxBytes:   cfg.Return.InlineMaxBytes,
		Sealer:           suite.ResultSealer,
		Publisher:        pub,
		Logger:           log,
	})

	dedupe, err := store.Open(statePath, cfg.ReplayTTL())
	if err != nil {
		return nil, fmt.Errorf("open dedupe store: %w", err)
	}

	maxConc := cfg.Limits.MaxConcurrency
	if maxConc <= 0 {
		maxConc = 8
	}

	return &Worker{
		cfg:    cfg,
		suite:  suite,
		engine: engine,
		rep:    rep,
		dedupe: dedupe,
		pub:    pub,
		log:    log,
		sem:    make(chan struct{}, maxConc),
	}, nil
}

// SelfCheck validates that a built worker's configuration and keys are usable.
// The supervisor runs `worker --selfcheck` on a freshly downloaded binary
// before promoting it.
func SelfCheck(cfg *config.Config, statePath string, log *slog.Logger) error {
	_, err := Build(cfg, statePath, log)
	return err
}

// Run connects the transport and processes jobs until ctx is cancelled, then
// drains in-flight work. healthAddr, when non-empty, starts a loopback health
// server (used by the supervisor).
func (w *Worker) Run(ctx context.Context, healthAddr string) error {
	if healthAddr != "" {
		if err := w.startHealthServer(ctx, healthAddr); err != nil {
			return fmt.Errorf("start health server: %w", err)
		}
	}

	tr, err := transport.Connect(ctx, transport.Options{
		AgentID:    w.cfg.AgentID,
		PublishKey: w.cfg.PushFlo.PublishKey,
		BaseURL:    w.cfg.PushFlo.BaseURL,
		Logger:     w.log,
	}, transport.Handlers{
		OnJob:     w.onJob,
		OnControl: w.onControl,
	})
	if err != nil {
		return fmt.Errorf("connect transport: %w", err)
	}
	w.tr.Store(tr)
	w.log.Info("executor running", "agentId", w.cfg.AgentID, "name", w.cfg.Name, "version", version.String())

	// Announce identity + current version immediately, then on an interval. This
	// is how the cloud tracks each agent's live build version — which changes
	// after an auto-update, when the new worker connects fresh and says hello.
	w.sendHeartbeat(protocol.AckHello, "")
	go w.heartbeatLoop(ctx)

	<-ctx.Done()
	w.log.Info("shutdown signal; draining", "inFlight", w.inflight.Load())
	w.draining.Store(true)
	tr.Close() // stop accepting new messages

	done := make(chan struct{})
	go func() { w.wg.Wait(); close(done) }()
	select {
	case <-done:
		w.log.Info("drain complete")
	case <-time.After(drainTimeout):
		w.log.Warn("drain timeout; exiting with jobs still in flight", "inFlight", w.inflight.Load())
	}
	return nil
}

// onJob handles a raw jobs-channel message: parse, verify+decrypt, validate,
// dedupe, then execute under the pool.
func (w *Worker) onJob(m pushflo.Message) {
	if w.draining.Load() {
		// Do not accept new work while draining; at-least-once delivery means
		// the cloud can redeliver to us or another agent.
		return
	}

	env, err := envelope.Parse(m.Content)
	if err != nil {
		w.log.Warn("jobs message is not an envelope", "err", err)
		return
	}
	var job protocol.Job
	if err := w.suite.Opener.OpenJSON(env, &job); err != nil {
		// Forgeries, replays, expired, or wrong-recipient messages land here.
		w.log.Warn("rejected job", "err", err, "mid", env.MessageID)
		return
	}

	if job.AgentID != "" && job.AgentID != w.cfg.AgentID {
		w.log.Warn("job addressed to another agent; ignoring", "jobId", job.JobID, "target", job.AgentID)
		return
	}
	if job.Deadline != nil && time.Now().After(*job.Deadline) {
		w.log.Warn("job past deadline; skipping", "jobId", job.JobID, "deadline", job.Deadline)
		return
	}

	seen, err := w.dedupe.SeenOrRecord(job.JobID)
	if err != nil {
		w.log.Error("dedupe store error", "jobId", job.JobID, "err", err)
		return
	}
	if seen {
		w.log.Info("duplicate job suppressed", "jobId", job.JobID)
		return
	}

	w.wg.Add(1)
	w.inflight.Add(1)
	go func() {
		defer w.wg.Done()
		defer w.inflight.Add(-1)
		w.runJob(job)
	}()
}

// runJob executes a job's requests and reports the sealed result.
func (w *Worker) runJob(job protocol.Job) {
	ctx := context.Background()
	started := time.Now()

	responses := w.execRequests(ctx, job)

	result := protocol.Result{
		JobID:         job.JobID,
		AgentID:       w.cfg.AgentID,
		Context:       job.Context,
		AgentVersion:  version.Version,
		WorkerVersion: version.Version,
		StartedAt:     started,
		FinishedAt:    time.Now(),
		Responses:     responses,
	}

	if err := w.rep.Report(ctx, result, job.Return); err != nil {
		w.log.Error("report result failed", "jobId", job.JobID, "err", err)
		return
	}
	w.log.Info("job complete", "jobId", job.JobID, "requests", len(responses), "ms", time.Since(started).Milliseconds())
}

// execRequests runs a job's requests, sequentially by default or with bounded
// concurrency when Execution.MaxConcurrency > 1. Each request also passes the
// global pool semaphore so a burst cannot exhaust connections.
func (w *Worker) execRequests(ctx context.Context, job protocol.Job) []protocol.ResponseResult {
	n := len(job.Requests)
	out := make([]protocol.ResponseResult, n)

	maxConc := job.Execution.MaxConcurrency
	if maxConc <= 1 {
		for i, spec := range job.Requests {
			out[i] = w.execOne(ctx, spec)
			if job.Execution.StopOnError && out[i].Error != nil {
				w.log.Info("stopOnError: aborting remaining requests", "jobId", job.JobID, "at", i)
				// Leave the rest zero-valued; mark them skipped.
				for j := i + 1; j < n; j++ {
					out[j] = protocol.ResponseResult{
						RequestID: job.Requests[j].ID,
						Error:     &protocol.ExecError{Kind: protocol.ErrKindInvalid, Message: "skipped after earlier failure"},
					}
				}
				break
			}
		}
		return out
	}

	jobSem := make(chan struct{}, maxConc)
	var wg sync.WaitGroup
	for i, spec := range job.Requests {
		wg.Add(1)
		go func(i int, spec protocol.RequestSpec) {
			defer wg.Done()
			jobSem <- struct{}{}
			defer func() { <-jobSem }()
			out[i] = w.execOne(ctx, spec)
		}(i, spec)
	}
	wg.Wait()
	return out
}

// execOne runs a single request under the global pool semaphore.
func (w *Worker) execOne(ctx context.Context, spec protocol.RequestSpec) protocol.ResponseResult {
	w.sem <- struct{}{}
	defer func() { <-w.sem }()
	return w.engine.Execute(ctx, spec)
}

// onControl handles control-channel messages (ping -> ack, and logs the rest;
// update/rotate are actioned by the supervisor/agentctl in v1).
func (w *Worker) onControl(m pushflo.Message) {
	env, err := envelope.Parse(m.Content)
	if err != nil {
		w.log.Warn("control message is not an envelope", "err", err)
		return
	}
	// The relay echoes our own heartbeat acks back on this channel; they are
	// signed with our key, not a cloud signer — ignore them silently.
	if env.SignKeyID != "" && env.SignKeyID == w.cfg.Keys.SignKeyID {
		return
	}
	var ctl protocol.ControlMessage
	if err := w.suite.Opener.OpenJSON(env, &ctl); err != nil {
		w.log.Warn("rejected control message", "err", err)
		return
	}
	switch ctl.Type {
	case protocol.ControlPing:
		w.sendHeartbeat(protocol.AckPong, env.MessageID)
	default:
		w.log.Info("control message received", "type", ctl.Type)
	}
}

// heartbeatLoop periodically re-announces the agent's liveness and current build
// version until ctx is cancelled. Disabled when HeartbeatSec <= 0.
func (w *Worker) heartbeatLoop(ctx context.Context) {
	interval := time.Duration(w.cfg.Limits.HeartbeatSec) * time.Second
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if !w.draining.Load() {
				w.sendHeartbeat(protocol.AckHeartbeat, "")
			}
		}
	}
}

// sendHeartbeat publishes a sealed Ack carrying the agent's identity (id, name,
// labels) and its live build version over the control channel. This is the
// authoritative version-exchange the cloud tracks, and it reflects the running
// binary — so after an auto-update the reported version changes automatically.
func (w *Worker) sendHeartbeat(kind, inReplyTo string) {
	if w.pub == nil {
		// No publish key (e.g. HTTP-only return): version still travels in every
		// Result. Nothing to send over the channel.
		return
	}
	ack := protocol.Ack{
		Kind:          kind,
		AgentID:       w.cfg.AgentID,
		Name:          w.cfg.Name,
		Labels:        w.cfg.Labels,
		AgentVersion:  version.Version,
		WorkerVersion: version.Version,
		SentAt:        time.Now(),
		InFlight:      int(w.inflight.Load()),
		InReplyTo:     inReplyTo,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := w.pub.PublishSealed(ctx, protocol.ControlChannel(w.cfg.AgentID), w.suite.ResultSealer, ack,
		envelope.Meta{ContentType: protocol.ContentTypeAck}, pushflo.WithEventType(protocol.EventAck))
	if err != nil {
		w.log.Warn("send heartbeat failed", "kind", kind, "err", err)
	}
}

// startHealthServer exposes /healthz and /readyz on a loopback address.
func (w *Worker) startHealthServer(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(rw http.ResponseWriter, _ *http.Request) {
		writeJSON(rw, http.StatusOK, map[string]any{
			"status":   "ok",
			"agentId":  w.cfg.AgentID,
			"version":  version.Version,
			"inFlight": w.inflight.Load(),
			"draining": w.draining.Load(),
		})
	})
	mux.HandleFunc("/readyz", func(rw http.ResponseWriter, _ *http.Request) {
		tr := w.tr.Load()
		ready := tr != nil && tr.Connected() && !w.draining.Load()
		code := http.StatusOK
		if !ready {
			code = http.StatusServiceUnavailable
		}
		writeJSON(rw, code, map[string]any{"ready": ready})
	})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			w.log.Warn("health server stopped", "err", err)
		}
	}()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	w.log.Info("health server listening", "addr", ln.Addr().String())
	return nil
}

func writeJSON(rw http.ResponseWriter, code int, v any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(code)
	_ = json.NewEncoder(rw).Encode(v)
}
