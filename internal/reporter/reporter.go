// Package reporter sends sealed results back to the cloud. Two transports are
// supported and selectable per job (with an agent default): a sealed publish
// over the PushFlo results channel, and a sealed HTTP POST to a cloud result
// endpoint. Results are sealed+signed identically regardless of transport, so
// the relay and any HTTP intermediary only ever see ciphertext.
//
// The control channel is for control: a channel-bound result larger than the
// inline threshold is automatically diverted to the HTTP endpoint so multi-MB
// bodies never clog the WebSocket.
package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"time"

	pushflo "github.com/PushFlo/pushflo-go"
	"github.com/PushFlo/pushflo-go/envelope"

	"github.com/APIpact/apipact-agent/internal/protocol"
)

// DefaultInlineMaxBytes is the sealed-envelope size above which a channel-bound
// result is diverted to the HTTP endpoint.
const DefaultInlineMaxBytes = 200 * 1024

// Config configures a Reporter.
type Config struct {
	AgentID          string
	DefaultTransport string // protocol.ReturnChannel | protocol.ReturnHTTP
	ResultsChannel   string // default channel when a job does not name one
	ResultURL        string // default HTTP endpoint
	ResultToken      string // bearer token for the HTTP endpoint
	InlineMaxBytes   int
	Sealer           *envelope.Sealer
	Publisher        *pushflo.Publisher // may be nil if only HTTP is used
	HTTPClient       *http.Client       // optional
	Logger           *slog.Logger
	RetryAttempts    int
}

// Reporter delivers results.
type Reporter struct {
	cfg  Config
	http *http.Client
	log  *slog.Logger
}

// New builds a Reporter.
func New(cfg Config) *Reporter {
	if cfg.InlineMaxBytes <= 0 {
		cfg.InlineMaxBytes = DefaultInlineMaxBytes
	}
	if cfg.RetryAttempts <= 0 {
		cfg.RetryAttempts = 4
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Reporter{cfg: cfg, http: hc, log: log}
}

// Report seals result and delivers it according to spec (falling back to the
// agent defaults). It retries transient failures and, for channel delivery,
// diverts oversized results to HTTP.
func (r *Reporter) Report(ctx context.Context, result protocol.Result, spec protocol.ReturnSpec) error {
	transport := spec.Transport
	if transport == "" {
		transport = r.cfg.DefaultTransport
	}
	inlineMax := spec.InlineMaxBytes
	if inlineMax <= 0 {
		inlineMax = r.cfg.InlineMaxBytes
	}

	meta := envelope.Meta{
		MessageID:   result.JobID, // dedupe key on the cloud side
		ContentType: protocol.ContentTypeResult,
	}
	env, err := r.cfg.Sealer.SealJSON(result, meta)
	if err != nil {
		return fmt.Errorf("seal result: %w", err)
	}
	sealed, err := env.Marshal()
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	switch transport {
	case protocol.ReturnHTTP:
		url := firstNonEmpty(spec.URL, r.cfg.ResultURL)
		return r.postHTTP(ctx, url, result.JobID, sealed)

	case protocol.ReturnChannel, "":
		if len(sealed) > inlineMax {
			url := firstNonEmpty(spec.URL, r.cfg.ResultURL)
			if url != "" {
				r.log.Info("result exceeds inline threshold; diverting to HTTP",
					"jobId", result.JobID, "bytes", len(sealed), "threshold", inlineMax)
				return r.postHTTP(ctx, url, result.JobID, sealed)
			}
			r.log.Warn("oversized result and no HTTP endpoint configured; sending over channel anyway",
				"jobId", result.JobID, "bytes", len(sealed))
		}
		channel := firstNonEmpty(spec.Channel, r.cfg.ResultsChannel)
		return r.publishChannel(ctx, channel, result.JobID, sealed)

	default:
		return fmt.Errorf("unknown return transport %q", transport)
	}
}

// publishChannel sends a pre-sealed envelope over the results channel, with a
// fallback to HTTP if the channel path keeps failing.
func (r *Reporter) publishChannel(ctx context.Context, channel, jobID string, sealed []byte) error {
	if r.cfg.Publisher == nil {
		return fmt.Errorf("channel result requested but no publisher configured")
	}
	if channel == "" {
		return fmt.Errorf("no results channel configured")
	}
	// PublishRaw already retries transient HTTP errors internally; we add a
	// bounded outer retry for resilience across brief disconnects.
	var lastErr error
	for attempt := 0; attempt < r.cfg.RetryAttempts; attempt++ {
		if attempt > 0 {
			if err := sleep(ctx, backoff(attempt)); err != nil {
				return err
			}
		}
		_, err := r.cfg.Publisher.PublishRaw(ctx, channel, json.RawMessage(sealed),
			pushflo.WithEventType(protocol.EventResult))
		if err == nil {
			return nil
		}
		lastErr = err
		r.log.Warn("channel result publish failed", "jobId", jobID, "attempt", attempt+1, "err", err)
	}
	// Last resort: try the HTTP endpoint if we have one.
	if r.cfg.ResultURL != "" {
		r.log.Warn("falling back to HTTP result endpoint", "jobId", jobID)
		return r.postHTTP(ctx, r.cfg.ResultURL, jobID, sealed)
	}
	return fmt.Errorf("channel result publish failed after %d attempts: %w", r.cfg.RetryAttempts, lastErr)
}

// postHTTP POSTs the sealed envelope to the cloud result endpoint. Routing
// metadata (agent id, job id) travels in clear headers; the body is ciphertext.
func (r *Reporter) postHTTP(ctx context.Context, url, jobID string, sealed []byte) error {
	if url == "" {
		return fmt.Errorf("no result URL configured")
	}
	var lastErr error
	for attempt := 0; attempt < r.cfg.RetryAttempts; attempt++ {
		if attempt > 0 {
			if err := sleep(ctx, backoff(attempt)); err != nil {
				return err
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(sealed))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/apipact.envelope+json")
		req.Header.Set("X-APIPact-Agent", r.cfg.AgentID)
		req.Header.Set("X-APIPact-Job", jobID)
		if r.cfg.ResultToken != "" {
			req.Header.Set("Authorization", "Bearer "+r.cfg.ResultToken)
		}

		resp, err := r.http.Do(req)
		if err != nil {
			lastErr = err
			r.log.Warn("http result post failed", "jobId", jobID, "attempt", attempt+1, "err", err)
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16)) //nolint:errcheck
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("result endpoint returned %s", resp.Status)
		// 4xx (other than 429) is not worth retrying.
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			return lastErr
		}
		r.log.Warn("http result non-2xx", "jobId", jobID, "status", resp.StatusCode, "attempt", attempt+1)
	}
	return fmt.Errorf("http result post failed after %d attempts: %w", r.cfg.RetryAttempts, lastErr)
}

func backoff(attempt int) time.Duration {
	base := 250 * time.Millisecond * time.Duration(1<<uint(attempt-1))
	if base > 8*time.Second {
		base = 8 * time.Second
	}
	// #nosec G404 -- jitter only; not security-sensitive
	jitter := time.Duration(rand.Int63n(int64(base) / 2))
	return base/2 + jitter
}

func sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
