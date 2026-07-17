package worker

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	pushflo "github.com/PushFlo/pushflo-go"
	"github.com/PushFlo/pushflo-go/envelope"

	"github.com/APIpact/apipact-agent/internal/config"
	"github.com/APIpact/apipact-agent/internal/obs"
	"github.com/APIpact/apipact-agent/internal/protocol"
	"github.com/APIpact/apipact-agent/internal/secure"
)

// TestJobToSealedHTTPResult exercises the full worker path without a relay:
// a "cloud" seals a job, the worker opens it, executes an HTTP request against
// a local test server, and POSTs a sealed result to a mock cloud endpoint,
// which the test opens and verifies. It proves open -> execute -> seal -> return.
func TestJobToSealedHTTPResult(t *testing.T) {
	// --- key set: cloud <-> agent ---
	agentRecipient, _ := envelope.GenerateRecipientKeyPair()
	agentSigner, _ := envelope.GenerateSigningKeyPair()
	cloudRecipient, _ := envelope.GenerateRecipientKeyPair()
	cloudSigner, _ := envelope.GenerateSigningKeyPair()

	cloudJobSealer, _ := envelope.NewSealer(envelope.SealerConfig{
		RecipientPublic: agentRecipient.Public,
		SignerPrivate:   cloudSigner.Private,
		SignerKeyID:     "cloud-1",
	})
	cloudResultOpener, _ := envelope.NewOpener(envelope.OpenerConfig{
		RecipientPublic:  cloudRecipient.Public,
		RecipientPrivate: cloudRecipient.Private,
		Signers:          map[string]ed25519.PublicKey{"agent-1": agentSigner.Public},
		MaxClockSkew:     time.Minute,
		Replay:           envelope.NewMemoryReplayCache(time.Minute),
	})

	// --- the API under test ---
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Akamai-Test"); got != "edge-1" {
			t.Errorf("api did not receive custom header, got %q", got)
		}
		w.Header().Set("X-Server", "under-test")
		w.WriteHeader(201)
		io.WriteString(w, "created")
	}))
	defer api.Close()

	// --- mock cloud result endpoint (captures the sealed result) ---
	var mu sync.Mutex
	var got *protocol.Result
	done := make(chan struct{})
	resultSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		env, err := envelope.Parse(body)
		if err != nil {
			t.Errorf("result body is not an envelope: %v", err)
			w.WriteHeader(400)
			return
		}
		var res protocol.Result
		if err := cloudResultOpener.OpenJSON(env, &res); err != nil {
			t.Errorf("cloud could not open sealed result: %v", err)
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		got = &res
		mu.Unlock()
		w.WriteHeader(200)
		close(done)
	}))
	defer resultSrv.Close()

	// --- agent config using the HTTP return path ---
	cfg := &config.Config{
		AgentID:      "7f3a9c2b1d",
		CloudBaseURL: "https://cloud.example",
	}
	cfg.PushFlo.PublishKey = "pub_test"
	cfg.Keys = secure.KeyMaterial{
		RecipientPublicB64:  envelope.EncodePublicKey(agentRecipient.Public),
		RecipientPrivateB64: envelope.EncodePrivateKey(agentRecipient.Private),
		CloudSignersB64:     map[string]string{"cloud-1": envelope.EncodeSigningPublic(cloudSigner.Public)},
		CloudPublicB64:      envelope.EncodePublicKey(cloudRecipient.Public),
		SignPrivateB64:      envelope.EncodeSigningPrivate(agentSigner.Private),
		SignKeyID:           "agent-1",
	}
	cfg.Egress.AllowPrivate = true // the API under test is on 127.0.0.1
	cfg.Return.Transport = protocol.ReturnHTTP
	cfg.Return.ResultURL = resultSrv.URL
	// Run defaults + validation as the loader would.
	if raw, err := json.Marshal(cfg); err != nil {
		t.Fatal(err)
	} else {
		_ = raw
	}

	state := filepath.Join(t.TempDir(), "dedupe.json")
	w, err := buildForTest(t, cfg, state)
	if err != nil {
		t.Fatal(err)
	}

	// --- seal a job as the cloud would and hand it to the worker ---
	job := protocol.Job{
		JobID:   "job-42",
		AgentID: cfg.AgentID,
		Context: json.RawMessage(`{"suite":"smoke","run":7}`),
		Return:  protocol.ReturnSpec{Transport: protocol.ReturnHTTP, URL: resultSrv.URL},
		Requests: []protocol.RequestSpec{{
			ID:         "r1",
			Method:     "POST",
			URL:        api.URL + "/things",
			Headers:    []protocol.NameValue{{Name: "X-Akamai-Test", Value: "edge-1"}},
			BodyBase64: base64.StdEncoding.EncodeToString([]byte("payload")),
		}},
	}
	env, err := cloudJobSealer.SealJSON(job, envelope.Meta{MessageID: "job-42", ContentType: protocol.ContentTypeJob})
	if err != nil {
		t.Fatal(err)
	}
	sealed, _ := env.Marshal()

	w.onJob(pushflo.Message{Channel: protocol.JobsChannel(cfg.AgentID), Content: sealed})

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for sealed result")
	}

	mu.Lock()
	defer mu.Unlock()
	if got == nil {
		t.Fatal("no result captured")
	}
	if got.JobID != "job-42" {
		t.Errorf("jobId echo wrong: %s", got.JobID)
	}
	if string(got.Context) != `{"suite":"smoke","run":7}` {
		t.Errorf("context not echoed verbatim: %s", got.Context)
	}
	if len(got.Responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(got.Responses))
	}
	r := got.Responses[0]
	if r.Status != 201 {
		t.Errorf("expected status 201, got %d", r.Status)
	}
	if r.RequestID != "r1" {
		t.Errorf("requestId not preserved: %q", r.RequestID)
	}
	body, _ := base64.StdEncoding.DecodeString(r.BodyBase64)
	if string(body) != "created" {
		t.Errorf("response body wrong: %q", body)
	}
}

// TestDuplicateJobSuppressed verifies at-least-once idempotency: the same job
// delivered twice runs once.
func TestDuplicateJobSuppressed(t *testing.T) {
	agentRecipient, _ := envelope.GenerateRecipientKeyPair()
	agentSigner, _ := envelope.GenerateSigningKeyPair()
	cloudRecipient, _ := envelope.GenerateRecipientKeyPair()
	cloudSigner, _ := envelope.GenerateSigningKeyPair()
	cloudJobSealer, _ := envelope.NewSealer(envelope.SealerConfig{
		RecipientPublic: agentRecipient.Public, SignerPrivate: cloudSigner.Private, SignerKeyID: "cloud-1",
	})

	var calls int32
	var mu sync.Mutex
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer api.Close()
	resultSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(200)
	}))
	defer resultSrv.Close()

	cfg := &config.Config{AgentID: "abcd1234ef"}
	cfg.PushFlo.PublishKey = "pub_test"
	cfg.Keys = secure.KeyMaterial{
		RecipientPublicB64:  envelope.EncodePublicKey(agentRecipient.Public),
		RecipientPrivateB64: envelope.EncodePrivateKey(agentRecipient.Private),
		CloudSignersB64:     map[string]string{"cloud-1": envelope.EncodeSigningPublic(cloudSigner.Public)},
		CloudPublicB64:      envelope.EncodePublicKey(cloudRecipient.Public),
		SignPrivateB64:      envelope.EncodeSigningPrivate(agentSigner.Private),
		SignKeyID:           "agent-1",
	}
	cfg.Egress.AllowPrivate = true
	cfg.Return.Transport = protocol.ReturnHTTP
	cfg.Return.ResultURL = resultSrv.URL

	w, err := buildForTest(t, cfg, filepath.Join(t.TempDir(), "dedupe.json"))
	if err != nil {
		t.Fatal(err)
	}

	job := protocol.Job{JobID: "dup-1", AgentID: cfg.AgentID, Return: protocol.ReturnSpec{Transport: protocol.ReturnHTTP, URL: resultSrv.URL},
		Requests: []protocol.RequestSpec{{Method: "GET", URL: api.URL}}}
	env, _ := cloudJobSealer.SealJSON(job, envelope.Meta{MessageID: "dup-1", ContentType: protocol.ContentTypeJob})
	sealed, _ := env.Marshal()

	msg := pushflo.Message{Content: sealed}
	w.onJob(msg)
	w.onJob(msg) // duplicate: same jobId (and same envelope mid -> also replay-rejected)
	w.wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("expected the API to be called once, got %d", calls)
	}
}

// TestHeartbeatCarriesIdentityAndVersion verifies the version-exchange the cloud
// relies on: the agent's sealed heartbeat announces its id, name, labels, and
// live build version. Reported over a mock relay endpoint.
func TestHeartbeatCarriesIdentityAndVersion(t *testing.T) {
	agentRecipient, _ := envelope.GenerateRecipientKeyPair()
	agentSigner, _ := envelope.GenerateSigningKeyPair()
	cloudRecipient, _ := envelope.GenerateRecipientKeyPair()
	cloudSigner, _ := envelope.GenerateSigningKeyPair()

	cloudOpener, _ := envelope.NewOpener(envelope.OpenerConfig{
		RecipientPublic:  cloudRecipient.Public,
		RecipientPrivate: cloudRecipient.Private,
		Signers:          map[string]ed25519.PublicKey{"agent-1": agentSigner.Public},
		MaxClockSkew:     time.Minute,
		Replay:           envelope.NewMemoryReplayCache(time.Minute),
	})

	// Mock relay: capture the published (sealed) message content.
	var mu sync.Mutex
	var captured []byte
	done := make(chan struct{}, 1)
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Content json.RawMessage `json:"content"`
		}
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		json.Unmarshal(raw, &body)
		mu.Lock()
		captured = body.Content
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"success":true,"data":{}}`)
		select {
		case done <- struct{}{}:
		default:
		}
	}))
	defer relay.Close()

	cfg := &config.Config{AgentID: "7f3a9c2b1d", Name: "prod-eu-dc1", Labels: map[string]string{"env": "prod"}}
	cfg.PushFlo.PublishKey = "pub_test"
	cfg.PushFlo.SecretKey = "sec_test"
	cfg.PushFlo.BaseURL = relay.URL // publisher posts heartbeats here
	cfg.Keys = secure.KeyMaterial{
		RecipientPublicB64:  envelope.EncodePublicKey(agentRecipient.Public),
		RecipientPrivateB64: envelope.EncodePrivateKey(agentRecipient.Private),
		CloudSignersB64:     map[string]string{"cloud-1": envelope.EncodeSigningPublic(cloudSigner.Public)},
		CloudPublicB64:      envelope.EncodePublicKey(cloudRecipient.Public),
		SignPrivateB64:      envelope.EncodeSigningPrivate(agentSigner.Private),
		SignKeyID:           "agent-1",
	}
	cfg.Return.Transport = protocol.ReturnChannel

	w, err := buildForTest(t, cfg, filepath.Join(t.TempDir(), "dedupe.json"))
	if err != nil {
		t.Fatal(err)
	}

	w.sendHeartbeat(protocol.AckHello, "")

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("no heartbeat published")
	}

	mu.Lock()
	content := captured
	mu.Unlock()
	env, err := envelope.Parse(content)
	if err != nil {
		t.Fatalf("heartbeat is not an envelope: %v", err)
	}
	var ack protocol.Ack
	if err := cloudOpener.OpenJSON(env, &ack); err != nil {
		t.Fatalf("cloud could not open sealed heartbeat: %v", err)
	}
	if ack.Kind != protocol.AckHello {
		t.Errorf("kind: got %q want hello", ack.Kind)
	}
	if ack.AgentID != "7f3a9c2b1d" || ack.Name != "prod-eu-dc1" {
		t.Errorf("identity wrong: id=%q name=%q", ack.AgentID, ack.Name)
	}
	if ack.Labels["env"] != "prod" {
		t.Errorf("labels not carried: %v", ack.Labels)
	}
	if ack.AgentVersion == "" || ack.WorkerVersion == "" {
		t.Errorf("version not reported: agent=%q worker=%q", ack.AgentVersion, ack.WorkerVersion)
	}
}

// buildForTest builds a worker with defaults applied (mirroring config.Load).
func buildForTest(t *testing.T, cfg *config.Config, state string) (*Worker, error) {
	t.Helper()
	// Apply the same defaults + validation the loader would.
	if err := roundTripConfig(cfg); err != nil {
		return nil, err
	}
	return Build(cfg, state, obs.New(obs.LevelFromEnv(), "worker-test"))
}

// roundTripConfig applies config defaults/validation by marshalling and
// reloading through the config package's exported helpers.
func roundTripConfig(cfg *config.Config) error {
	// Config exposes Validate via Load; here we just ensure required fields and
	// defaults for the fields Build depends on.
	if cfg.Limits.MaxConcurrency == 0 {
		cfg.Limits.MaxConcurrency = 8
	}
	if cfg.Limits.MaxBodyBytes == 0 {
		cfg.Limits.MaxBodyBytes = 1 << 20
	}
	if cfg.Limits.ClockSkewSec == 0 {
		cfg.Limits.ClockSkewSec = 120
	}
	if cfg.Limits.ReplayTTLSec == 0 {
		cfg.Limits.ReplayTTLSec = 600
	}
	return cfg.Validate()
}
