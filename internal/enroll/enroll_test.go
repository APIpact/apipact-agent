package enroll

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PushFlo/pushflo-go/envelope"

	"github.com/APIpact/apipact-agent/internal/protocol"
)

// mockCloud returns an enroll endpoint that echoes the requested name and hands
// back a valid association response built from freshly generated cloud keys.
func mockCloud(t *testing.T) *httptest.Server {
	t.Helper()
	cloudRecipient, _ := envelope.GenerateRecipientKeyPair()
	cloudSigner, _ := envelope.GenerateSigningKeyPair()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != EnrollPath {
			w.WriteHeader(404)
			return
		}
		var req Request
		json.NewDecoder(r.Body).Decode(&req)
		if req.Token == "" || req.RecipientPublic == "" || req.SignPublic == "" {
			w.WriteHeader(400)
			return
		}
		resp := Response{AgentID: "7f3a9c2b1d", Name: req.Name}
		resp.PushFlo.PublishKey = "pub_x"
		resp.PushFlo.SecretKey = "sec_x"
		resp.CloudPublic = envelope.EncodePublicKey(cloudRecipient.Public)
		resp.CloudSigners = map[string]string{"cloud-1": envelope.EncodeSigningPublic(cloudSigner.Public)}
		json.NewEncoder(w).Encode(resp)
	}))
}

// TestEnrollNoPin is the regression test for the typed-nil Transport panic:
// enrollment without a TLS pin must succeed.
func TestEnrollNoPin(t *testing.T) {
	srv := mockCloud(t)
	defer srv.Close()

	cfg, err := Enroll(context.Background(), Options{
		CloudBaseURL: srv.URL,
		Token:        "tok",
		Name:         "prod-eu-dc1",
		Labels:       map[string]string{"env": "prod"},
	})
	if err != nil {
		t.Fatalf("enroll failed: %v", err)
	}
	if cfg.AgentID != "7f3a9c2b1d" {
		t.Errorf("agentId wrong: %s", cfg.AgentID)
	}
	if cfg.Name != "prod-eu-dc1" {
		t.Errorf("name not stored: %q", cfg.Name)
	}
	if cfg.Labels["env"] != "prod" {
		t.Errorf("labels not stored: %v", cfg.Labels)
	}
	// The assembled config must be valid and produce well-formed channels.
	if err := cfg.Validate(); err != nil {
		t.Errorf("assembled config invalid: %v", err)
	}
	if protocol.JobsChannel(cfg.AgentID) != "agent-7f3a9c2b1d-jobs" {
		t.Errorf("unexpected jobs channel")
	}
}

// TestEnrollRejectsBadResponse ensures a response missing association essentials
// is refused.
func TestEnrollRejectsBadResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Response{AgentID: "7f3a9c2b1d"}) // missing keys/pushflo
	}))
	defer srv.Close()

	if _, err := Enroll(context.Background(), Options{CloudBaseURL: srv.URL, Token: "t"}); err == nil {
		t.Fatal("expected enrollment to fail on incomplete response")
	}
}
