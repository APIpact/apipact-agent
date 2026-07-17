// Package enroll implements token-based online enrollment. The operator pastes
// a one-time token from the cloud console; the agent generates its key pairs
// locally (private halves never leave the host), registers its public keys over
// pinned TLS, and receives its identity, channel context, the cloud's keys, and
// its policy/update settings — which are written to the agent config.
package enroll

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/PushFlo/pushflo-go/envelope"

	"github.com/APIpact/apipact-agent/internal/config"
	"github.com/APIpact/apipact-agent/internal/protocol"
	"github.com/APIpact/apipact-agent/internal/secure"
	"github.com/APIpact/apipact-agent/internal/version"
)

// EnrollPath is the REST endpoint the agent POSTs to.
const EnrollPath = "/api/v1/agents/enroll"

// Request is the enrollment payload sent to the cloud. Only public keys leave
// the host.
type Request struct {
	Token           string            `json:"token"`
	Name            string            `json:"name,omitempty"`   // operator-chosen display name
	Labels          map[string]string `json:"labels,omitempty"` // operator tags (env, region, ...)
	RecipientPublic string            `json:"recipientPublic"`  // agent X25519 public (base64)
	SignPublic      string            `json:"signPublic"`       // agent Ed25519 public (base64)
	Hostname        string            `json:"hostname,omitempty"`
	OS              string            `json:"os,omitempty"`
	Arch            string            `json:"arch,omitempty"`
	AgentVersion    string            `json:"agentVersion,omitempty"`
}

// Response is what the cloud returns on success. It carries everything the
// agent needs to operate (but no agent private keys — those stay local).
type Response struct {
	AgentID string `json:"agentId"`
	// Name, when set, is the cloud's authoritative display name for the agent and
	// overrides any name the operator supplied at enrollment.
	Name string `json:"name,omitempty"`

	PushFlo struct {
		BaseURL    string `json:"baseUrl,omitempty"`
		PublishKey string `json:"publishKey"`
		SecretKey  string `json:"secretKey,omitempty"`
	} `json:"pushflo"`

	CloudPublic      string            `json:"cloudPublic"`  // cloud X25519 public (seal results to)
	CloudSigners     map[string]string `json:"cloudSigners"` // skid -> Ed25519 public (base64)
	RecipientKeyID   string            `json:"recipientKeyId,omitempty"`
	CloudRecipientID string            `json:"cloudRecipientId,omitempty"`

	Egress struct {
		AllowPrivate bool     `json:"allowPrivate"`
		Allow        []string `json:"allow,omitempty"`
		Block        []string `json:"block,omitempty"`
	} `json:"egress"`

	Return struct {
		Transport      string `json:"transport,omitempty"`
		ResultURL      string `json:"resultUrl,omitempty"`
		ResultToken    string `json:"resultToken,omitempty"`
		InlineMaxBytes int    `json:"inlineMaxBytes,omitempty"`
	} `json:"return"`

	Update struct {
		Mode             string `json:"mode,omitempty"`
		Channel          string `json:"channel,omitempty"`
		ManifestURL      string `json:"manifestUrl,omitempty"`
		ReleaseSignerB64 string `json:"releaseSigner,omitempty"`
		PollInterval     string `json:"pollInterval,omitempty"`
	} `json:"update"`

	Limits struct {
		MaxConcurrency int   `json:"maxConcurrency,omitempty"`
		MaxBodyBytes   int64 `json:"maxBodyBytes,omitempty"`
		ClockSkewSec   int   `json:"clockSkewSec,omitempty"`
		ReplayTTLSec   int   `json:"replayTtlSec,omitempty"`
	} `json:"limits"`
}

// Options configures an enrollment.
type Options struct {
	CloudBaseURL string
	Token        string
	Name         string            // operator-chosen display name (cloud may override)
	Labels       map[string]string // operator tags
	// PinSHA256, when set, requires the server's leaf certificate public-key
	// SPKI SHA-256 (base64) to match, defeating a MITM on first contact.
	PinSHA256  string
	HTTPClient *http.Client
}

// Enroll performs the enrollment round-trip and returns a fully-formed Config
// (with freshly generated local private keys) ready to persist.
func Enroll(ctx context.Context, opts Options) (*config.Config, error) {
	if opts.Token == "" {
		return nil, fmt.Errorf("enrollment token is required")
	}
	if opts.CloudBaseURL == "" {
		return nil, fmt.Errorf("cloud base URL is required")
	}

	recipient, signing, err := secure.GenerateAgentKeys()
	if err != nil {
		return nil, fmt.Errorf("generate keys: %w", err)
	}

	reqBody := Request{
		Token:           opts.Token,
		Name:            opts.Name,
		Labels:          opts.Labels,
		RecipientPublic: envelope.EncodePublicKey(recipient.Public),
		SignPublic:      envelope.EncodeSigningPublic(signing.Public),
		Hostname:        hostname(),
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
		AgentVersion:    version.Version,
	}
	raw, _ := json.Marshal(reqBody)

	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
		// Only override Transport when pinning; assigning a typed-nil
		// *http.Transport would create a non-nil interface wrapping a nil
		// pointer and panic on use.
		if tr := pinnedTransport(opts.PinSHA256); tr != nil {
			hc.Transport = tr
		}
	}

	url := strings.TrimRight(opts.CloudBaseURL, "/") + EnrollPath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := hc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("enroll request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("enroll rejected: %s: %s", resp.Status, string(body))
	}

	var er Response
	if err := json.Unmarshal(body, &er); err != nil {
		return nil, fmt.Errorf("parse enroll response: %w", err)
	}
	if err := protocol.CheckAgentID(er.AgentID); err != nil {
		return nil, fmt.Errorf("cloud returned %w", err)
	}
	if er.PushFlo.PublishKey == "" || er.CloudPublic == "" || len(er.CloudSigners) == 0 {
		return nil, fmt.Errorf("enroll response missing required fields (publishKey/cloudPublic/cloudSigners)")
	}

	cfg := buildConfig(opts.CloudBaseURL, opts, er, recipient, signing)
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("assembled config invalid: %w", err)
	}
	return cfg, nil
}

func buildConfig(cloudBaseURL string, opts Options, er Response, recipient *envelope.RecipientKeyPair, signing *envelope.SigningKeyPair) *config.Config {
	// The cloud's name wins if it assigned one; otherwise keep the operator's.
	name := opts.Name
	if er.Name != "" {
		name = er.Name
	}
	cfg := &config.Config{
		AgentID:      er.AgentID,
		Name:         name,
		Labels:       opts.Labels,
		CloudBaseURL: cloudBaseURL,
	}
	cfg.PushFlo.BaseURL = er.PushFlo.BaseURL
	cfg.PushFlo.PublishKey = er.PushFlo.PublishKey
	cfg.PushFlo.SecretKey = er.PushFlo.SecretKey

	cfg.Keys = secure.KeyMaterial{
		RecipientPublicB64:  envelope.EncodePublicKey(recipient.Public),
		RecipientPrivateB64: envelope.EncodePrivateKey(recipient.Private),
		CloudSignersB64:     er.CloudSigners,
		CloudPublicB64:      er.CloudPublic,
		SignPrivateB64:      envelope.EncodeSigningPrivate(signing.Private),
		SignKeyID:           agentSignKeyID(er.AgentID),
		RecipientKeyID:      er.RecipientKeyID,
		CloudRecipientID:    er.CloudRecipientID,
	}

	cfg.Egress.AllowPrivate = er.Egress.AllowPrivate
	cfg.Egress.Allow = er.Egress.Allow
	cfg.Egress.Block = er.Egress.Block

	cfg.Return.Transport = er.Return.Transport
	cfg.Return.ResultURL = er.Return.ResultURL
	cfg.Return.ResultToken = er.Return.ResultToken
	cfg.Return.InlineMaxBytes = er.Return.InlineMaxBytes

	cfg.Update.Mode = er.Update.Mode
	cfg.Update.Channel = er.Update.Channel
	cfg.Update.ManifestURL = er.Update.ManifestURL
	cfg.Update.ReleaseSignerB64 = er.Update.ReleaseSignerB64
	cfg.Update.PollInterval = er.Update.PollInterval

	cfg.Limits.MaxConcurrency = er.Limits.MaxConcurrency
	cfg.Limits.MaxBodyBytes = er.Limits.MaxBodyBytes
	cfg.Limits.ClockSkewSec = er.Limits.ClockSkewSec
	cfg.Limits.ReplayTTLSec = er.Limits.ReplayTTLSec
	return cfg
}

func agentSignKeyID(agentID string) string { return "agent-" + agentID + "-1" }

// pinnedTransport returns an http.Transport that pins the server's SPKI SHA-256
// when pin is non-empty; otherwise it uses standard verification.
func pinnedTransport(pin string) *http.Transport {
	if pin == "" {
		return nil
	}
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			VerifyConnection: func(cs tls.ConnectionState) error {
				for _, cert := range cs.PeerCertificates {
					sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
					if base64.StdEncoding.EncodeToString(sum[:]) == pin {
						return nil
					}
				}
				return fmt.Errorf("server certificate SPKI does not match pin")
			},
		},
	}
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}
