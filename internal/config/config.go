// Package config loads and persists the agent's post-enrollment configuration:
// its identity, PushFlo keys, sealed-envelope key material, egress policy,
// result-return defaults, and update-channel settings. The file holds private
// keys, so it is written atomically with 0600 permissions.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/APIpact/apipact-agent/internal/executor"
	"github.com/APIpact/apipact-agent/internal/protocol"
	"github.com/APIpact/apipact-agent/internal/secure"
)

// Config is the complete agent configuration.
type Config struct {
	AgentID      string            `json:"agentId"`          // unique machine id (assigned at enrollment); drives channel names
	Name         string            `json:"name,omitempty"`   // human-friendly display name to differentiate agents
	Labels       map[string]string `json:"labels,omitempty"` // operator tags (env, region, datacenter, ...)
	CloudBaseURL string            `json:"cloudBaseUrl"`     // control-plane REST base (enroll, rotate, results)
	PushFlo      PushFlo           `json:"pushflo"`

	Keys   secure.KeyMaterial `json:"keys"`
	Egress Egress             `json:"egress"`
	Return Return             `json:"return"`
	Update Update             `json:"update"`
	Limits Limits             `json:"limits"`
}

// PushFlo holds the relay credentials.
type PushFlo struct {
	BaseURL    string `json:"baseUrl,omitempty"` // default https://api.pushflo.dev
	PublishKey string `json:"publishKey"`        // pub_... — subscribe to jobs/control
	SecretKey  string `json:"secretKey"`         // sec_... — publish results (transport=channel)
}

// Egress is the persisted egress policy. CIDRs are strings so the file stays
// human-readable; they are parsed into executor.EgressPolicy on load.
type Egress struct {
	AllowPrivate bool     `json:"allowPrivate"`
	Allow        []string `json:"allow,omitempty"` // extra CIDRs permitted
	Block        []string `json:"block,omitempty"` // extra CIDRs denied
}

// Return holds the agent's default result-return path (a job may override it).
type Return struct {
	Transport      string `json:"transport,omitempty"` // channel|http
	ResultURL      string `json:"resultUrl,omitempty"` // for transport=http
	ResultToken    string `json:"resultToken,omitempty"`
	InlineMaxBytes int    `json:"inlineMaxBytes,omitempty"` // channel results above this switch to HTTP
}

// Update holds the self-update settings the supervisor uses.
type Update struct {
	Mode             string `json:"mode,omitempty"`    // binary|external (default binary)
	Channel          string `json:"channel,omitempty"` // stable|beta|... (release channel)
	ManifestURL      string `json:"manifestUrl,omitempty"`
	ReleaseSignerB64 string `json:"releaseSigner,omitempty"` // Ed25519 public key that signs manifests
	PinnedVersion    string `json:"pinnedVersion,omitempty"` // if set, do not update past this
	PollInterval     string `json:"pollInterval,omitempty"`  // e.g. "5m"
}

// Limits caps resource usage and sets crypto freshness windows.
type Limits struct {
	MaxConcurrency int   `json:"maxConcurrency,omitempty"` // in-flight requests, default 8
	MaxBodyBytes   int64 `json:"maxBodyBytes,omitempty"`   // default 1 MiB
	ClockSkewSec   int   `json:"clockSkewSec,omitempty"`   // envelope MaxClockSkew, default 120
	ReplayTTLSec   int   `json:"replayTtlSec,omitempty"`   // replay retention, default 600
	HeartbeatSec   int   `json:"heartbeatSec,omitempty"`   // version/liveness heartbeat interval, default 60 (0 disables)
}

// DefaultPath returns the config path, honoring APIPACT_CONFIG, else a per-user
// location under the OS config dir.
func DefaultPath() string {
	if p := os.Getenv("APIPACT_CONFIG"); p != "" {
		return p
	}
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		dir = "/etc"
	}
	return filepath.Join(dir, "apipact", "agent.json")
}

// Load reads and validates the config at path.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- path is operator-controlled config location
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Save writes the config atomically with 0600 permissions.
func Save(path string, c *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".agent-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func (c *Config) applyDefaults() {
	if c.Limits.MaxConcurrency == 0 {
		c.Limits.MaxConcurrency = 8
	}
	if c.Limits.MaxBodyBytes == 0 {
		c.Limits.MaxBodyBytes = 1 << 20
	}
	if c.Limits.ClockSkewSec == 0 {
		c.Limits.ClockSkewSec = 120
	}
	if c.Limits.ReplayTTLSec == 0 {
		c.Limits.ReplayTTLSec = 600
	}
	if c.Limits.HeartbeatSec == 0 {
		c.Limits.HeartbeatSec = 60
	}
	if c.Update.Mode == "" {
		c.Update.Mode = "binary"
	}
	if c.Return.Transport == "" {
		c.Return.Transport = protocol.ReturnChannel
	}
}

// Validate checks the invariants the rest of the agent relies on.
func (c *Config) Validate() error {
	if err := protocol.CheckAgentID(c.AgentID); err != nil {
		return err
	}
	if c.PushFlo.PublishKey == "" {
		return fmt.Errorf("pushflo.publishKey is required")
	}
	if c.Return.Transport == protocol.ReturnChannel && c.PushFlo.SecretKey == "" {
		return fmt.Errorf("pushflo.secretKey is required for channel result return")
	}
	if c.Return.Transport == protocol.ReturnHTTP && c.Return.ResultURL == "" {
		return fmt.Errorf("return.resultUrl is required for http result return")
	}
	if _, err := c.EgressPolicy(); err != nil {
		return err
	}
	return nil
}

// EgressPolicy parses the persisted egress config into a runtime policy.
func (c *Config) EgressPolicy() (executor.EgressPolicy, error) {
	allow, err := executor.ParseCIDRs(joinList(c.Egress.Allow))
	if err != nil {
		return executor.EgressPolicy{}, fmt.Errorf("egress.allow: %w", err)
	}
	block, err := executor.ParseCIDRs(joinList(c.Egress.Block))
	if err != nil {
		return executor.EgressPolicy{}, fmt.Errorf("egress.block: %w", err)
	}
	return executor.EgressPolicy{AllowPrivate: c.Egress.AllowPrivate, Allow: allow, Block: block}, nil
}

// ClockSkew and ReplayTTL as durations.
func (c *Config) ClockSkew() time.Duration { return time.Duration(c.Limits.ClockSkewSec) * time.Second }
func (c *Config) ReplayTTL() time.Duration { return time.Duration(c.Limits.ReplayTTLSec) * time.Second }

func joinList(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}
