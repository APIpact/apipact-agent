package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/APIpact/apipact-agent/internal/protocol"
)

func validConfig() *Config {
	c := &Config{AgentID: "7f3a9c2b1d"}
	c.PushFlo.PublishKey = "pub_x"
	c.PushFlo.SecretKey = "sec_x"
	c.Return.Transport = protocol.ReturnChannel
	return c
}

func TestSaveLoadRoundTripAndPerms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "agent.json")
	if err := Save(path, validConfig()); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("expected 0600 perms, got %o", fi.Mode().Perm())
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.AgentID != "7f3a9c2b1d" {
		t.Errorf("agent id round-trip wrong: %s", got.AgentID)
	}
	if got.Limits.MaxConcurrency != 8 {
		t.Errorf("expected default MaxConcurrency 8, got %d", got.Limits.MaxConcurrency)
	}
}

func TestValidateRejectsBadAgentID(t *testing.T) {
	c := validConfig()
	c.AgentID = "Bad.ID"
	if err := c.Validate(); err == nil {
		t.Error("expected validation error for bad agent id")
	}
}

func TestValidateRequiresSecretForChannelReturn(t *testing.T) {
	c := validConfig()
	c.PushFlo.SecretKey = ""
	if err := c.Validate(); err == nil {
		t.Error("expected error: channel return needs a secret key")
	}
}

func TestEgressPolicyParsing(t *testing.T) {
	c := validConfig()
	c.Egress.Allow = []string{"10.0.0.0/8"}
	c.Egress.Block = []string{"10.6.6.6/32"}
	p, err := c.EgressPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Allow) != 1 || len(p.Block) != 1 {
		t.Errorf("expected 1 allow and 1 block net, got %d/%d", len(p.Allow), len(p.Block))
	}
}
