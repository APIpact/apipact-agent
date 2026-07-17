// Command agentctl is the operator CLI for the APIPact agent: enroll, generate
// keys, and inspect status.
//
// Usage:
//
//	agentctl enroll --token TOKEN --server https://cloud [--config PATH] [--pin SPKI]
//	agentctl keygen                                   # print a full key set (dev/offline)
//	agentctl status [--config PATH]
//	agentctl version
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/PushFlo/pushflo-go/envelope"

	"github.com/APIpact/apipact-agent/internal/config"
	"github.com/APIpact/apipact-agent/internal/enroll"
	"github.com/APIpact/apipact-agent/internal/protocol"
	"github.com/APIpact/apipact-agent/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "enroll":
		cmdEnroll(os.Args[2:])
	case "keygen":
		cmdKeygen(os.Args[2:])
	case "release-keygen":
		cmdReleaseKeygen(os.Args[2:])
	case "status":
		cmdStatus(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("agentctl", version.String())
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `agentctl — APIPact agent operator CLI

Commands:
  enroll          Register this agent with the cloud and write its config
  keygen          Generate a full cloud<->agent key set (dev / offline provisioning)
  release-keygen  Generate an Ed25519 release-signing key pair (for signed updates)
  status          Print the local agent identity and channel context
  version         Print version`)
}

// cmdReleaseKeygen generates the Ed25519 key pair used to sign release manifests.
// The PRIVATE half becomes the CI secret consumed by release-sign; the PUBLIC
// half is what the cloud returns as update.releaseSigner at enrollment, so the
// supervisor can verify manifests. This key is distinct from the message-envelope
// keys and should be managed as a high-value signing key.
func cmdReleaseKeygen(args []string) {
	fs := flag.NewFlagSet("release-keygen", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "emit JSON instead of env-style lines")
	_ = fs.Parse(args)

	pair, err := envelope.GenerateSigningKeyPair()
	if err != nil {
		fmt.Fprintln(os.Stderr, "keygen:", err)
		os.Exit(1)
	}
	priv := envelope.EncodeSigningPrivate(pair.Private)
	pub := envelope.EncodeSigningPublic(pair.Public)
	if *asJSON {
		b, _ := json.MarshalIndent(map[string]string{
			"RELEASE_SIGN_PRIVATE_B64": priv,
			"RELEASE_SIGN_PUBLIC_B64":  pub,
		}, "", "  ")
		fmt.Println(string(b))
		return
	}
	fmt.Println("# Store PRIVATE as a CI secret (RELEASE_SIGN_PRIVATE_B64); never commit it.")
	fmt.Println("# Return PUBLIC to agents as update.releaseSigner in the enrollment response.")
	fmt.Printf("RELEASE_SIGN_PRIVATE_B64=%s\n", priv)
	fmt.Printf("RELEASE_SIGN_PUBLIC_B64=%s\n", pub)
}

func cmdEnroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	token := fs.String("token", "", "one-time enrollment token from the cloud console")
	server := fs.String("server", "", "cloud control-plane base URL, e.g. https://cloud.apipact.example")
	name := fs.String("name", "", "human-friendly display name for this agent (e.g. prod-eu-dc1)")
	var labels labelFlags
	fs.Var(&labels, "label", "operator tag key=value (repeatable, e.g. --label env=prod --label region=eu)")
	pin := fs.String("pin", "", "optional server SPKI SHA-256 (base64) to pin TLS")
	out := fs.String("config", config.DefaultPath(), "where to write the agent config")
	force := fs.Bool("force", false, "overwrite an existing config")
	_ = fs.Parse(args)

	if *token == "" || *server == "" {
		fmt.Fprintln(os.Stderr, "enroll requires --token and --server")
		os.Exit(2)
	}
	if _, err := os.Stat(*out); err == nil && !*force {
		fmt.Fprintf(os.Stderr, "config already exists at %s (use --force to overwrite)\n", *out)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cfg, err := enroll.Enroll(ctx, enroll.Options{
		CloudBaseURL: *server, Token: *token, Name: *name, Labels: labels.m, PinSHA256: *pin,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "enrollment failed:", err)
		os.Exit(1)
	}
	if err := config.Save(*out, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "write config:", err)
		os.Exit(1)
	}
	fmt.Printf("enrolled as %s", cfg.AgentID)
	if cfg.Name != "" {
		fmt.Printf(" (%q)", cfg.Name)
	}
	fmt.Println()
	fmt.Printf("config written to %s (0600)\n", *out)
	fmt.Printf("jobs channel:    %s\n", protocol.JobsChannel(cfg.AgentID))
	fmt.Printf("results channel: %s\n", protocol.ResultsChannel(cfg.AgentID))
	fmt.Printf("control channel: %s\n", protocol.ControlChannel(cfg.AgentID))
}

// labelFlags collects repeated --label key=value pairs.
type labelFlags struct{ m map[string]string }

func (l *labelFlags) String() string { return "" }
func (l *labelFlags) Set(v string) error {
	i := strings.IndexByte(v, '=')
	if i <= 0 {
		return fmt.Errorf("label must be key=value, got %q", v)
	}
	if l.m == nil {
		l.m = map[string]string{}
	}
	l.m[v[:i]] = v[i+1:]
	return nil
}

// cmdKeygen prints a full key set for both directions. Useful for local
// development and offline/air-gapped provisioning where online enrollment is
// not available.
func cmdKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "emit JSON instead of env-style lines")
	_ = fs.Parse(args)

	agentRecipient, _ := envelope.GenerateRecipientKeyPair()
	cloudSigner, _ := envelope.GenerateSigningKeyPair()
	cloudRecipient, _ := envelope.GenerateRecipientKeyPair()
	agentSigner, _ := envelope.GenerateSigningKeyPair()

	set := map[string]string{
		"AGENT_RECIPIENT_PUBLIC":  envelope.EncodePublicKey(agentRecipient.Public),
		"AGENT_RECIPIENT_PRIVATE": envelope.EncodePrivateKey(agentRecipient.Private),
		"AGENT_SIGN_PUBLIC":       envelope.EncodeSigningPublic(agentSigner.Public),
		"AGENT_SIGN_PRIVATE":      envelope.EncodeSigningPrivate(agentSigner.Private),
		"CLOUD_RECIPIENT_PUBLIC":  envelope.EncodePublicKey(cloudRecipient.Public),
		"CLOUD_RECIPIENT_PRIVATE": envelope.EncodePrivateKey(cloudRecipient.Private),
		"CLOUD_SIGN_PUBLIC":       envelope.EncodeSigningPublic(cloudSigner.Public),
		"CLOUD_SIGN_PRIVATE":      envelope.EncodeSigningPrivate(cloudSigner.Private),
	}
	if *asJSON {
		b, _ := json.MarshalIndent(set, "", "  ")
		fmt.Println(string(b))
		return
	}
	fmt.Println("# AGENT holds: AGENT_RECIPIENT_PRIVATE, AGENT_SIGN_PRIVATE, CLOUD_RECIPIENT_PUBLIC, CLOUD_SIGN_PUBLIC")
	fmt.Println("# CLOUD holds: CLOUD_RECIPIENT_PRIVATE, CLOUD_SIGN_PRIVATE, AGENT_RECIPIENT_PUBLIC, AGENT_SIGN_PUBLIC")
	for _, k := range []string{
		"AGENT_RECIPIENT_PUBLIC", "AGENT_RECIPIENT_PRIVATE", "AGENT_SIGN_PUBLIC", "AGENT_SIGN_PRIVATE",
		"CLOUD_RECIPIENT_PUBLIC", "CLOUD_RECIPIENT_PRIVATE", "CLOUD_SIGN_PUBLIC", "CLOUD_SIGN_PRIVATE",
	} {
		fmt.Printf("%s=%s\n", k, set[k])
	}
}

func cmdStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	path := fs.String("config", config.DefaultPath(), "path to agent config")
	_ = fs.Parse(args)

	cfg, err := config.Load(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load config:", err)
		os.Exit(1)
	}
	fmt.Printf("agent id:        %s\n", cfg.AgentID)
	fmt.Printf("name:            %s\n", cfg.Name)
	if len(cfg.Labels) > 0 {
		fmt.Printf("labels:          %s\n", formatLabels(cfg.Labels))
	}
	fmt.Printf("version:         %s\n", version.String())
	fmt.Printf("cloud:           %s\n", cfg.CloudBaseURL)
	fmt.Printf("jobs channel:    %s\n", protocol.JobsChannel(cfg.AgentID))
	fmt.Printf("results channel: %s\n", protocol.ResultsChannel(cfg.AgentID))
	fmt.Printf("control channel: %s\n", protocol.ControlChannel(cfg.AgentID))
	fmt.Printf("return:          %s\n", cfg.Return.Transport)
	fmt.Printf("egress:          allowPrivate=%v allow=%v block=%v\n", cfg.Egress.AllowPrivate, cfg.Egress.Allow, cfg.Egress.Block)
	fmt.Printf("update:          mode=%s channel=%s\n", cfg.Update.Mode, cfg.Update.Channel)
}

func formatLabels(m map[string]string) string {
	parts := make([]string, 0, len(m))
	for k, v := range m {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ",")
}
