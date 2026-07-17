package protocol

import (
	"fmt"
	"regexp"
)

// PushFlo channel slugs allow only lowercase letters, digits, and hyphens (no
// dots), with no leading/trailing or consecutive hyphens. Agent IDs are minted
// slug-safe at enrollment so these helpers always produce valid channels.
//
// Channel layout for the fleet (many agents, one cloud):
//
//	agent-<id>-jobs     cloud -> agent   (sealed jobs; only this agent subscribes)
//	agent-<id>-results  agent -> cloud   (sealed results, when transport=channel)
//	agent-<id>-control  cloud -> agent   (sealed control frames) and agent acks
var agentIDRe = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// ValidAgentID reports whether id is safe to embed in a channel slug.
func ValidAgentID(id string) bool {
	if len(id) == 0 || len(id) > 100 { // leave headroom under the 128-char slug cap
		return false
	}
	return agentIDRe.MatchString(id)
}

// JobsChannel is the downlink channel the agent subscribes to for jobs.
func JobsChannel(agentID string) string { return "agent-" + agentID + "-jobs" }

// ResultsChannel is the uplink channel for sealed results (transport=channel).
func ResultsChannel(agentID string) string { return "agent-" + agentID + "-results" }

// ControlChannel is the bidirectional control/heartbeat channel.
func ControlChannel(agentID string) string { return "agent-" + agentID + "-control" }

// CheckAgentID returns an error describing why id is not a valid agent id.
func CheckAgentID(id string) error {
	if !ValidAgentID(id) {
		return fmt.Errorf("invalid agent id %q: must be 1-100 chars of lowercase letters, digits, and non-repeating hyphens", id)
	}
	return nil
}
