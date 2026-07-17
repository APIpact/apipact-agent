package protocol

import (
	pushflo "github.com/PushFlo/pushflo-go"
	"testing"
)

func TestValidAgentID(t *testing.T) {
	valid := []string{"a", "abc123", "ag-1", "7f3a9c2b1d"}
	for _, id := range valid {
		if !ValidAgentID(id) {
			t.Errorf("expected %q valid", id)
		}
	}
	invalid := []string{"", "-x", "x-", "a--b", "Abc", "a.b", "a_b", "a b"}
	for _, id := range invalid {
		if ValidAgentID(id) {
			t.Errorf("expected %q invalid", id)
		}
	}
}

// TestChannelsAreValidSlugs guards the invariant that our channel names are
// always accepted by the PushFlo SDK (which forbids dots and uppercase).
func TestChannelsAreValidSlugs(t *testing.T) {
	id := "7f3a9c2b1d"
	for _, ch := range []string{JobsChannel(id), ResultsChannel(id), ControlChannel(id)} {
		if !pushflo.IsValidChannelSlug(ch) {
			t.Errorf("channel %q is not a valid pushflo slug", ch)
		}
	}
}
