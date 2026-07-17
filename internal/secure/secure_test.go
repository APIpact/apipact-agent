package secure

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/PushFlo/pushflo-go/envelope"
)

// testSetup builds a full cloud<->agent key set: the KeyMaterial the agent
// stores, a Sealer the cloud uses to seal jobs to the agent, and an Opener the
// cloud uses to open results sealed by the agent.
func testSetup(t *testing.T) (KeyMaterial, *envelope.Sealer, *envelope.Opener) {
	t.Helper()

	agentRecipient, err := envelope.GenerateRecipientKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	agentSigner, err := envelope.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cloudRecipient, err := envelope.GenerateRecipientKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cloudSigner, err := envelope.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	km := KeyMaterial{
		RecipientPublicB64:  envelope.EncodePublicKey(agentRecipient.Public),
		RecipientPrivateB64: envelope.EncodePrivateKey(agentRecipient.Private),
		CloudSignersB64:     map[string]string{"cloud-1": envelope.EncodeSigningPublic(cloudSigner.Public)},
		CloudPublicB64:      envelope.EncodePublicKey(cloudRecipient.Public),
		SignPrivateB64:      envelope.EncodeSigningPrivate(agentSigner.Private),
		SignKeyID:           "agent-1",
	}

	cloudJobSealer, err := envelope.NewSealer(envelope.SealerConfig{
		RecipientPublic: agentRecipient.Public,
		SignerPrivate:   cloudSigner.Private,
		SignerKeyID:     "cloud-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	cloudResultOpener, err := envelope.NewOpener(envelope.OpenerConfig{
		RecipientPublic:  cloudRecipient.Public,
		RecipientPrivate: cloudRecipient.Private,
		Signers:          map[string]ed25519.PublicKey{"agent-1": agentSigner.Public},
		MaxClockSkew:     time.Minute,
		Replay:           envelope.NewMemoryReplayCache(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	return km, cloudJobSealer, cloudResultOpener
}

func TestSuiteRoundTrip(t *testing.T) {
	km, cloudSealer, cloudOpener := testSetup(t)

	suite, err := BuildSuite(km, time.Minute, envelope.NewMemoryReplayCache(time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	type job struct {
		JobID string `json:"jobId"`
	}
	env, err := cloudSealer.SealJSON(job{JobID: "j-1"}, envelope.Meta{MessageID: "m-1"})
	if err != nil {
		t.Fatal(err)
	}
	var got job
	if err := suite.Opener.OpenJSON(env, &got); err != nil {
		t.Fatalf("agent open: %v", err)
	}
	if got.JobID != "j-1" {
		t.Errorf("job round-trip wrong: %+v", got)
	}

	type result struct {
		OK bool `json:"ok"`
	}
	renv, err := suite.ResultSealer.SealJSON(result{OK: true}, envelope.Meta{MessageID: "r-1"})
	if err != nil {
		t.Fatal(err)
	}
	var gotRes result
	if err := cloudOpener.OpenJSON(renv, &gotRes); err != nil {
		t.Fatalf("cloud open result: %v", err)
	}
	if !gotRes.OK {
		t.Error("result round-trip failed")
	}
}

func TestReplayRejected(t *testing.T) {
	km, cloudSealer, _ := testSetup(t)
	suite, err := BuildSuite(km, time.Minute, envelope.NewMemoryReplayCache(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	env, err := cloudSealer.SealJSON(map[string]string{"jobId": "dup"}, envelope.Meta{MessageID: "same-id"})
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]string
	if err := suite.Opener.OpenJSON(env, &v); err != nil {
		t.Fatalf("first open should succeed: %v", err)
	}
	if err := suite.Opener.OpenJSON(env, &v); err != envelope.ErrReplay {
		t.Errorf("expected replay rejection, got %v", err)
	}
}

func TestForgedSignatureRejected(t *testing.T) {
	km, _, _ := testSetup(t)
	suite, err := BuildSuite(km, time.Minute, envelope.NewMemoryReplayCache(time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	attackerSigner, _ := envelope.GenerateSigningKeyPair()
	agentPub, _ := envelope.DecodeKey32(km.RecipientPublicB64)
	forger, _ := envelope.NewSealer(envelope.SealerConfig{
		RecipientPublic: agentPub,
		SignerPrivate:   attackerSigner.Private,
		SignerKeyID:     "cloud-1", // reuse the known skid — still rejected
	})
	env, _ := forger.SealJSON(map[string]string{"jobId": "evil"}, envelope.Meta{MessageID: "x"})
	var v map[string]string
	if err := suite.Opener.OpenJSON(env, &v); err != envelope.ErrBadSignature {
		t.Errorf("expected bad signature, got %v", err)
	}
}
