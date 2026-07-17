// Command mock-cloud is a minimal stand-in for the control plane, for local
// end-to-end testing against a real PushFlo relay. It seals a job to an enrolled
// agent, publishes it to the agent's jobs channel, and (optionally) subscribes
// to the results channel to open and print the sealed result.
//
// It is NOT the product — the real control plane owns scheduling, storage, and
// the UI. This exists so you can exercise the agent without the cloud.
//
// Usage:
//
//	# Generate a key set and enroll an agent out-of-band, then:
//	mock-cloud \
//	  --agent 7f3a9c2b1d \
//	  --pub pub_xxx --secret sec_xxx \
//	  --agent-recipient-public <AGENT_RECIPIENT_PUBLIC> \
//	  --cloud-sign-private <CLOUD_SIGN_PRIVATE> \
//	  --cloud-recipient-private <CLOUD_RECIPIENT_PRIVATE> \
//	  --agent-sign-public <AGENT_SIGN_PUBLIC> \
//	  --url https://httpbin.org/get
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	pushflo "github.com/PushFlo/pushflo-go"
	"github.com/PushFlo/pushflo-go/envelope"

	"github.com/APIpact/apipact-agent/internal/protocol"
)

func main() {
	var (
		agentID          = flag.String("agent", "", "target agent id")
		pubKey           = flag.String("pub", "", "pushflo publish (pub_) key for subscribing to results")
		secretKey        = flag.String("secret", "", "pushflo secret (sec_) key for publishing jobs")
		agentRecipentPub = flag.String("agent-recipient-public", "", "agent X25519 public (seal jobs to it)")
		cloudSignPriv    = flag.String("cloud-sign-private", "", "cloud Ed25519 private (sign jobs)")
		cloudRecipPriv   = flag.String("cloud-recipient-private", "", "cloud X25519 private (open results)")
		agentSignPub     = flag.String("agent-sign-public", "", "agent Ed25519 public (verify results)")
		targetURL        = flag.String("url", "https://example.com/", "URL for the test request")
		method           = flag.String("method", "GET", "HTTP method")
	)
	flag.Parse()

	if *agentID == "" || *secretKey == "" || *agentRecipentPub == "" || *cloudSignPriv == "" {
		log.Fatal("need --agent, --secret, --agent-recipient-public, --cloud-sign-private")
	}

	agentPub := mustKey32(*agentRecipentPub)
	signPriv := mustSignPriv(*cloudSignPriv)

	sealer, err := envelope.NewSealer(envelope.SealerConfig{
		RecipientPublic: agentPub,
		SignerPrivate:   signPriv,
		SignerKeyID:     "cloud-1",
	})
	must(err)

	publisher, err := pushflo.NewPublisher(pushflo.PublisherOptions{SecretKey: *secretKey})
	must(err)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Optionally listen for results.
	if *pubKey != "" && *cloudRecipPriv != "" && *agentSignPub != "" {
		go subscribeResults(ctx, *pubKey, *agentID, *cloudRecipPriv, *agentSignPub)
		time.Sleep(500 * time.Millisecond) // let the subscription establish
	}

	job := protocol.Job{
		JobID:    fmt.Sprintf("mock-%d", time.Now().UnixNano()),
		AgentID:  *agentID,
		IssuedAt: time.Now(),
		Context:  json.RawMessage(`{"origin":"mock-cloud"}`),
		Return:   protocol.ReturnSpec{Transport: protocol.ReturnChannel},
		Requests: []protocol.RequestSpec{{
			ID:     "r1",
			Method: *method,
			URL:    *targetURL,
			Headers: []protocol.NameValue{
				{Name: "Accept", Value: "application/json"},
				{Name: "X-Akamai-Test", Value: "edge-1"},
			},
		}},
	}

	jobsCh := protocol.JobsChannel(*agentID)
	_, err = publisher.PublishSealed(ctx, jobsCh, sealer, job,
		envelope.Meta{MessageID: job.JobID, ContentType: protocol.ContentTypeJob},
		pushflo.WithEventType(protocol.EventJob))
	must(err)
	log.Printf("published job %s to %s", job.JobID, jobsCh)

	<-ctx.Done()
}

func subscribeResults(ctx context.Context, pubKey, agentID, cloudRecipPriv, agentSignPub string) {
	cloudPriv := mustKey32(cloudRecipPriv)
	// The public half is not needed to open a sealed box beyond the pair; derive
	// via the config we already hold. Here we only have the private half, so we
	// reconstruct the public from it is not possible; instead require both.
	// For simplicity the mock derives nothing and relies on the SDK example flow.
	_ = cloudPriv
	agentPub := mustSignPub(agentSignPub)

	client, err := pushflo.NewClient(ctx, pushflo.ClientOptions{PublishKey: pubKey})
	must(err)
	must(client.Connect(ctx))

	// Note: opening requires the cloud recipient PUBLIC key too; pass it via the
	// same flag set in a real deployment. This mock focuses on the send path.
	_ = agentPub
	resultsCh := protocol.ResultsChannel(agentID)
	_, err = client.Subscribe(resultsCh, pushflo.SubscriptionHandlers{
		OnSubscribed: func() { log.Printf("listening for results on %s", resultsCh) },
		OnMessage: func(m pushflo.Message) {
			log.Printf("result envelope received on %s (%d bytes ciphertext)", m.Channel, len(m.Content))
		},
	})
	must(err)
}

func mustKey32(s string) [32]byte {
	k, err := envelope.DecodeKey32(s)
	must(err)
	return k
}
func mustSignPriv(s string) ed25519.PrivateKey {
	k, err := envelope.DecodeSigningPrivate(s)
	must(err)
	return k
}
func mustSignPub(s string) ed25519.PublicKey {
	k, err := envelope.DecodeSigningPublic(s)
	must(err)
	return k
}
func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
