// Package secure wires the pushflo/envelope primitives from an agent's stored
// key material into an Opener (verify+decrypt inbound jobs/control) and a Sealer
// (encrypt+sign outbound results/acks).
//
// Key directions (see the envelope package): the cloud seals jobs to the
// agent's X25519 recipient key and signs them with its Ed25519 key; the agent
// seals results to the cloud's X25519 recipient key and signs them with its own
// Ed25519 key. Rotation is supported by carrying multiple signer epochs keyed by
// skid.
package secure

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/PushFlo/pushflo-go/envelope"
)

// KeyMaterial is everything the agent needs to open inbound and seal outbound
// messages. All fields are base64 (std) as produced by the envelope encode
// helpers and stored in the agent config.
type KeyMaterial struct {
	// Inbound (open jobs/control sealed to this agent).
	RecipientPublicB64  string `json:"recipientPublic"`
	RecipientPrivateB64 string `json:"recipientPrivate"`
	// Signers verifying the cloud, keyed by skid (signing key id / epoch). The
	// empty-string key accepts envelopes that carry no skid.
	CloudSignersB64 map[string]string `json:"cloudSigners"`

	// Outbound (seal results/acks to the cloud).
	CloudPublicB64   string `json:"cloudPublic"`
	SignPrivateB64   string `json:"signPrivate"`
	SignKeyID        string `json:"signKeyId"`        // this agent's skid, echoed on outbound envelopes
	RecipientKeyID   string `json:"recipientKeyId"`   // this agent's kid/epoch, echoed on inbound seals
	CloudRecipientID string `json:"cloudRecipientId"` // cloud's kid/epoch, set on outbound seals
}

// Suite bundles a ready Opener and result Sealer.
type Suite struct {
	Opener       *envelope.Opener
	ResultSealer *envelope.Sealer
}

// BuildSuite constructs the Opener and Sealer from key material. maxSkew and the
// replay cache guard freshness/replay on the inbound path.
func BuildSuite(km KeyMaterial, maxSkew time.Duration, replay envelope.ReplayCache) (*Suite, error) {
	recipientPub, err := envelope.DecodeKey32(km.RecipientPublicB64)
	if err != nil {
		return nil, fmt.Errorf("recipient public: %w", err)
	}
	recipientPriv, err := envelope.DecodeKey32(km.RecipientPrivateB64)
	if err != nil {
		return nil, fmt.Errorf("recipient private: %w", err)
	}
	if len(km.CloudSignersB64) == 0 {
		return nil, fmt.Errorf("no cloud signer keys configured")
	}
	signers := make(map[string]ed25519.PublicKey, len(km.CloudSignersB64))
	for skid, b64 := range km.CloudSignersB64 {
		pub, err := envelope.DecodeSigningPublic(b64)
		if err != nil {
			return nil, fmt.Errorf("cloud signer %q: %w", skid, err)
		}
		signers[skid] = pub
	}

	opener, err := envelope.NewOpener(envelope.OpenerConfig{
		RecipientPublic:  recipientPub,
		RecipientPrivate: recipientPriv,
		Signers:          signers,
		MaxClockSkew:     maxSkew,
		Replay:           replay,
	})
	if err != nil {
		return nil, fmt.Errorf("build opener: %w", err)
	}

	cloudPub, err := envelope.DecodeKey32(km.CloudPublicB64)
	if err != nil {
		return nil, fmt.Errorf("cloud public: %w", err)
	}
	signPriv, err := envelope.DecodeSigningPrivate(km.SignPrivateB64)
	if err != nil {
		return nil, fmt.Errorf("sign private: %w", err)
	}
	sealer, err := envelope.NewSealer(envelope.SealerConfig{
		RecipientPublic: cloudPub,
		RecipientKeyID:  km.CloudRecipientID,
		SignerPrivate:   signPriv,
		SignerKeyID:     km.SignKeyID,
	})
	if err != nil {
		return nil, fmt.Errorf("build sealer: %w", err)
	}

	return &Suite{Opener: opener, ResultSealer: sealer}, nil
}

// GenerateAgentKeys creates the agent's own key pairs (recipient X25519 for
// receiving sealed jobs, signing Ed25519 for signing results). Used at
// enrollment; private halves never leave the host.
func GenerateAgentKeys() (recipient *envelope.RecipientKeyPair, signing *envelope.SigningKeyPair, err error) {
	recipient, err = envelope.GenerateRecipientKeyPair()
	if err != nil {
		return nil, nil, err
	}
	signing, err = envelope.GenerateSigningKeyPair()
	if err != nil {
		return nil, nil, err
	}
	return recipient, signing, nil
}
