// Package transport wraps the PushFlo subscriber client. It owns the outbound
// WebSocket connection, subscribes the agent to its jobs and control channels,
// and forwards raw messages to handlers. It performs no crypto — the relay is
// untrusted, so decryption/verification happens one layer up in the worker.
package transport

import (
	"context"
	"log/slog"

	pushflo "github.com/PushFlo/pushflo-go"

	"github.com/APIpact/apipact-agent/internal/protocol"
)

// Handlers receives raw (still-sealed) messages from the two channels.
type Handlers struct {
	OnJob     func(pushflo.Message)
	OnControl func(pushflo.Message)
}

// Options configures the transport.
type Options struct {
	AgentID    string
	PublishKey string
	BaseURL    string
	Logger     *slog.Logger
	Debug      bool
}

// Transport is a connected subscriber for one agent.
type Transport struct {
	agentID string
	client  *pushflo.Client
	log     *slog.Logger
}

// Connect builds the client, connects, and subscribes to the jobs and control
// channels. Auto-reconnect (with subscription replay) is handled by the SDK.
func Connect(ctx context.Context, opts Options, h Handlers) (*Transport, error) {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}

	client, err := pushflo.NewClient(ctx, pushflo.ClientOptions{
		PublishKey: opts.PublishKey,
		BaseURL:    opts.BaseURL,
		Debug:      opts.Debug,
	})
	if err != nil {
		return nil, err
	}

	client.OnConnectionChange(func(s pushflo.ConnectionState) {
		log.Info("connection state", "state", string(s))
	})
	client.OnError(func(err error) { log.Warn("transport error", "err", err) })

	if err := client.Connect(ctx); err != nil {
		client.Destroy()
		return nil, err
	}

	jobsCh := protocol.JobsChannel(opts.AgentID)
	ctrlCh := protocol.ControlChannel(opts.AgentID)

	if _, err := client.Subscribe(jobsCh, pushflo.SubscriptionHandlers{
		OnSubscribed: func() { log.Info("subscribed", "channel", jobsCh) },
		OnMessage: func(m pushflo.Message) {
			if h.OnJob != nil {
				h.OnJob(m)
			}
		},
		OnError: func(err error) { log.Warn("jobs subscription error", "err", err) },
	}); err != nil {
		client.Destroy()
		return nil, err
	}

	if _, err := client.Subscribe(ctrlCh, pushflo.SubscriptionHandlers{
		OnSubscribed: func() { log.Info("subscribed", "channel", ctrlCh) },
		OnMessage: func(m pushflo.Message) {
			if h.OnControl != nil {
				h.OnControl(m)
			}
		},
		OnError: func(err error) { log.Warn("control subscription error", "err", err) },
	}); err != nil {
		client.Destroy()
		return nil, err
	}

	return &Transport{agentID: opts.AgentID, client: client, log: log}, nil
}

// Connected reports whether the underlying client is connected.
func (t *Transport) Connected() bool { return t.client.IsConnected() }

// Close tears down the connection.
func (t *Transport) Close() { t.client.Destroy() }
