// Package protocol is the single source of truth for the wire contract between
// the APIPact cloud control plane and a local executor agent.
//
// Every sensitive payload travels sealed inside a pushflo/envelope.Envelope;
// these types describe the *plaintext* that is sealed. The cloud mirrors these
// shapes so the two sides cannot drift. Nothing here imports the transport, so
// the same definitions serve the WebSocket path and the HTTP result path.
//
// Design rules baked into these types:
//
//   - Headers and query strings are ORDERED lists of name/value pairs, not
//     maps. Order, repetition, and exact casing are preserved because edge
//     providers (Akamai, Cloudflare, Imperva) can be sensitive to all three.
//   - The agent performs no assertions. It executes faithfully and reports
//     structured facts; the cloud reasons about pass/fail.
//   - Every job carries an opaque Context that the agent echoes back verbatim,
//     so one cloud can correlate results across a fleet of agents on different
//     infrastructures (the relationship is many-to-many, never 1:1).
package protocol

import (
	"encoding/json"
	"time"
)

// Content types set on the envelope's `cty` field. The agent dispatches on
// these rather than on the transport's event type, so the contract is
// transport-independent.
const (
	ContentTypeJob     = "application/apipact.job+json"
	ContentTypeResult  = "application/apipact.result+json"
	ContentTypeControl = "application/apipact.control+json"
	ContentTypeAck     = "application/apipact.ack+json"
)

// Event types published on pushflo messages (a human-facing hint only; the
// authoritative type is the envelope content type above).
const (
	EventJob     = "apipact.job"
	EventResult  = "apipact.result"
	EventControl = "apipact.control"
	EventAck     = "apipact.ack"
)

// NameValue is one ordered header or query-string entry. The same name may
// appear multiple times; order is preserved on the wire and in results.
type NameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Timeouts bounds each layer of a single HTTP exchange independently. Zero on
// any field means "use the agent default" for that layer.
type Timeouts struct {
	ConnectMs        int `json:"connectMs,omitempty"`        // TCP connect
	TLSMs            int `json:"tlsMs,omitempty"`            // TLS handshake
	ResponseHeaderMs int `json:"responseHeaderMs,omitempty"` // request write -> response headers
	TotalMs          int `json:"totalMs,omitempty"`          // whole exchange incl. body read
}

// AcceptEncoding modes control how the agent handles content compression.
const (
	// AcceptEncodingAsIs sends exactly the headers the spec provides and never
	// auto-decodes: the reported body is the literal bytes on the wire and the
	// Content-Encoding header is preserved. This is the faithful default and the
	// right choice for edge/CDN testing.
	AcceptEncodingAsIs = "asis"
	// AcceptEncodingIdentity forces an uncompressed response (Accept-Encoding:
	// identity) and never auto-decodes.
	AcceptEncodingIdentity = "identity"
	// AcceptEncodingGzip lets the agent negotiate gzip and transparently
	// decompress, like a general-purpose HTTP client.
	AcceptEncodingGzip = "gzip"
)

// HTTP2 negotiation modes.
const (
	HTTP2Auto    = "auto"    // negotiate via ALPN (default)
	HTTP2Force   = "force"   // require HTTP/2
	HTTP2Disable = "disable" // HTTP/1.1 only
)

// RequestSpec is a single HTTP call to execute. Its defaults deliberately
// differ from a general-purpose client (no redirect following, faithful
// headers, no automatic compression).
type RequestSpec struct {
	ID                 string      `json:"id,omitempty"`
	Method             string      `json:"method"`
	URL                string      `json:"url"`
	Headers            []NameValue `json:"headers,omitempty"`      // ordered; may repeat; casing preserved
	HostOverride       string      `json:"hostOverride,omitempty"` // sets Host header (and SNI unless SNI is set)
	SNI                string      `json:"sni,omitempty"`          // TLS ServerName override
	Query              []NameValue `json:"query,omitempty"`        // appended to the URL in order
	BodyBase64         string      `json:"bodyBase64,omitempty"`
	FollowRedirects    bool        `json:"followRedirects,omitempty"` // default false: capture the 3xx
	MaxRedirects       int         `json:"maxRedirects,omitempty"`    // default 10 when following
	InsecureSkipVerify bool        `json:"insecureSkipVerify,omitempty"`
	Timeouts           Timeouts    `json:"timeouts,omitempty"`
	MaxBodyBytes       int64       `json:"maxBodyBytes,omitempty"`     // 0 => agent default (1 MiB)
	ReuseConnection    bool        `json:"reuseConnection,omitempty"`  // false => cold connection (no keep-alive)
	HTTP2              string      `json:"http2,omitempty"`            // auto|force|disable
	AcceptEncoding     string      `json:"acceptEncoding,omitempty"`   // asis|identity|gzip
	CaptureCertChain   bool        `json:"captureCertChain,omitempty"` // include full peer cert PEM chain
}

// ReturnTransport selects how a result travels back.
const (
	ReturnChannel = "channel" // sealed publish over the results channel
	ReturnHTTP    = "http"    // sealed POST to a cloud result endpoint
)

// ReturnSpec tells the agent where and how to send the result. Any field left
// empty falls back to the agent's enrolled default.
type ReturnSpec struct {
	Transport      string `json:"transport,omitempty"` // channel|http
	Channel        string `json:"channel,omitempty"`   // for transport=channel
	URL            string `json:"url,omitempty"`       // for transport=http
	InlineMaxBytes int    `json:"inlineMaxBytes,omitempty"`
}

// ExecutionSpec controls how the requests in a job are run.
type ExecutionSpec struct {
	MaxConcurrency int  `json:"maxConcurrency,omitempty"` // 0 => sequential (1)
	StopOnError    bool `json:"stopOnError,omitempty"`    // abort remaining requests on the first transport error
}

// Job is one dispatch from the cloud to a specific agent.
type Job struct {
	JobID     string          `json:"jobId"`              // idempotency / dedupe key
	AgentID   string          `json:"agentId"`            // MUST equal the receiving agent
	IssuedAt  time.Time       `json:"issuedAt"`           //
	Deadline  *time.Time      `json:"deadline,omitempty"` // do not start if already past
	Context   json.RawMessage `json:"context,omitempty"`  // opaque; echoed verbatim in the result
	Return    ReturnSpec      `json:"return,omitempty"`
	Execution ExecutionSpec   `json:"execution,omitempty"`
	Requests  []RequestSpec   `json:"requests"`
}

// Timing is a per-request latency breakdown, in milliseconds.
type Timing struct {
	DNSMs     float64 `json:"dnsMs"`
	ConnectMs float64 `json:"connectMs"`
	TLSMs     float64 `json:"tlsMs"`
	TTFBMs    float64 `json:"ttfbMs"`
	TotalMs   float64 `json:"totalMs"`
}

// RedirectHop is one entry in a followed redirect chain.
type RedirectHop struct {
	Status   int    `json:"status"`
	Location string `json:"location"`
	URL      string `json:"url"` // the URL that produced this 3xx
}

// TLSInfo describes the negotiated TLS connection and presented certificate.
type TLSInfo struct {
	Version      string     `json:"version"`
	CipherSuite  string     `json:"cipherSuite"`
	ALPN         string     `json:"alpn,omitempty"`
	ServerName   string     `json:"serverName,omitempty"`
	Issuer       string     `json:"issuer,omitempty"`
	Subject      string     `json:"subject,omitempty"`
	DNSNames     []string   `json:"dnsNames,omitempty"`
	NotBefore    *time.Time `json:"notBefore,omitempty"`
	NotAfter     *time.Time `json:"notAfter,omitempty"`
	PeerCertsPEM []string   `json:"peerCertsPem,omitempty"` // only when RequestSpec.CaptureCertChain
}

// Structured error kinds. The cloud reasons on these instead of string-matching.
const (
	ErrKindDNS     = "dns"
	ErrKindConnect = "connect"
	ErrKindTLS     = "tls"
	ErrKindTimeout = "timeout"
	ErrKindHTTP    = "http"    // a protocol-level failure after connecting
	ErrKindBlocked = "blocked" // egress policy denied the target
	ErrKindInvalid = "invalid" // malformed spec (bad URL, bad body, ...)
)

// ExecError is a structured failure classification for a single request.
type ExecError struct {
	Kind      string `json:"kind"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// Body encodings reported on a ResponseResult.
const (
	BodyEncodingBase64    = "base64"
	BodyEncodingTruncated = "truncated"
)

// ResponseResult is the structured outcome of one request — the real product.
type ResponseResult struct {
	RequestID     string        `json:"requestId,omitempty"`
	Status        int           `json:"status"`
	Proto         string        `json:"proto,omitempty"` // e.g. "HTTP/1.1", "HTTP/2.0"
	Headers       []NameValue   `json:"headers,omitempty"`
	BodyEncoding  string        `json:"bodyEncoding,omitempty"`
	BodyBase64    string        `json:"bodyBase64,omitempty"`
	BodyTruncated bool          `json:"bodyTruncated"`
	BodyBytes     int64         `json:"bodyBytes"`
	Timing        Timing        `json:"timing"`
	RedirectChain []RedirectHop `json:"redirectChain,omitempty"`
	TLS           *TLSInfo      `json:"tls,omitempty"`
	Error         *ExecError    `json:"error,omitempty"`
}

// Result is what the agent returns for a whole job.
type Result struct {
	JobID         string           `json:"jobId"`
	AgentID       string           `json:"agentId"`
	Context       json.RawMessage  `json:"context,omitempty"` // echoed verbatim from the job
	AgentVersion  string           `json:"agentVersion,omitempty"`
	WorkerVersion string           `json:"workerVersion,omitempty"`
	StartedAt     time.Time        `json:"startedAt"`
	FinishedAt    time.Time        `json:"finishedAt"`
	Responses     []ResponseResult `json:"responses"`
}

// Control message types on the control channel.
const (
	ControlPing       = "ping"        // cloud liveness probe -> agent replies with an Ack heartbeat
	ControlRotateKeys = "rotate-keys" // nudge the agent to rotate its recipient key
	ControlUpdate     = "update"      // nudge the supervisor to check the release channel now
	ControlConfig     = "config"      // push a config delta (egress policy, thresholds, ...)
)

// ControlMessage is a sealed instruction on the control channel.
type ControlMessage struct {
	Type     string          `json:"type"`
	IssuedAt time.Time       `json:"issuedAt"`
	Payload  json.RawMessage `json:"payload,omitempty"`
}

// Ack kinds distinguish an unsolicited hello/heartbeat from a ping reply.
const (
	AckHello     = "hello"     // sent once on (re)connect — announces identity + version
	AckHeartbeat = "heartbeat" // periodic liveness + current version
	AckPong      = "pong"      // reply to a ControlPing
)

// Ack is the agent's heartbeat / acknowledgement back to the cloud. It is how the
// cloud learns and tracks each agent's live build version — which changes after an
// auto-update — plus its operator-facing identity (name/labels) and load.
type Ack struct {
	Kind          string            `json:"kind"` // hello | heartbeat | pong
	AgentID       string            `json:"agentId"`
	Name          string            `json:"name,omitempty"`   // human-friendly display name
	Labels        map[string]string `json:"labels,omitempty"` // operator tags (env, region, ...)
	AgentVersion  string            `json:"agentVersion,omitempty"`
	WorkerVersion string            `json:"workerVersion,omitempty"`
	SentAt        time.Time         `json:"sentAt"`
	InFlight      int               `json:"inFlight"`
	// InReplyTo echoes the message id of a ControlPing, when this ack answers one.
	InReplyTo string `json:"inReplyTo,omitempty"`
}
