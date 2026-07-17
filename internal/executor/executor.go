// Package executor is the HTTP execution engine — the part of the agent that
// makes the actual calls. Its behaviour differs deliberately from a
// general-purpose client so that API tests are faithful and edge/anti-bot
// setups (Akamai et al.) behave as they would for a real caller:
//
//   - headers are sent verbatim (exact names, values, repetition), the default
//     Go User-Agent is suppressed unless the spec sets one, and automatic gzip
//     is off by default so the reported body is the literal bytes on the wire;
//   - redirects are NOT followed unless asked, and when followed the full chain
//     is captured;
//   - every layer has its own timeout, the body is size-capped, and failures
//     are classified structurally;
//   - all egress passes the SSRF guard, which checks the post-DNS IP.
package executor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/APIpact/apipact-agent/internal/protocol"
)

// DefaultMaxBodyBytes caps a captured response body when the spec does not.
const DefaultMaxBodyBytes int64 = 1 << 20 // 1 MiB

// defaults for the per-layer timeouts when a spec leaves them at zero.
const (
	defaultConnectTimeout = 10 * time.Second
	defaultTLSTimeout     = 10 * time.Second
	defaultTotalTimeout   = 30 * time.Second
	defaultMaxRedirects   = 10
)

// Engine executes request specs under a fixed egress policy. It is safe for
// concurrent use.
type Engine struct {
	Policy         EgressPolicy
	DefaultMaxBody int64
	Logger         *slog.Logger
	// resolver is overridable in tests; nil uses the default resolver.
	resolver *net.Resolver
}

// New builds an Engine.
func New(policy EgressPolicy, logger *slog.Logger) *Engine {
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{Policy: policy, DefaultMaxBody: DefaultMaxBodyBytes, Logger: logger}
}

// egressBlockedError marks a dial rejected by the egress policy so it can be
// classified distinctly from an ordinary connection failure.
type egressBlockedError struct{ msg string }

func (e *egressBlockedError) Error() string { return e.msg }

// Execute runs a single request spec and returns a structured result. It never
// returns an error; failures are reported inside the ResponseResult.Error.
func (e *Engine) Execute(ctx context.Context, spec protocol.RequestSpec) protocol.ResponseResult {
	res := protocol.ResponseResult{RequestID: spec.ID}

	u, err := buildURL(spec)
	if err != nil {
		res.Error = &protocol.ExecError{Kind: protocol.ErrKindInvalid, Message: err.Error()}
		return res
	}

	body, err := decodeBody(spec.BodyBase64)
	if err != nil {
		res.Error = &protocol.ExecError{Kind: protocol.ErrKindInvalid, Message: "bad body: " + err.Error()}
		return res
	}

	// A single total deadline spans the whole exchange, including any redirects.
	total := defaultTotalTimeout
	if spec.Timeouts.TotalMs > 0 {
		total = time.Duration(spec.Timeouts.TotalMs) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, total)
	defer cancel()

	maxRedirects := 0
	if spec.FollowRedirects {
		maxRedirects = spec.MaxRedirects
		if maxRedirects <= 0 {
			maxRedirects = defaultMaxRedirects
		}
	}

	method := strings.ToUpper(strings.TrimSpace(spec.Method))
	if method == "" {
		method = http.MethodGet
	}
	curURL := u
	curBody := body

	for hop := 0; ; hop++ {
		resp, tlsState, tt, err := e.doOnce(ctx, method, curURL, spec, curBody)
		if err != nil {
			res.Timing = tt.snapshot(msSince(tt.start))
			res.Error = classify(err)
			return res
		}

		// A redirect we are asked to follow: record it and continue.
		if spec.FollowRedirects && isRedirect(resp.StatusCode) && hop < maxRedirects {
			loc := resp.Header.Get("Location")
			res.RedirectChain = append(res.RedirectChain, protocol.RedirectHop{
				Status:   resp.StatusCode,
				Location: loc,
				URL:      curURL.String(),
			})
			next, nErr := curURL.Parse(loc)
			drainClose(resp.Body)
			if nErr != nil || loc == "" {
				res.Error = &protocol.ExecError{Kind: protocol.ErrKindHTTP, Message: "invalid redirect Location: " + loc}
				return res
			}
			method, curBody = redirectMethod(resp.StatusCode, method, body)
			curURL = next
			continue
		}

		// Terminal response.
		e.fill(&res, resp, tlsState, spec)
		res.Timing = tt.snapshot(msSince(tt.start)) // includes the body read
		return res
	}
}

// traceTimer collects httptrace timings. Its hooks may be invoked concurrently
// (dual-stack/parallel DNS dials) and a cancelled DNS lookup can leave a
// goroutine that fires a hook after Do returns, so every field is mutex-guarded
// and lives in its own struct that outlives any lingering goroutine safely.
type traceTimer struct {
	mu                          sync.Mutex
	start, dnsAt, connAt, tlsAt time.Time
	t                           protocol.Timing
}

func (tt *traceTimer) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart:             func(httptrace.DNSStartInfo) { tt.mu.Lock(); tt.dnsAt = time.Now(); tt.mu.Unlock() },
		DNSDone:              func(httptrace.DNSDoneInfo) { tt.mu.Lock(); tt.t.DNSMs = msSince(tt.dnsAt); tt.mu.Unlock() },
		ConnectStart:         func(string, string) { tt.mu.Lock(); tt.connAt = time.Now(); tt.mu.Unlock() },
		ConnectDone:          func(string, string, error) { tt.mu.Lock(); tt.t.ConnectMs = msSince(tt.connAt); tt.mu.Unlock() },
		TLSHandshakeStart:    func() { tt.mu.Lock(); tt.tlsAt = time.Now(); tt.mu.Unlock() },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { tt.mu.Lock(); tt.t.TLSMs = msSince(tt.tlsAt); tt.mu.Unlock() },
		GotFirstResponseByte: func() { tt.mu.Lock(); tt.t.TTFBMs = msSince(tt.start); tt.mu.Unlock() },
	}
}

func (tt *traceTimer) snapshot(total float64) protocol.Timing {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	out := tt.t
	out.TotalMs = total
	return out
}

// doOnce performs exactly one HTTP exchange (never auto-following redirects) and
// records timing. It returns the response with its Body still open.
func (e *Engine) doOnce(ctx context.Context, method string, u *url.URL, spec protocol.RequestSpec, body []byte) (*http.Response, *tls.ConnectionState, *traceTimer, error) {
	tt := &traceTimer{start: time.Now()}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bodyReader(body))
	if err != nil {
		return nil, nil, tt, err
	}
	applyHeaders(req, spec)
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), tt.trace()))

	client := e.buildClient(spec, u)
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, tt, err
	}
	return resp, resp.TLS, tt, nil
}

// buildClient constructs a per-request client wiring every knob: layered
// timeouts, the guarded dialer, compression control, HTTP/2 negotiation, and
// TLS verification/SNI. A fresh client (no shared pool) is what makes
// reuseConnection=false a genuine cold-connection measurement.
func (e *Engine) buildClient(spec protocol.RequestSpec, u *url.URL) *http.Client {
	connectTimeout := defaultConnectTimeout
	if spec.Timeouts.ConnectMs > 0 {
		connectTimeout = time.Duration(spec.Timeouts.ConnectMs) * time.Millisecond
	}
	tlsTimeout := defaultTLSTimeout
	if spec.Timeouts.TLSMs > 0 {
		tlsTimeout = time.Duration(spec.Timeouts.TLSMs) * time.Millisecond
	}

	serverName := firstNonEmpty(spec.SNI, spec.HostOverride, u.Hostname())

	tr := &http.Transport{
		DialContext:           e.guardedDial(connectTimeout),
		TLSHandshakeTimeout:   tlsTimeout,
		DisableKeepAlives:     !spec.ReuseConnection,
		DisableCompression:    spec.AcceptEncoding != protocol.AcceptEncodingGzip,
		ForceAttemptHTTP2:     spec.HTTP2 != protocol.HTTP2Disable,
		ResponseHeaderTimeout: durMs(spec.Timeouts.ResponseHeaderMs),
		// #nosec G402 -- InsecureSkipVerify is a per-request, operator-opted knob
		// delivered inside a signed, E2E-encrypted job, used to probe staging
		// endpoints with self-signed certs. Verification is on by default.
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: spec.InsecureSkipVerify,
			ServerName:         serverName,
			MinVersion:         tls.VersionTLS10, // deliberately permissive: we TEST endpoints, incl. legacy ones
		},
	}
	if spec.HTTP2 == protocol.HTTP2Disable {
		// A non-nil empty map disables the automatic HTTP/2 upgrade.
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}

	return &http.Client{
		Transport: tr,
		// We follow redirects manually to capture the chain, so the client must
		// never chase them itself.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// guardedDial resolves the target, filters candidate IPs through the egress
// policy, and connects to a vetted IP directly — closing the DNS-rebinding gap
// (we never re-resolve between the check and the connect).
func (e *Engine) guardedDial(connectTimeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: connectTimeout}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		var ips []net.IP
		if literal := net.ParseIP(host); literal != nil {
			ips = []net.IP{literal}
		} else {
			resolver := e.resolver
			if resolver == nil {
				resolver = net.DefaultResolver
			}
			addrs, rErr := resolver.LookupIPAddr(ctx, host)
			if rErr != nil {
				return nil, rErr
			}
			for _, a := range addrs {
				ips = append(ips, a.IP)
			}
		}

		var lastErr error
		for _, ip := range ips {
			if ok, reason := e.Policy.Allowed(ip); !ok {
				lastErr = &egressBlockedError{msg: reason}
				continue
			}
			conn, dErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if dErr != nil {
				lastErr = dErr
				continue
			}
			return conn, nil
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("no addresses for %s", host)
		}
		return nil, lastErr
	}
}

// fill reads the terminal response into the result: headers, size-capped body,
// TLS info, timing, protocol.
func (e *Engine) fill(res *protocol.ResponseResult, resp *http.Response, tlsState *tls.ConnectionState, spec protocol.RequestSpec) {
	defer drainClose(resp.Body)

	maxBody := spec.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = e.DefaultMaxBody
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	truncated := int64(len(raw)) > maxBody
	if truncated {
		raw = raw[:maxBody]
	}

	res.Status = resp.StatusCode
	res.Proto = resp.Proto
	res.Headers = flattenHeaders(resp.Header)
	res.BodyBase64 = base64.StdEncoding.EncodeToString(raw)
	res.BodyBytes = int64(len(raw))
	res.BodyTruncated = truncated
	if truncated {
		res.BodyEncoding = protocol.BodyEncodingTruncated
	} else {
		res.BodyEncoding = protocol.BodyEncodingBase64
	}
	if tlsState != nil {
		res.TLS = describeTLS(tlsState, spec.CaptureCertChain)
	}
}

// --- helpers ----------------------------------------------------------------

func buildURL(spec protocol.RequestSpec) (*url.URL, error) {
	if strings.TrimSpace(spec.URL) == "" {
		return nil, errors.New("empty url")
	}
	u, err := url.Parse(spec.URL)
	if err != nil {
		return nil, fmt.Errorf("bad url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if len(spec.Query) > 0 {
		q := u.Query()
		for _, kv := range spec.Query {
			q.Add(kv.Name, kv.Value)
		}
		u.RawQuery = q.Encode()
	}
	return u, nil
}

func decodeBody(b64 string) ([]byte, error) {
	if b64 == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(b64)
}

func bodyReader(b []byte) io.Reader {
	if len(b) == 0 {
		return nil
	}
	return strings.NewReader(string(b))
}

// applyHeaders writes the spec's headers verbatim, preserving casing (by writing
// directly to the header map rather than through Set/Add, which canonicalise),
// maps a Host header to req.Host, and suppresses Go's default User-Agent unless
// the spec provides one.
func applyHeaders(req *http.Request, spec protocol.RequestSpec) {
	hasUA := false
	for _, h := range spec.Headers {
		switch {
		case strings.EqualFold(h.Name, "Host"):
			if spec.HostOverride == "" {
				req.Host = h.Value
			}
		case strings.EqualFold(h.Name, "User-Agent"):
			hasUA = true
			req.Header[h.Name] = append(req.Header[h.Name], h.Value)
		default:
			req.Header[h.Name] = append(req.Header[h.Name], h.Value)
		}
	}
	if spec.HostOverride != "" {
		req.Host = spec.HostOverride
	}
	if !hasUA {
		// Omit the header entirely rather than sending Go's default.
		req.Header["User-Agent"] = nil
	}
	// For identity mode, be explicit if the spec did not set the header itself.
	if spec.AcceptEncoding == protocol.AcceptEncodingIdentity && req.Header.Get("Accept-Encoding") == "" {
		req.Header["Accept-Encoding"] = []string{"identity"}
	}
}

func flattenHeaders(h http.Header) []protocol.NameValue {
	out := make([]protocol.NameValue, 0, len(h))
	for name, vals := range h {
		for _, v := range vals {
			out = append(out, protocol.NameValue{Name: name, Value: v})
		}
	}
	return out
}

func describeTLS(s *tls.ConnectionState, includeChain bool) *protocol.TLSInfo {
	info := &protocol.TLSInfo{
		Version:     tls.VersionName(s.Version),
		CipherSuite: tls.CipherSuiteName(s.CipherSuite),
		ALPN:        s.NegotiatedProtocol,
		ServerName:  s.ServerName,
	}
	if len(s.PeerCertificates) > 0 {
		leaf := s.PeerCertificates[0]
		nb, na := leaf.NotBefore, leaf.NotAfter
		info.Issuer = leaf.Issuer.String()
		info.Subject = leaf.Subject.String()
		info.DNSNames = leaf.DNSNames
		info.NotBefore = &nb
		info.NotAfter = &na
		if includeChain {
			info.PeerCertsPEM = certsToPEM(s.PeerCertificates)
		}
	}
	return info
}

func certsToPEM(certs []*x509.Certificate) []string {
	out := make([]string, 0, len(certs))
	for _, c := range certs {
		b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
		out = append(out, string(b))
	}
	return out
}

func isRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// redirectMethod mirrors browser/Go semantics: 307/308 preserve method and
// body; 301/302/303 turn a body-bearing method into GET.
func redirectMethod(status int, method string, body []byte) (string, []byte) {
	switch status {
	case http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return method, body
	default: // 301, 302, 303
		if method != http.MethodGet && method != http.MethodHead {
			return http.MethodGet, nil
		}
		return method, nil
	}
}

func classify(err error) *protocol.ExecError {
	var blocked *egressBlockedError
	if errors.As(err, &blocked) {
		return &protocol.ExecError{Kind: protocol.ErrKindBlocked, Message: err.Error()}
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return &protocol.ExecError{Kind: protocol.ErrKindDNS, Message: err.Error(), Retryable: dnsErr.IsTemporary}
	}
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return &protocol.ExecError{Kind: protocol.ErrKindTLS, Message: err.Error()}
	}
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return &protocol.ExecError{Kind: protocol.ErrKindTLS, Message: err.Error()}
	}
	if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		return &protocol.ExecError{Kind: protocol.ErrKindTimeout, Message: err.Error(), Retryable: true}
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return &protocol.ExecError{Kind: protocol.ErrKindConnect, Message: err.Error(), Retryable: true}
	}
	return &protocol.ExecError{Kind: protocol.ErrKindHTTP, Message: err.Error()}
}

func isTimeout(err error) bool {
	var te interface{ Timeout() bool }
	return errors.As(err, &te) && te.Timeout()
}

func drainClose(rc io.ReadCloser) {
	if rc == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(rc, 1<<16))
	_ = rc.Close()
}

func msSince(t time.Time) float64 {
	if t.IsZero() {
		return 0
	}
	return float64(time.Since(t).Microseconds()) / 1000.0
}

func durMs(ms int) time.Duration {
	if ms <= 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
