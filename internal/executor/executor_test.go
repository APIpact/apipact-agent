package executor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/APIpact/apipact-agent/internal/protocol"
)

// allowLocal is the engine used by tests that hit httptest (127.0.0.1) servers.
func allowLocal() *Engine {
	return New(EgressPolicy{AllowPrivate: true}, nil)
}

// echoResponse is what the header-echo server returns.
type echoResponse struct {
	Method         string      `json:"method"`
	Host           string      `json:"host"`
	Header         http.Header `json:"header"`
	AcceptEncoding string      `json:"acceptEncoding"`
	UserAgent      string      `json:"userAgent"`
}

func echoServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := echoResponse{
			Method:         r.Method,
			Host:           r.Host,
			Header:         r.Header,
			AcceptEncoding: r.Header.Get("Accept-Encoding"),
			UserAgent:      r.Header.Get("User-Agent"),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func decodeEcho(t *testing.T, res protocol.ResponseResult) echoResponse {
	t.Helper()
	if res.Error != nil {
		t.Fatalf("unexpected error: %+v", res.Error)
	}
	raw, err := base64.StdEncoding.DecodeString(res.BodyBase64)
	if err != nil {
		t.Fatalf("decode body: %v", err)
	}
	var e echoResponse
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatalf("unmarshal echo: %v (%s)", err, raw)
	}
	return e
}

func TestFaithfulHeadersAndHostOverride(t *testing.T) {
	srv := echoServer()
	defer srv.Close()

	res := allowLocal().Execute(context.Background(), protocol.RequestSpec{
		Method: "GET",
		URL:    srv.URL,
		Headers: []protocol.NameValue{
			{Name: "X-Akamai-Test", Value: "edge-1"},
			{Name: "True-Client-IP", Value: "203.0.113.7"},
			{Name: "Pragma", Value: "akamai-x-cache-on"},
		},
		HostOverride: "www.protected.example",
	})
	e := decodeEcho(t, res)

	if e.Host != "www.protected.example" {
		t.Errorf("Host override not applied: got %q", e.Host)
	}
	if got := e.Header.Get("X-Akamai-Test"); got != "edge-1" {
		t.Errorf("custom header missing: got %q", got)
	}
	if got := e.Header.Get("True-Client-IP"); got != "203.0.113.7" {
		t.Errorf("True-Client-IP missing: got %q", got)
	}
	if got := e.Header.Get("Pragma"); got != "akamai-x-cache-on" {
		t.Errorf("Pragma missing: got %q", got)
	}
}

func TestUserAgentSuppressed(t *testing.T) {
	srv := echoServer()
	defer srv.Close()

	res := allowLocal().Execute(context.Background(), protocol.RequestSpec{Method: "GET", URL: srv.URL})
	e := decodeEcho(t, res)
	if e.UserAgent != "" {
		t.Errorf("expected no User-Agent, got %q", e.UserAgent)
	}

	// When the spec supplies one, it is honored verbatim.
	res = allowLocal().Execute(context.Background(), protocol.RequestSpec{
		Method:  "GET",
		URL:     srv.URL,
		Headers: []protocol.NameValue{{Name: "User-Agent", Value: "APIPact/1.0"}},
	})
	e = decodeEcho(t, res)
	if e.UserAgent != "APIPact/1.0" {
		t.Errorf("expected supplied UA, got %q", e.UserAgent)
	}
}

func TestAcceptEncodingAsIsSendsNoGzip(t *testing.T) {
	srv := echoServer()
	defer srv.Close()

	res := allowLocal().Execute(context.Background(), protocol.RequestSpec{Method: "GET", URL: srv.URL}) // asis default
	e := decodeEcho(t, res)
	if strings.Contains(e.AcceptEncoding, "gzip") {
		t.Errorf("asis mode should not auto-add gzip, got %q", e.AcceptEncoding)
	}

	res = allowLocal().Execute(context.Background(), protocol.RequestSpec{
		Method:         "GET",
		URL:            srv.URL,
		AcceptEncoding: protocol.AcceptEncodingIdentity,
	})
	e = decodeEcho(t, res)
	if e.AcceptEncoding != "identity" {
		t.Errorf("identity mode should send Accept-Encoding: identity, got %q", e.AcceptEncoding)
	}
}

func TestRedirectNotFollowedByDefault(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dest", http.StatusFound)
	})
	mux.HandleFunc("/dest", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := allowLocal().Execute(context.Background(), protocol.RequestSpec{Method: "GET", URL: srv.URL + "/start"})
	if res.Error != nil {
		t.Fatalf("unexpected error: %+v", res.Error)
	}
	if res.Status != http.StatusFound {
		t.Errorf("expected 302 captured, got %d", res.Status)
	}
	if loc := headerValue(res.Headers, "Location"); loc != "/dest" {
		t.Errorf("expected Location /dest, got %q", loc)
	}
	if len(res.RedirectChain) != 0 {
		t.Errorf("expected no redirect chain, got %d", len(res.RedirectChain))
	}
}

func TestRedirectFollowedCapturesChain(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/b", http.StatusFound) })
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/c", http.StatusFound) })
	mux.HandleFunc("/c", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "done") })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := allowLocal().Execute(context.Background(), protocol.RequestSpec{
		Method:          "GET",
		URL:             srv.URL + "/a",
		FollowRedirects: true,
	})
	if res.Error != nil {
		t.Fatalf("unexpected error: %+v", res.Error)
	}
	if res.Status != 200 {
		t.Errorf("expected final 200, got %d", res.Status)
	}
	if len(res.RedirectChain) != 2 {
		t.Fatalf("expected 2 hops, got %d: %+v", len(res.RedirectChain), res.RedirectChain)
	}
	if res.RedirectChain[0].Status != 302 || res.RedirectChain[0].Location != "/b" {
		t.Errorf("hop 0 wrong: %+v", res.RedirectChain[0])
	}
}

func TestRedirectMaxRespected(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/loop", http.StatusFound) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := allowLocal().Execute(context.Background(), protocol.RequestSpec{
		Method:          "GET",
		URL:             srv.URL + "/loop",
		FollowRedirects: true,
		MaxRedirects:    3,
	})
	// After 3 hops we stop and report the last 302 as terminal.
	if res.Status != http.StatusFound {
		t.Errorf("expected to stop at a 302, got %d", res.Status)
	}
	if len(res.RedirectChain) != 3 {
		t.Errorf("expected exactly 3 recorded hops, got %d", len(res.RedirectChain))
	}
}

func TestBodyTruncation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("x", 5000)))
	}))
	defer srv.Close()

	res := allowLocal().Execute(context.Background(), protocol.RequestSpec{
		Method:       "GET",
		URL:          srv.URL,
		MaxBodyBytes: 1000,
	})
	if res.Error != nil {
		t.Fatalf("unexpected error: %+v", res.Error)
	}
	if !res.BodyTruncated {
		t.Error("expected truncated body")
	}
	if res.BodyBytes != 1000 {
		t.Errorf("expected 1000 bytes captured, got %d", res.BodyBytes)
	}
	if res.BodyEncoding != protocol.BodyEncodingTruncated {
		t.Errorf("expected encoding truncated, got %q", res.BodyEncoding)
	}
}

func TestTimingCaptured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(15 * time.Millisecond)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	res := allowLocal().Execute(context.Background(), protocol.RequestSpec{Method: "GET", URL: srv.URL})
	if res.Timing.TotalMs <= 0 {
		t.Errorf("expected positive total timing, got %v", res.Timing.TotalMs)
	}
	if res.Timing.TTFBMs <= 0 {
		t.Errorf("expected positive TTFB, got %v", res.Timing.TTFBMs)
	}
}

func TestTLSSelfSignedAndCertCapture(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()

	// Without skip-verify, the self-signed cert must fail as a TLS error.
	res := allowLocal().Execute(context.Background(), protocol.RequestSpec{Method: "GET", URL: srv.URL})
	if res.Error == nil || res.Error.Kind != protocol.ErrKindTLS {
		t.Errorf("expected TLS error, got %+v", res.Error)
	}

	// With skip-verify + cert capture, it succeeds and returns the chain.
	res = allowLocal().Execute(context.Background(), protocol.RequestSpec{
		Method:             "GET",
		URL:                srv.URL,
		InsecureSkipVerify: true,
		CaptureCertChain:   true,
	})
	if res.Error != nil {
		t.Fatalf("unexpected error: %+v", res.Error)
	}
	if res.TLS == nil {
		t.Fatal("expected TLS info")
	}
	if len(res.TLS.PeerCertsPEM) == 0 {
		t.Error("expected captured cert chain")
	}
	if !strings.HasPrefix(res.TLS.PeerCertsPEM[0], "-----BEGIN CERTIFICATE-----") {
		t.Error("cert not PEM-encoded")
	}
}

func TestInvalidURL(t *testing.T) {
	res := allowLocal().Execute(context.Background(), protocol.RequestSpec{Method: "GET", URL: "ftp://nope"})
	if res.Error == nil || res.Error.Kind != protocol.ErrKindInvalid {
		t.Errorf("expected invalid error, got %+v", res.Error)
	}
}

func TestDNSFailureClassified(t *testing.T) {
	res := allowLocal().Execute(context.Background(), protocol.RequestSpec{
		Method:   "GET",
		URL:      "http://this-host-does-not-exist.invalid",
		Timeouts: protocol.Timeouts{TotalMs: 3000},
	})
	if res.Error == nil || res.Error.Kind != protocol.ErrKindDNS {
		t.Errorf("expected dns error, got %+v", res.Error)
	}
}

func TestPOSTBodyRoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		r.Body.Read(b)
		fmt.Fprintf(w, "got:%s", b)
	}))
	defer srv.Close()

	res := allowLocal().Execute(context.Background(), protocol.RequestSpec{
		Method:     "POST",
		URL:        srv.URL,
		BodyBase64: base64.StdEncoding.EncodeToString([]byte("hello")),
	})
	if res.Error != nil {
		t.Fatalf("unexpected error: %+v", res.Error)
	}
	raw, _ := base64.StdEncoding.DecodeString(res.BodyBase64)
	if string(raw) != "got:hello" {
		t.Errorf("body round-trip wrong: %q", raw)
	}
}

func headerValue(hs []protocol.NameValue, name string) string {
	for _, h := range hs {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}
