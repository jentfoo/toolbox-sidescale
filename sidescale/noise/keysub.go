package noise

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/jentfoo/toolbox-sidescale/sidescale/tsproto"
)

// keySubstituter implements the substitute strategy's /key handling. It learns the
// real upstream Noise key once and serves a substituted /key body: via a registered
// native-proxy responder (responder mode) or in the byte path on a host-terminated
// control claim (sidecar_tls mode).
type keySubstituter struct {
	h           *Handler
	controlHost string
	clientPort  int
	responderID string

	mu        sync.Mutex
	fetched   bool
	realKey   key.MachinePublic
	legacyKey key.MachinePublic
	subBody   []byte
}

// setupKeySubstitution provisions /key substitution for the substitute strategy,
// returning nil for borrow (which needs none). Under responder mode it registers
// the substituted /key response after learning the real key.
func setupKeySubstitution(ctx context.Context, h *Handler) (*keySubstituter, error) {
	if h.cfg.KeyStrategy != KeyStrategySubstitute {
		return nil, nil
	}
	ks := &keySubstituter{h: h, controlHost: h.controlHost, clientPort: h.controlPort}
	// learn the real key before registering any responder to avoid a self-loop
	if err := ks.ensureFetched(ctx); err != nil {
		return nil, err
	}
	if h.cfg.KeySubstitution == KeySubResponder {
		body, err := ks.substitutedBody(ctx)
		if err != nil {
			return nil, err
		}
		id, err := ks.registerResponder(ctx, body)
		if err != nil {
			return nil, fmt.Errorf("register /key responder: %w", err)
		}
		ks.responderID = id
	}
	return ks, nil
}

// registerResponder registers the substituted /key response via the core
// proxy_respond_add tool and returns the responder id.
func (ks *keySubstituter) registerResponder(ctx context.Context, body []byte) (string, error) {
	// enable core tools so proxy_respond_add is permitted without the operator
	// starting sectool with --workflow none (best-effort: tool absent under an
	// explicit workflow, where tools already work)
	if _, err := ks.h.conn.CoreInvoke(ctx, "workflow", map[string]any{"task": "cli"}); err != nil {
		_ = ks.h.conn.Log("debug", "keysub: workflow init skipped", map[string]any{"err": err.Error()})
	}
	// omit the default https port so the canonical origin matches the client's
	// request (proxy_respond_add resolves a missing port to 443)
	origin := "https://" + ks.controlHost
	if ks.clientPort != 443 {
		origin += ":" + strconv.Itoa(ks.clientPort)
	}
	res, err := ks.h.conn.CoreInvoke(ctx, "proxy_respond_add", map[string]any{
		"origin":      origin,
		"path":        "/key",
		"method":      http.MethodGet,
		"status_code": http.StatusOK,
		"headers":     map[string]string{"Content-Type": "application/json"},
		"body":        string(body),
	})
	if err != nil {
		return "", err
	}
	if res.IsError {
		return "", errors.New(res.Content)
	}
	var entry struct {
		ResponderID string `json:"responder_id"`
	}
	if err := json.Unmarshal([]byte(res.Content), &entry); err != nil {
		return "", fmt.Errorf("parse responder: %w", err)
	}
	return entry.ResponderID, nil
}

// close deletes a responder registered by this substituter.
func (ks *keySubstituter) close(ctx context.Context) {
	if ks == nil || ks.responderID == "" {
		return
	}
	_, _ = ks.h.conn.CoreInvoke(ctx, "proxy_respond_delete", map[string]any{"id": ks.responderID})
}

// ensureFetched fetches and caches the real /key body and Noise key once.
func (ks *keySubstituter) ensureFetched(ctx context.Context) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if ks.fetched {
		return nil
	}
	// fetched at startup with the sidecar's capability version (no client yet)
	// the server's Noise publicKey does not vary by v, so this matches every client
	dialHost, dialPort, scheme := ks.h.upstreamDial(ks.controlHost)
	raw, err := fetchKeyBody(ctx, ks.h.conn, scheme, net.JoinHostPort(dialHost, strconv.Itoa(dialPort)), uint16(tsproto.CurrentCapabilityVersion))
	if err != nil {
		return err
	}
	var resp tailcfg.OverTLSPublicKeyResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("parse /key response: %w", err)
	}
	if resp.PublicKey.IsZero() {
		return errors.New("/key response missing publicKey")
	}
	sub, err := substitutePublicKey(raw, ks.h.responderKey.Public())
	if err != nil {
		return err
	}
	ks.realKey = resp.PublicKey
	ks.legacyKey = resp.LegacyPublicKey
	ks.subBody = sub
	ks.fetched = true
	return nil
}

// realServerKey returns the cached real upstream Noise key.
func (ks *keySubstituter) realServerKey(ctx context.Context) (key.MachinePublic, error) {
	if err := ks.ensureFetched(ctx); err != nil {
		return key.MachinePublic{}, err
	}
	ks.mu.Lock()
	defer ks.mu.Unlock()
	return ks.realKey, nil
}

// realLegacyServerKey returns the cached real upstream legacy machine key, the key the
// register SignatureV2 hash binds. Zero when the server serves no legacy key.
func (ks *keySubstituter) realLegacyServerKey(ctx context.Context) (key.MachinePublic, error) {
	if err := ks.ensureFetched(ctx); err != nil {
		return key.MachinePublic{}, err
	}
	ks.mu.Lock()
	defer ks.mu.Unlock()
	return ks.legacyKey, nil
}

// substitutedBody returns the cached /key body with the substituted publicKey.
func (ks *keySubstituter) substitutedBody(ctx context.Context) ([]byte, error) {
	if err := ks.ensureFetched(ctx); err != nil {
		return nil, err
	}
	ks.mu.Lock()
	defer ks.mu.Unlock()
	return ks.subBody, nil
}

// serveKey answers the cleartext /key request delivered on the host-terminated
// control claim (sidecar_tls mode) with the substituted body.
func (ks *keySubstituter) serveKey(ctx context.Context, conn net.Conn, streamID string) {
	defer func() { _ = conn.Close() }()

	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		ks.h.tunnelError(streamID, "read /key request", err)
		return
	}
	_ = req.Body.Close()
	if req.Method != http.MethodGet || !strings.HasPrefix(req.URL.Path, "/key") {
		_ = ks.h.conn.Log("warn", "keysub: unexpected request on control claim", map[string]any{"method": req.Method, "path": req.URL.Path})
		writeHTTPResponse(conn, http.StatusMisdirectedRequest, "text/plain", []byte("unsupported on control claim"))
		return
	}
	body, err := ks.substitutedBody(ctx)
	if err != nil {
		ks.h.tunnelError(streamID, "substitute /key", err)
		writeHTTPResponse(conn, http.StatusBadGateway, "text/plain", []byte("key fetch failed"))
		return
	}
	writeHTTPResponse(conn, http.StatusOK, "application/json", body)
}

// substitutePublicKey rewrites the publicKey field of a /key JSON body to pub, preserving other fields.
func substitutePublicKey(raw []byte, pub key.MachinePublic) ([]byte, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	v, err := json.Marshal(pub.String())
	if err != nil {
		return nil, err
	}
	obj["publicKey"] = v
	return json.Marshal(obj)
}

// writeHTTPResponse writes a minimal HTTP/1.1 response.
func writeHTTPResponse(w io.Writer, status int, contentType string, body []byte) {
	_, _ = fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		status, http.StatusText(status), contentType, len(body))
	_, _ = w.Write(body)
}
