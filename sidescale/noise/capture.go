package noise

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-analyze/bulk"

	"github.com/go-appsec/toolbox/sidecar/wire"
	"github.com/jentfoo/toolbox-sidescale/sidescale/adapter"
	"github.com/jentfoo/toolbox-sidescale/sidescale/tsproto"
)

// mapEndpoint is the streaming-capable inner endpoint.
const mapEndpoint = "/machine/map"

// captureInner returns the per-request capture seam for tunnel at: it records the inner
// request as a tailscale.control flow, applies hot-path rules, forwards over the tunnel's
// current upstream (healing a dead conn), records the response, and relays it to the client.
func (h *Handler) captureInner(ctx context.Context, at *activeTunnel) tsproto.CaptureFunc {
	return func(req *http.Request) (*http.Response, error) {
		reqBody, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
		headers := requestHeaders(req)

		fwdBody, fwdHeaders, err := h.captureRequest(ctx, at.flowID, req, headers, reqBody)
		if err != nil {
			return nil, h.captureError(at, req, "capture request", err)
		}

		outReq, err := buildUpstreamRequest(ctx, at.controlHost, fwdHeaders, fwdBody)
		if err != nil {
			return nil, h.captureError(at, req, "build upstream request", err)
		}
		fwdStart := time.Now()
		resp, err := h.forwardTunnel(ctx, at, outReq)
		if err != nil {
			return nil, h.captureError(at, req, "forward upstream", err)
		}
		// per-request feedback, mirroring sectool's proxy request logging
		_ = h.conn.Log("info", "control request", map[string]any{
			"method": req.Method, "path": req.URL.Path, "tunnel_id": at.flowID,
			"status": resp.StatusCode, "dur_ms": time.Since(fwdStart).Milliseconds(),
		})

		// long-lived streaming /machine/map: capture chunk-by-chunk as ordered
		// children of the stream parent, re-encoding to the client as they flow
		if isStreamingMap(req.URL.Path, fwdBody) {
			pseudo, regular := bulk.SliceSplit(isPseudoHeader, responseHeaders(resp))
			mutRegular, fired := h.conn.Rules().ApplyHeaders(regular, wire.RuleTypeResponseHeader)
			// a fired rule mutates the parent's headers and the client-facing stream
			if len(fired) > 0 {
				regular = mutRegular
				setResponseHeaders(resp, mutRegular)
			}
			// parent stays in-flight (no CompletedAt) as the anchor, completed on stream close
			parentID, err := h.conn.PushFlow(ctx, wire.Flow{
				ProtocolTag:  streamProtocolTag,
				Direction:    adapter.DirServerToClient,
				ParentFlowID: at.flowID,
				Response:     &wire.FlowMessage{StatusCode: resp.StatusCode, Headers: slices.Concat(regular, pseudo)},
				StartedAt:    time.Now(),
			})
			if err != nil {
				_ = resp.Body.Close()
				return nil, h.captureError(at, req, "stream parent", err)
			}
			resp.Body = newMapStreamReader(ctx, h, resp.Body, parentID)
			return resp, nil
		}

		out, err := h.captureResponse(ctx, at.flowID, resp)
		if err != nil {
			return nil, h.captureError(at, req, "capture response", err)
		}
		return out, nil
	}
}

// captureError logs an inner-capture failure with the offending tunnel and endpoint
// and returns the error so the bridge relays a 502 to the client.
func (h *Handler) captureError(at *activeTunnel, req *http.Request, stage string, err error) error {
	_ = h.conn.Log("error", "inner capture failed: "+stage, map[string]any{
		"method": req.Method, "path": req.URL.Path, "tunnel_id": at.flowID, "error": err.Error(),
	})
	return err
}

// captureRequest emits the request flow (mutated when a rule fires) and returns the body/headers to forward upstream.
func (h *Handler) captureRequest(ctx context.Context, tunnelID string, req *http.Request, headers []wire.Header, body []byte) ([]byte, []wire.Header, error) {
	mutBody, firedBody := h.conn.Rules().ApplyBody(body, wire.RuleTypeRequestBody)
	// header rules run over regular headers only: pseudo-headers are derived and
	// not operator-mutable, and the rule render/parse round-trip corrupts them
	pseudo, regular := bulk.SliceSplit(isPseudoHeader, headers)
	mutRegular, firedHdr := h.conn.Rules().ApplyHeaders(regular, wire.RuleTypeRequestHeader)
	// Concat, not append: SliceSplit's results may be views into headers, so
	// appending would risk mutating that shared backing array
	mutHeaders := slices.Concat(mutRegular, pseudo)
	fired := slices.Concat(firedBody, firedHdr)

	// a request capture is a complete one-way flow (the response is its own
	// server_to_client flow), so mark it done rather than leaving it in-flight
	captured := wire.Flow{
		ProtocolTag:  controlProtocolTag,
		Direction:    adapter.DirClientToServer,
		ParentFlowID: tunnelID,
		Request:      &wire.FlowMessage{Method: req.Method, Path: req.URL.Path, Headers: headers, Body: body},
		StartedAt:    time.Now(),
	}
	captured.CompletedAt = captured.StartedAt
	if len(fired) == 0 {
		if _, err := h.conn.PushFlow(ctx, captured); err != nil {
			return nil, nil, err
		}
		return body, headers, nil
	}

	mutated := captured
	mutated.Request = &wire.FlowMessage{Method: req.Method, Path: req.URL.Path, Headers: mutHeaders, Body: mutBody}
	if _, err := h.conn.PushFlow(ctx, mutated); err != nil {
		return nil, nil, err
	}
	return mutBody, mutHeaders, nil
}

// captureResponse buffers the upstream response, emits the response flow
// (mutated when a rule fires), and builds the client-facing response.
func (h *Handler) captureResponse(ctx context.Context, tunnelID string, resp *http.Response) (*http.Response, error) {
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	headers := responseHeaders(resp)

	mutBody, firedBody := h.conn.Rules().ApplyBody(body, wire.RuleTypeResponseBody)
	pseudo, regular := bulk.SliceSplit(isPseudoHeader, headers)
	mutRegular, firedHdr := h.conn.Rules().ApplyHeaders(regular, wire.RuleTypeResponseHeader)
	mutHeaders := slices.Concat(mutRegular, pseudo)
	fired := slices.Concat(firedBody, firedHdr)

	captured := wire.Flow{
		ProtocolTag:  controlProtocolTag,
		Direction:    adapter.DirServerToClient,
		ParentFlowID: tunnelID,
		Response:     &wire.FlowMessage{StatusCode: resp.StatusCode, Headers: headers, Body: body},
		StartedAt:    time.Now(),
	}
	captured.CompletedAt = captured.StartedAt
	outBody, outHeaders := body, headers
	if len(fired) == 0 {
		if _, err := h.conn.PushFlow(ctx, captured); err != nil {
			return nil, err
		}
	} else {
		mutated := captured
		mutated.Response = &wire.FlowMessage{StatusCode: resp.StatusCode, Headers: mutHeaders, Body: mutBody}
		if _, err := h.conn.PushFlow(ctx, mutated); err != nil {
			return nil, err
		}
		outBody, outHeaders = mutBody, mutHeaders
	}
	return clientResponse(resp, outHeaders, outBody), nil
}

// isPseudoHeader reports whether an HTTP/2 header is a pseudo-header (":"-prefixed).
func isPseudoHeader(h wire.Header) bool { return strings.HasPrefix(h.Name, ":") }

// hopHeaders are connection-specific headers dropped when re-emitting a message.
var hopHeaders = map[string]struct{}{
	"connection": {}, "keep-alive": {}, "proxy-connection": {},
	"transfer-encoding": {}, "upgrade": {}, "content-length": {}, "host": {},
}

// requestHeaders renders the inner request as HTTP/2 pseudo-headers plus regular
// headers (pseudo-headers prefixed with ':').
func requestHeaders(req *http.Request) []wire.Header {
	out := []wire.Header{
		{Name: ":method", Value: req.Method},
		{Name: ":path", Value: req.URL.RequestURI()},
		{Name: ":authority", Value: req.Host},
		{Name: ":scheme", Value: "https"},
	}
	return appendHTTPHeaders(out, req.Header)
}

// responseHeaders renders the response status pseudo-header plus regular headers.
func responseHeaders(resp *http.Response) []wire.Header {
	out := []wire.Header{{Name: ":status", Value: strconv.Itoa(resp.StatusCode)}}
	return appendHTTPHeaders(out, resp.Header)
}

// setResponseHeaders replaces resp.Header with the regular headers, so header-rule
// mutations reach the client-facing streaming response ServeCapture relays from it.
func setResponseHeaders(resp *http.Response, headers []wire.Header) {
	hdr := http.Header{}
	for _, h := range headers {
		if strings.HasPrefix(h.Name, ":") {
			continue
		}
		hdr.Add(h.Name, h.Value)
	}
	resp.Header = hdr
}

func appendHTTPHeaders(out []wire.Header, hdr http.Header) []wire.Header {
	for name, values := range hdr {
		for _, v := range values {
			out = append(out, wire.Header{Name: name, Value: v})
		}
	}
	return out
}

// buildUpstreamRequest constructs the outbound HTTP/2 request from captured headers
// and body, dropping pseudo and hop-by-hop headers.
func buildUpstreamRequest(ctx context.Context, controlHost string, headers []wire.Header, body []byte) (*http.Request, error) {
	method, path := "GET", "/"
	hdr := http.Header{}
	for _, h := range headers {
		switch {
		case h.Name == ":method":
			method = h.Value
		case h.Name == ":path":
			path = h.Value
		case strings.HasPrefix(h.Name, ":"):
			// other pseudo-headers are derived from the URL
		case isHopHeader(h.Name):
		default:
			hdr.Add(h.Name, h.Value)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://"+controlHost+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header = hdr
	req.ContentLength = int64(len(body))
	return req, nil
}

// clientResponse builds the response relayed to the client from captured headers
// and body, dropping pseudo and hop-by-hop headers.
func clientResponse(upstream *http.Response, headers []wire.Header, body []byte) *http.Response {
	hdr := http.Header{}
	for _, h := range headers {
		if strings.HasPrefix(h.Name, ":") || isHopHeader(h.Name) {
			continue
		}
		hdr.Add(h.Name, h.Value)
	}
	return &http.Response{
		StatusCode:    upstream.StatusCode,
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		Header:        hdr,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

func isHopHeader(name string) bool {
	_, ok := hopHeaders[strings.ToLower(name)]
	return ok
}

// isStreamingMap reports if an inner request is a streaming /machine/map, signaled by Stream:true in the MapRequest body.
func isStreamingMap(path string, body []byte) bool {
	if path != mapEndpoint {
		return false
	}
	var mr struct {
		Stream bool `json:"Stream"`
	}
	return json.Unmarshal(body, &mr) == nil && mr.Stream
}
