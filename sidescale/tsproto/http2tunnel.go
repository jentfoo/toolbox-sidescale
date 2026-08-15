package tsproto

import (
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

// CaptureFunc handles one inner request from the client-facing side and returns the response to relay back.
// The response Body is streamed to the client and closed by the bridge.
type CaptureFunc func(req *http.Request) (*http.Response, error)

// H2Bridge bridges inner HTTP/2 between a client-facing connection (server side) and an
// upstream connection (client side), both prior-knowledge HTTP/2 over a plaintext Noise byte stream.
type H2Bridge struct {
	upstream *http2.ClientConn
	server   *http2.Server
}

// NewH2Bridge returns a bridge whose upstream client speaks over upstreamConn.
func NewH2Bridge(upstreamConn net.Conn) (*H2Bridge, error) {
	// keepalive PINGs: control closes an idle /ts2021 conn (~10s), which would break
	// the ClientConn before the first inner request
	tr := &http2.Transport{AllowHTTP: true, ReadIdleTimeout: 5 * time.Second}
	cc, err := tr.NewClientConn(upstreamConn)
	if err != nil {
		return nil, err
	}
	return &H2Bridge{upstream: cc, server: &http2.Server{}}, nil
}

// Forward sends req upstream and returns the response.
func (b *H2Bridge) Forward(req *http.Request) (*http.Response, error) {
	return b.upstream.RoundTrip(req)
}

// Usable reports whether the upstream connection can still serve requests.
func (b *H2Bridge) Usable() bool {
	st := b.upstream.State()
	return !st.Closed && !st.Closing
}

// Close shuts down the upstream HTTP/2 client connection.
func (b *H2Bridge) Close() error {
	return b.upstream.Close()
}

// ServeCapture serves the client-facing side over clientConn,
// routing each inner request through capture, until the connection closes
func (b *H2Bridge) ServeCapture(clientConn net.Conn, capture CaptureFunc) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := capture(r)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		flushingCopy(w, resp.Body)
	})
	b.server.ServeConn(clientConn, &http2.ServeConnOpts{Handler: h})
}

// flushingCopy relays src to w, flushing after each read so streamed frames reach the client promptly.
func flushingCopy(w http.ResponseWriter, src io.Reader) {
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if rerr != nil {
			return
		}
	}
}
