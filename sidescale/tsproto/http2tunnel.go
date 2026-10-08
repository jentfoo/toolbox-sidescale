package tsproto

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// Inner HTTP/2 pseudo-header field names carried on captured control messages.
const (
	HdrMethod    = ":method"
	HdrPath      = ":path"
	HdrAuthority = ":authority"
	HdrScheme    = ":scheme"
	HdrStatus    = ":status"
)

// CaptureFunc handles one inner request from the client-facing side and returns the response to relay back.
// The response Body is streamed to the client and closed by the bridge.
type CaptureFunc func(req *http.Request) (*http.Response, error)

// H2Bridge bridges inner HTTP/2 between a client-facing connection (server side) and an
// upstream connection (client side), both prior-knowledge HTTP/2 over a plaintext Noise byte stream.
type H2Bridge struct {
	upstream *http.ClientConn
}

// NewH2Bridge returns a bridge whose upstream client speaks over upstreamConn.
// ctx scopes connection setup; the conn itself outlives it.
func NewH2Bridge(ctx context.Context, upstreamConn net.Conn) (*H2Bridge, error) {
	// explicit Protocols opts into h2c prior knowledge despite the custom dialer;
	// keepalive PINGs: control closes an idle /ts2021 conn (~10s), which would
	// break the ClientConn before the first inner request
	tr := &http.Transport{
		Protocols: &http.Protocols{},
		HTTP2:     &http.HTTP2Config{SendPingTimeout: 5 * time.Second},
	}
	tr.Protocols.SetUnencryptedHTTP2(true)
	tr.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return upstreamConn, nil
	}
	cc, err := tr.NewClientConn(ctx, "http", "noise-upstream:443")
	if err != nil {
		return nil, err
	}
	return &H2Bridge{upstream: cc}, nil
}

// Forward sends req upstream and returns the response.
func (b *H2Bridge) Forward(req *http.Request) (*http.Response, error) {
	return b.upstream.RoundTrip(req)
}

// Usable reports whether the upstream connection can still serve requests.
// A drained conn (GOAWAY) reads usable until it hard-closes, so forwardTunnel
// heals one request after the server stops accepting new streams.
func (b *H2Bridge) Usable() bool {
	return b.upstream.Err() == nil
}

// Close shuts down the upstream HTTP/2 client connection.
func (b *H2Bridge) Close() error {
	return b.upstream.Close()
}

// ServeCapture serves the client-facing side over clientConn until the conn closes
// or ctx is canceled, routing each inner request through capture
func (b *H2Bridge) ServeCapture(ctx context.Context, clientConn net.Conn, capture CaptureFunc) {
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
	_ = ServeH2Conn(ctx, clientConn, h)
}

// ServeH2Conn serves prior-knowledge HTTP/2 on conn until the conn closes or ctx is
// canceled. It returns nil once the conn is done serving, ctx.Err when canceled, and
// the underlying serve error otherwise. Request contexts derive from ctx via the
// server BaseContext.
func ServeH2Conn(ctx context.Context, conn net.Conn, h http.Handler) error {
	srv := &http.Server{Handler: h, Protocols: &http.Protocols{}}
	srv.Protocols.SetUnencryptedHTTP2(true)
	srv.BaseContext = func(net.Listener) context.Context { return ctx }
	l := newSingleConnListener(conn)
	served := make(chan error, 1)
	go func() { served <- srv.Serve(l) }()
	select {
	case err := <-served:
		if errors.Is(err, errConnServed) {
			return nil // the one conn closed: routine teardown, not a serve failure
		}
		return err
	case <-ctx.Done():
		_ = l.conn.Close() // ends the served conn and the pending Accept
		<-served
		return ctx.Err()
	}
}

// errConnServed ends the serve loop once the listener's one conn is done being
// served; ServeH2Conn maps it to nil since it is routine teardown, not a failure.
var errConnServed = errors.New("tsproto: conn finished serving")

// singleConnListener feeds one pre-established conn to http.Server.Serve. Accept
// hands the conn out once, then blocks until it is done being served before
// reporting errConnServed, so ServeH2Conn stays blocked for the conn's lifetime.
type singleConnListener struct {
	conn net.Conn
	done chan struct{}
	used bool
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	l := &singleConnListener{done: make(chan struct{})}
	l.conn = &closeNotifyConn{Conn: conn, onClose: sync.OnceFunc(func() { close(l.done) })}
	return l
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.used {
		<-l.done
		return nil, errConnServed
	}
	l.used = true
	return l.conn, nil
}

// Close is a no-op, the caller owns the served conn.
func (l *singleConnListener) Close() error { return nil }

func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

// closeNotifyConn fires onClose when Close is called, marking the conn done
// being served.
type closeNotifyConn struct {
	net.Conn
	onClose func()
}

func (c *closeNotifyConn) Close() error {
	c.onClose()
	return c.Conn.Close()
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
