package tsproto

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// h2EchoHandler answers every request with the method, path, body length, and X-Probe header.
func h2EchoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Upstream", "seen")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "%s %s bytes=%d probe=%s", r.Method, r.URL.Path, len(body), r.Header.Get("X-Probe"))
	})
}

// h2ClientConn returns a prior-knowledge HTTP/2 client conn wired to speak to a
// single server-side conn, so tests drive requests at a served connection.
func h2ClientConn(ctx context.Context, t *testing.T, served net.Conn) *http.ClientConn {
	t.Helper()

	tr := &http.Transport{Protocols: &http.Protocols{}}
	tr.Protocols.SetUnencryptedHTTP2(true)
	tr.DialContext = func(context.Context, string, string) (net.Conn, error) { return served, nil }
	cc, err := tr.NewClientConn(ctx, "http", "client:443")
	require.NoError(t, err)
	return cc
}

// h2RoundTrip sends one probe request over cc, returning the echoed body text.
func h2RoundTrip(ctx context.Context, t *testing.T, cc *http.ClientConn, path string) string {
	t.Helper()

	req, err := http.NewRequestWithContext(ctx, "POST", "https://client"+path, strings.NewReader("hello-body"))
	require.NoError(t, err)
	req.Header.Set("X-Probe", "p1")
	req.URL.Scheme = "https" // scheme feeds the h2 :scheme pseudo-header

	resp, err := cc.RoundTrip(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "seen", resp.Header.Get("X-Upstream"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}

func TestH2Bridge(t *testing.T) {
	t.Parallel()

	// upstream HTTP/2 server: echoes method+path and the request body length
	var lc net.ListenConfig
	upLn, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = upLn.Close() })
	go func() {
		conn, aerr := upLn.Accept()
		if aerr != nil {
			return
		}
		_ = ServeH2Conn(t.Context(), conn, h2EchoHandler())
	}()

	var d net.Dialer
	upConn, err := d.DialContext(t.Context(), "tcp", upLn.Addr().String())
	require.NoError(t, err)
	bridge, err := NewH2Bridge(t.Context(), upConn)
	require.NoError(t, err)

	// client-facing side: ServeCapture forwards each request upstream verbatim
	var clLc net.ListenConfig
	clLn, err := clLc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = clLn.Close() })
	go func() {
		conn, aerr := clLn.Accept()
		if aerr != nil {
			return
		}
		bridge.ServeCapture(t.Context(), conn, func(req *http.Request) (*http.Response, error) {
			out, oerr := http.NewRequestWithContext(req.Context(), req.Method, "http://upstream"+req.URL.Path, req.Body)
			if oerr != nil {
				return nil, oerr
			}
			out.Header.Set("X-Probe", req.Header.Get("X-Probe"))
			return bridge.Forward(out)
		})
	}()

	var clDialer net.Dialer
	clConn, err := clDialer.DialContext(t.Context(), "tcp", clLn.Addr().String())
	require.NoError(t, err)
	cc := h2ClientConn(t.Context(), t, clConn)

	assert.Equal(t, "POST /machine/register bytes=10 probe=p1", h2RoundTrip(t.Context(), t, cc, "/machine/register"))
}

func TestServeH2Conn(t *testing.T) {
	t.Parallel()

	pipe := func(t *testing.T) (client net.Conn, server net.Conn) {
		t.Helper()
		client, server = net.Pipe()
		t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
		return client, server
	}

	t.Run("blocks_across_requests", func(t *testing.T) {
		client, server := pipe(t)
		done := make(chan error, 1)
		go func() { done <- ServeH2Conn(t.Context(), server, h2EchoHandler()) }()

		cc := h2ClientConn(t.Context(), t, client)
		first := h2RoundTrip(t.Context(), t, cc, "/machine/map")
		assert.Equal(t, "POST /machine/map bytes=10 probe=p1", first)

		// the second request rides the same served conn, proving it stayed live
		second := h2RoundTrip(t.Context(), t, cc, "/machine/map")
		assert.Equal(t, "POST /machine/map bytes=10 probe=p1", second)
	})

	t.Run("returns_on_client_close", func(t *testing.T) {
		client, server := pipe(t)
		done := make(chan error, 1)
		go func() { done <- ServeH2Conn(t.Context(), server, h2EchoHandler()) }()

		cc := h2ClientConn(t.Context(), t, client)
		_ = h2RoundTrip(t.Context(), t, cc, "/machine/map")

		require.NoError(t, client.Close())
		select {
		case err := <-done:
			require.NoError(t, err) // routine client teardown, not a serve failure
		case <-time.After(5 * time.Second):
			t.Fatal("ServeH2Conn did not return after client close")
		}
	})

	t.Run("cancel_closes_served_conn", func(t *testing.T) {
		client, server := pipe(t)
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)
		done := make(chan error, 1)
		go func() { done <- ServeH2Conn(ctx, server, h2EchoHandler()) }()

		cc := h2ClientConn(t.Context(), t, client)
		_ = h2RoundTrip(t.Context(), t, cc, "/machine/map")
		cancel()

		// ServeH2Conn reports ctx.Err and the client sees the closed conn
		select {
		case err := <-done:
			require.ErrorIs(t, err, context.Canceled)
		case <-time.After(5 * time.Second):
			t.Fatal("ServeH2Conn did not return after ctx cancel")
		}
		_, err := client.Write([]byte("ping"))
		require.Error(t, err)
	})

	t.Run("closed_conn_returns_nil", func(t *testing.T) {
		client, server := pipe(t)
		require.NoError(t, client.Close())

		// the dead conn ends serving promptly with nil, not a hang
		done := make(chan error, 1)
		go func() { done <- ServeH2Conn(t.Context(), server, h2EchoHandler()) }()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("ServeH2Conn did not return for a closed conn")
		}
	})
}
