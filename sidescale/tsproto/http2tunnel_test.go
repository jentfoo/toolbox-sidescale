package tsproto

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

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
		(&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				w.Header().Set("X-Upstream", "seen")
				w.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprintf(w, "%s %s bytes=%d probe=%s", r.Method, r.URL.Path, len(body), r.Header.Get("X-Probe"))
			}),
		})
	}()

	var d net.Dialer
	upConn, err := d.DialContext(t.Context(), "tcp", upLn.Addr().String())
	require.NoError(t, err)
	bridge, err := NewH2Bridge(upConn)
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
		bridge.ServeCapture(conn, func(req *http.Request) (*http.Response, error) {
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
	cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(clConn)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(t.Context(), "POST", "http://client/machine/register", strings.NewReader("hello-body"))
	require.NoError(t, err)
	req.Header.Set("X-Probe", "p1")
	req.URL.Scheme = "https" // ClientConn round-trip requires a scheme

	resp, err := cc.RoundTrip(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "seen", resp.Header.Get("X-Upstream"))
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "POST /machine/register bytes=10 probe=p1", string(body))
}
