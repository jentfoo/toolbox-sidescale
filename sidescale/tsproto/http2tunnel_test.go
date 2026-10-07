package tsproto

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		_ = ServeH2Conn(t.Context(), conn, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("X-Upstream", "seen")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, "%s %s bytes=%d probe=%s", r.Method, r.URL.Path, len(body), r.Header.Get("X-Probe"))
		}))
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
	clTr := &http.Transport{Protocols: &http.Protocols{}}
	clTr.Protocols.SetUnencryptedHTTP2(true)
	clTr.DialContext = func(context.Context, string, string) (net.Conn, error) { return clConn, nil }
	cc, err := clTr.NewClientConn(t.Context(), "http", "client:443")
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(t.Context(), "POST", "http://client/machine/register", strings.NewReader("hello-body"))
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
	assert.Equal(t, "POST /machine/register bytes=10 probe=p1", string(body))
}
