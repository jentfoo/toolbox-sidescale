//go:build unix

package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jentfoo/toolbox-sidescale/sidescale/noise"
)

// shortenReconnect swaps the reconnect pacing for test-scale values, restoring the
// originals at cleanup. Tests using it are not parallel (shared package vars).
func shortenReconnect(t *testing.T, initial, max, stable, window time.Duration) {
	t.Helper()

	oi, om, ostable, owindow := reconnectInitial, reconnectMax, reconnectStable, reconnectWindow
	reconnectInitial, reconnectMax, reconnectStable, reconnectWindow = initial, max, stable, window
	t.Cleanup(func() { reconnectInitial, reconnectMax, reconnectStable, reconnectWindow = oi, om, ostable, owindow })
}

// borrowConfig returns the default config under borrow, where Setup is a no-op, so the
// tests drive reconnect pacing rather than keysub.
func borrowConfig(t *testing.T) Config {
	t.Helper()

	cfg, err := LoadConfig("")
	require.NoError(t, err)
	cfg.Control.KeyStrategy = noise.KeyStrategyBorrow
	return cfg
}

// serveAsync runs serveForever in a goroutine, returning the completion channel and the
// signal-context cancel.
func serveAsync(t *testing.T, cfg Config, socket string) (chan error, context.CancelFunc) {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)
	go func() { errCh <- serveForever(ctx, cfg, socket, keyMaterial{}, testInstanceID) }()
	t.Cleanup(cancel)
	return errCh, cancel
}

func TestServeForever(t *testing.T) { // not parallel: shortens the shared pacing vars
	t.Run("reconnects_after_host_restart", func(t *testing.T) {
		shortenReconnect(t, 5*time.Millisecond, 20*time.Millisecond, 50*time.Millisecond, 5*time.Second)

		cfg := borrowConfig(t)
		socket := filepath.Join(t.TempDir(), "sidecar.sock")
		lst1, mgr1, _ := startHost(t, socket)
		errCh, cancel := serveAsync(t, cfg, socket)

		require.Eventually(t, func() bool { return mgr1.Count() == 1 }, 2*time.Second, 5*time.Millisecond)

		// a sectool restart: the session drops and the socket rebinds under a fresh host
		require.NoError(t, lst1.Close(context.Background()))
		require.Eventually(t, func() bool { return mgr1.Count() == 0 }, 2*time.Second, 5*time.Millisecond)
		_, mgr2, _ := startHost(t, socket)

		require.Eventually(t, func() bool { return mgr2.Count() == 1 }, 5*time.Second, 10*time.Millisecond)
		rec, ok := mgr2.Get(cfg.Name)
		require.True(t, ok)
		assert.Equal(t, testInstanceID, rec.InstanceID) // the stable id reattaches ownership

		cancel()
		select {
		case err := <-errCh:
			require.NoError(t, err) // signal exit stays clean
		case <-time.After(2 * time.Second):
			t.Fatal("serveForever did not return on signal")
		}
	})

	t.Run("first_dial_failure_fatal", func(t *testing.T) {
		cfg := borrowConfig(t)
		socket := filepath.Join(t.TempDir(), "missing.sock")

		// nothing is listening and no session ever served: a startup problem, not an outage
		err := serveForever(t.Context(), cfg, socket, keyMaterial{}, testInstanceID)
		require.ErrorContains(t, err, "dial sectool")
	})

	t.Run("window_exhaustion_exits_nonzero", func(t *testing.T) {
		shortenReconnect(t, 5*time.Millisecond, 20*time.Millisecond, 50*time.Millisecond, 150*time.Millisecond)

		cfg := borrowConfig(t)
		socket := filepath.Join(t.TempDir(), "sidecar.sock")
		lst, mgr, _ := startHost(t, socket)
		errCh, _ := serveAsync(t, cfg, socket)

		require.Eventually(t, func() bool { return mgr.Count() == 1 }, 2*time.Second, 5*time.Millisecond)
		require.NoError(t, lst.Close(context.Background())) // the host is gone for good

		select {
		case err := <-errCh:
			require.ErrorContains(t, err, "no healthy sectool session") // exit nonzero
		case <-time.After(3 * time.Second):
			t.Fatal("serveForever did not exhaust the outage window")
		}
	})
}
