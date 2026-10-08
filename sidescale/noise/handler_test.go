package noise

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWaitSetup(t *testing.T) {
	t.Parallel()

	cfg, err := defaultControlConfig() // substitute + responder defaults
	require.NoError(t, err)

	t.Run("blocks_until_setup_finishes", func(t *testing.T) {
		h := &Handler{cfg: cfg, setupDone: make(chan struct{})}

		done := make(chan error, 1)
		go func() { done <- h.waitSetup(t.Context()) }()
		require.Never(t, func() bool {
			select {
			case <-done:
				return true
			default:
				return false
			}
		}, 150*time.Millisecond, 25*time.Millisecond)

		close(h.setupDone) // Setup's completion signal
		require.NoError(t, <-done)
	})

	t.Run("returns_setup_error", func(t *testing.T) {
		h := &Handler{cfg: cfg, setupDone: make(chan struct{}), setupErr: errors.New("keysub boom")}
		close(h.setupDone)

		assert.ErrorContains(t, h.waitSetup(t.Context()), "keysub boom")
	})

	t.Run("bounded_by_ctx", func(t *testing.T) {
		h := &Handler{cfg: cfg, setupDone: make(chan struct{})}

		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		assert.ErrorIs(t, h.waitSetup(ctx), context.Canceled)
	})

	t.Run("borrow_passes_without_setup", func(t *testing.T) {
		borrowCfg, err := defaultControlConfig()
		require.NoError(t, err)
		borrowCfg.KeyStrategy = KeyStrategyBorrow
		h := &Handler{cfg: borrowCfg} // setupDone never closed

		assert.NoError(t, h.waitSetup(t.Context()))
	})
}
