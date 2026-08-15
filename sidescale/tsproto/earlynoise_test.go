package tsproto

import (
	"bufio"
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"tailscale.com/types/key"
)

// earlyNoiseFrame builds an EarlyNoise message and its encoded frame for decode tests.
func earlyNoiseFrame(t *testing.T) (*EarlyNoise, []byte) {
	t.Helper()
	msg := &EarlyNoise{NodeKeyChallenge: key.NewChallenge().Public()}
	frame, err := EncodeEarlyNoise(msg)
	require.NoError(t, err)
	return msg, frame
}

func TestDecodeEarlyNoise(t *testing.T) {
	t.Parallel()

	msg, frame := earlyNoiseFrame(t)

	t.Run("round_trip", func(t *testing.T) {
		got, consumed, ok, derr := DecodeEarlyNoise(frame)
		require.NoError(t, derr)
		require.True(t, ok)
		assert.Equal(t, len(frame), consumed)
		assert.Equal(t, msg.NodeKeyChallenge, got.NodeKeyChallenge)
	})

	t.Run("incomplete_buffer", func(t *testing.T) {
		_, _, ok, derr := DecodeEarlyNoise(frame[:len(frame)-1])
		require.NoError(t, derr)
		assert.False(t, ok)
	})

	t.Run("trailing_bytes_preserved", func(t *testing.T) {
		_, consumed, ok, derr := DecodeEarlyNoise(append(frame, "extra"...))
		require.NoError(t, derr)
		require.True(t, ok)
		assert.Equal(t, len(frame), consumed)
	})

	t.Run("bad_magic", func(t *testing.T) {
		bad := append([]byte("xxxxx"), frame[5:]...)
		_, _, ok, derr := DecodeEarlyNoise(bad)
		require.Error(t, derr)
		assert.False(t, ok)
	})
}

func TestReadEarlyNoise(t *testing.T) {
	t.Parallel()

	msg, frame := earlyNoiseFrame(t)

	t.Run("reads_frame_leaves_trailing", func(t *testing.T) {
		data := append(append([]byte{}, frame...), "H2DATA"...)
		br := bufio.NewReader(bytes.NewReader(data))
		raw, got, ok, rerr := ReadEarlyNoise(br)
		require.NoError(t, rerr)
		require.True(t, ok)
		assert.Equal(t, frame, raw)
		assert.Equal(t, msg.NodeKeyChallenge, got.NodeKeyChallenge)
		rest, _ := io.ReadAll(br)
		assert.Equal(t, "H2DATA", string(rest))
	})

	t.Run("no_early_noise_leaves_bytes", func(t *testing.T) {
		// leading bytes are not the magic (e.g. an HTTP/2 SETTINGS frame header)
		data := []byte{0x00, 0x00, 0x12, 0x04, 0x00}
		br := bufio.NewReader(bytes.NewReader(data))
		_, _, ok, rerr := ReadEarlyNoise(br)
		require.NoError(t, rerr)
		assert.False(t, ok)
		rest, _ := io.ReadAll(br)
		assert.Equal(t, data, rest)
	})

	t.Run("eof_is_not_error", func(t *testing.T) {
		br := bufio.NewReader(bytes.NewReader(nil))
		_, _, ok, rerr := ReadEarlyNoise(br)
		require.NoError(t, rerr)
		assert.False(t, ok)
	})
}
