package tsproto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeMapResponseFrame(t *testing.T) {
	t.Parallel()

	payloads := map[string]string{
		"json_object": `{"Node":{"Name":"host"}}`,
		"empty":       ``,
		"zero_object": `{}`,
	}
	for name, payload := range payloads {
		for _, compress := range []bool{true, false} {
			mode := "raw"
			if compress {
				mode = "zstd"
			}
			t.Run(name+"_"+mode, func(t *testing.T) {
				frame := EncodeMapResponseFrame([]byte(payload), compress)
				got, gotCompressed, consumed, ok, err := DecodeMapResponseFrame(frame)
				require.NoError(t, err)
				require.True(t, ok)
				assert.Equal(t, compress, gotCompressed)
				assert.Equal(t, len(frame), consumed)
				assert.Equal(t, payload, string(got))
			})
		}
	}

	t.Run("incomplete_length_prefix", func(t *testing.T) {
		_, _, _, ok, err := DecodeMapResponseFrame([]byte{0x01, 0x02})
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("incomplete_payload", func(t *testing.T) {
		frame := EncodeMapResponseFrame([]byte(`{"k":"v"}`), true)
		_, _, _, ok, err := DecodeMapResponseFrame(frame[:len(frame)-1])
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("trailing_frame_boundary", func(t *testing.T) {
		frame := EncodeMapResponseFrame([]byte(`{"a":1}`), true)
		_, _, consumed, ok, err := DecodeMapResponseFrame(append(frame, "next"...))
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, len(frame), consumed)
	})

	t.Run("raw_frame_not_mistaken_for_zstd", func(t *testing.T) {
		// a raw JSON body must round-trip as uncompressed
		frame := EncodeMapResponseFrame([]byte(`{"raw":true}`), false)
		got, compressed, _, ok, err := DecodeMapResponseFrame(frame)
		require.NoError(t, err)
		require.True(t, ok)
		assert.False(t, compressed)
		assert.Equal(t, `{"raw":true}`, string(got))
	})
}
