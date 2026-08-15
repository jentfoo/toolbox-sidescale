package tsproto

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitiationVersion(t *testing.T) {
	t.Parallel()

	t.Run("reads_be_version", func(t *testing.T) {
		init := make([]byte, 4)
		binary.BigEndian.PutUint16(init[:2], 141)
		v, err := InitiationVersion(init)
		require.NoError(t, err)
		assert.Equal(t, uint16(141), v)
	})

	t.Run("too_short", func(t *testing.T) {
		_, err := InitiationVersion([]byte{0x00})
		assert.ErrorContains(t, err, "too short")
	})
}
