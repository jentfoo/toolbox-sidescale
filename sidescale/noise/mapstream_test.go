//go:build unix

package noise

import (
	"bytes"
	"encoding/binary"
	"io"
	"slices"
	"testing"
	"time"

	"github.com/go-analyze/bulk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	scsidecar "github.com/go-appsec/toolbox/sectool/service/proxy/protocol/sidecar"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sidecar/wire"
	"github.com/jentfoo/toolbox-sidescale/sidescale/adapter"
	"github.com/jentfoo/toolbox-sidescale/sidescale/tsproto"
)

func streamChildren(flows []*types.Flow, parentID string) []*types.Flow {
	return bulk.SliceFilter(func(f *types.Flow) bool {
		return f.ProtocolTag == streamProtocolTag && f.ParentFlowID == parentID
	}, flows)
}

func TestMapStreamReader(t *testing.T) {
	t.Parallel()

	cfg, err := defaultControlConfig()
	require.NoError(t, err)

	frames := slices.Concat(
		tsproto.EncodeMapResponseFrame([]byte(`{"Node":{"Name":"a"}}`), true),
		tsproto.EncodeMapResponseFrame([]byte(`{"Node":{"Name":"b"}}`), true),
	)

	t.Run("no_rule_forwards_verbatim_ordered", func(t *testing.T) {
		flows := newRecordingFlows()
		h := testHandler(t, &cfg, flows, noopCore{}, stubRules{}, scsidecar.Config{})
		parentID, err := h.conn.PushFlow(t.Context(), wire.Flow{ProtocolTag: streamProtocolTag, Direction: adapter.DirServerToClient, StartedAt: time.Now()})
		require.NoError(t, err)

		r := newMapStreamReader(t.Context(), h, io.NopCloser(bytes.NewReader(frames)), parentID)
		out, err := io.ReadAll(r)
		require.NoError(t, err)
		require.NoError(t, r.Close())
		assert.Equal(t, frames, out) // unmutated frames pass through byte-for-byte

		children := streamChildren(flows.list(), parentID)
		require.Len(t, children, 2)
		assert.Equal(t, adapter.DirServerToClient, children[0].Direction)
		assert.Contains(t, string(children[0].Response.Body), `"Name":"a"`)
		assert.Contains(t, string(children[1].Response.Body), `"Name":"b"`) // arrival order preserved
		assert.NotEmpty(t, children[0].Response.Headers.Get(compressedBytesHeader))
		assert.NotEmpty(t, children[0].Response.Headers.Get(compressedLenHeader))
		assert.True(t, flows.wasCompleted(parentID)) // two-phase close
	})

	t.Run("rejects_oversized_frame", func(t *testing.T) {
		flows := newRecordingFlows()
		h := testHandler(t, &cfg, flows, noopCore{}, stubRules{}, scsidecar.Config{})
		parentID, err := h.conn.PushFlow(t.Context(), wire.Flow{ProtocolTag: streamProtocolTag, Direction: adapter.DirServerToClient, StartedAt: time.Now()})
		require.NoError(t, err)

		// a length prefix over the cap must fail at the buffering seam, not buffer unbounded
		var prefix [mapFramePrefixLen]byte
		binary.LittleEndian.PutUint32(prefix[:], tsproto.MaxMapFrameBytes+1)
		r := newMapStreamReader(t.Context(), h, io.NopCloser(bytes.NewReader(prefix[:])), parentID)
		_, err = io.ReadAll(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds max")
	})

	t.Run("rule_mutates_chunk_end_to_end", func(t *testing.T) {
		flows := newRecordingFlows()
		rules := stubRules{rules: []wire.Rule{{RuleID: "r1", Type: wire.RuleTypeResponseBody, Find: "linux", Replace: "darwin"}}}
		h := testHandler(t, &cfg, flows, noopCore{}, rules, scsidecar.Config{})
		parentID, err := h.conn.PushFlow(t.Context(), wire.Flow{ProtocolTag: streamProtocolTag, Direction: adapter.DirServerToClient, StartedAt: time.Now()})
		require.NoError(t, err)

		in := tsproto.EncodeMapResponseFrame([]byte(`{"Node":{"OS":"linux"}}`), true)
		r := newMapStreamReader(t.Context(), h, io.NopCloser(bytes.NewReader(in)), parentID)
		out, err := io.ReadAll(r)
		require.NoError(t, err)
		require.NoError(t, r.Close())

		// re-encoded output decodes to the mutated JSON
		payload, compressed, _, ok, err := tsproto.DecodeMapResponseFrame(out)
		require.NoError(t, err)
		require.True(t, ok)
		assert.True(t, compressed) // source frame was zstd; re-encode preserves it
		assert.Contains(t, string(payload), `"OS":"darwin"`)

		// only the mutated child is emitted, mirroring the native proxy
		children := streamChildren(flows.list(), parentID)
		require.Len(t, children, 1)
		assert.Contains(t, string(children[0].Response.Body), `"OS":"darwin"`)
	})

	t.Run("uncompressed_stream_captured", func(t *testing.T) {
		flows := newRecordingFlows()
		h := testHandler(t, &cfg, flows, noopCore{}, stubRules{}, scsidecar.Config{})
		parentID, err := h.conn.PushFlow(t.Context(), wire.Flow{ProtocolTag: streamProtocolTag, Direction: adapter.DirServerToClient, StartedAt: time.Now()})
		require.NoError(t, err)

		// a server that did not honor Compress:zstd sends raw-JSON frames
		in := tsproto.EncodeMapResponseFrame([]byte(`{"Node":{"Name":"raw"}}`), false)
		r := newMapStreamReader(t.Context(), h, io.NopCloser(bytes.NewReader(in)), parentID)
		out, err := io.ReadAll(r)
		require.NoError(t, err)
		require.NoError(t, r.Close())
		assert.Equal(t, in, out) // unmutated raw frame forwarded verbatim

		children := streamChildren(flows.list(), parentID)
		require.Len(t, children, 1)
		assert.Contains(t, string(children[0].Response.Body), `"Name":"raw"`)
	})

	t.Run("uncompressed_rule_reencode_stays_raw", func(t *testing.T) {
		flows := newRecordingFlows()
		rules := stubRules{rules: []wire.Rule{{RuleID: "r1", Type: wire.RuleTypeResponseBody, Find: "linux", Replace: "darwin"}}}
		h := testHandler(t, &cfg, flows, noopCore{}, rules, scsidecar.Config{})
		parentID, err := h.conn.PushFlow(t.Context(), wire.Flow{ProtocolTag: streamProtocolTag, Direction: adapter.DirServerToClient, StartedAt: time.Now()})
		require.NoError(t, err)

		in := tsproto.EncodeMapResponseFrame([]byte(`{"Node":{"OS":"linux"}}`), false)
		r := newMapStreamReader(t.Context(), h, io.NopCloser(bytes.NewReader(in)), parentID)
		out, err := io.ReadAll(r)
		require.NoError(t, err)
		require.NoError(t, r.Close())

		// mutated frame must stay uncompressed so a non-zstd client can still decode it
		payload, compressed, _, ok, err := tsproto.DecodeMapResponseFrame(out)
		require.NoError(t, err)
		require.True(t, ok)
		assert.False(t, compressed)
		assert.Contains(t, string(payload), `"OS":"darwin"`)
	})
}
