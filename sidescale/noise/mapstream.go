package noise

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-appsec/toolbox/sidecar"
	"github.com/go-appsec/toolbox/sidecar/wire"
	"github.com/jentfoo/toolbox-sidescale/sidescale/adapter"
	"github.com/jentfoo/toolbox-sidescale/sidescale/tsproto"
)

const (
	// mapFramePrefixLen is the little-endian length prefix preceding each zstd frame.
	mapFramePrefixLen = 4
	// compressed-frame metadata carried on each captured chunk.
	compressedBytesHeader = "X-Sectool-Compressed-Bytes"
	compressedLenHeader   = "X-Sectool-Compressed-Len"
)

// mapStreamReader reads a MapResponse body, emitting each zstd frame as an ordered
// child flow of parentID and returning the (possibly rule-mutated) frame to the
// client. Reading it to EOF or closing it completes the stream parent.
type mapStreamReader struct {
	ctx      context.Context
	h        *Handler
	upstream io.ReadCloser
	parentID string

	re       sidecar.Reassembler
	pending  []byte // re-encoded bytes not yet delivered to the client
	done     bool   // upstream reached EOF
	finished bool   // parent already completed
	frameErr error  // set by split when a length prefix exceeds the cap
}

// newMapStreamReader returns a reader over a streaming MapResponse body whose child
// chunks are captured under parentID.
func newMapStreamReader(ctx context.Context, h *Handler, upstream io.ReadCloser, parentID string) *mapStreamReader {
	return &mapStreamReader{ctx: ctx, h: h, upstream: upstream, parentID: parentID}
}

func (r *mapStreamReader) Read(p []byte) (int, error) {
	for len(r.pending) == 0 {
		if frame, ok := r.re.Next(r.split); ok {
			out, err := r.processFrame(frame)
			if err != nil {
				r.finish()
				return 0, err
			}
			r.pending = out
			break
		}
		if r.frameErr != nil {
			r.finish()
			return 0, r.frameErr
		}
		if r.done {
			r.finish()
			return 0, io.EOF
		}
		buf := make([]byte, 32*1024)
		n, rerr := r.upstream.Read(buf)
		if n > 0 {
			r.re.Append(buf[:n])
		}
		if rerr != nil {
			if rerr != io.EOF {
				r.finish()
				return 0, rerr
			}
			r.done = true // drain any remaining whole frames, then EOF
		}
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

// Close completes the stream parent and closes the upstream body.
func (r *mapStreamReader) Close() error {
	r.finish()
	return r.upstream.Close()
}

// processFrame captures one wire frame as a child flow (mutated when a rule fires) and
// returns the frame to forward: the original bytes when unmutated, the re-encoded bytes otherwise.
func (r *mapStreamReader) processFrame(frame []byte) ([]byte, error) {
	payload, compressed, _, ok, err := tsproto.DecodeMapResponseFrame(frame)
	if err != nil {
		return nil, err
	} else if !ok {
		return nil, errors.New("mapstream: short frame passed to processFrame")
	}

	mutJSON, fired := r.h.conn.Rules().ApplyBody(payload, wire.RuleTypeResponseBody)
	captured := wire.Flow{
		ProtocolTag:  streamProtocolTag,
		Direction:    adapter.DirServerToClient,
		ParentFlowID: r.parentID,
		Response:     &wire.FlowMessage{StatusCode: http.StatusOK, Headers: compressedHeaders(frame[mapFramePrefixLen:]), Body: payload},
		StartedAt:    time.Now(),
	}
	captured.CompletedAt = captured.StartedAt
	if len(fired) == 0 {
		if _, err := r.h.conn.PushFlow(r.ctx, captured); err != nil {
			return nil, err
		}
		return frame, nil // forward original bytes verbatim
	}

	// re-encode with the source frame's compression mode: a client that requested an
	// uncompressed stream (Compress:"") would fail to decode a zstd re-encode
	outFrame := tsproto.EncodeMapResponseFrame(mutJSON, compressed)
	mutated := captured
	mutated.Response = &wire.FlowMessage{StatusCode: http.StatusOK, Headers: compressedHeaders(outFrame[mapFramePrefixLen:]), Body: mutJSON}
	if _, err := r.h.conn.PushFlow(r.ctx, mutated); err != nil {
		return nil, err
	}
	return outFrame, nil
}

func (r *mapStreamReader) finish() {
	if r.finished {
		return
	}
	r.finished = true
	// teardown must not ride r.ctx (the base context), which may be cancelled
	_ = r.h.conn.CompleteFlow(context.Background(), r.parentID, nil, time.Now())
}

// compressedHeaders returns the compressed-frame metadata headers for a chunk: the
// base64 compressed payload and its byte length.
func compressedHeaders(compressed []byte) []wire.Header {
	return []wire.Header{
		{Name: compressedBytesHeader, Value: base64.StdEncoding.EncodeToString(compressed)},
		{Name: compressedLenHeader, Value: strconv.Itoa(len(compressed))},
	}
}

// split reports the leading complete frame's length in buf, or ok=false when buf
// does not yet hold a whole frame. A length prefix over the cap sets frameErr so
// the bound is enforced at the buffering seam, before unbounded bytes accumulate.
func (r *mapStreamReader) split(buf []byte) (int, bool) {
	if len(buf) < mapFramePrefixLen {
		return 0, false
	}
	length := binary.LittleEndian.Uint32(buf[:mapFramePrefixLen])
	if length > tsproto.MaxMapFrameBytes {
		r.frameErr = fmt.Errorf("mapstream: frame length %d exceeds max %d", length, tsproto.MaxMapFrameBytes)
		return 0, false
	}
	total := mapFramePrefixLen + int(length)
	if len(buf) < total {
		return 0, false
	}
	return total, true
}
