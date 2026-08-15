package derp

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"time"

	"go4.org/mem"
	"tailscale.com/types/key"

	"github.com/go-appsec/toolbox/sidecar/wire"
	"github.com/jentfoo/toolbox-sidescale/sidescale/adapter"
	"github.com/jentfoo/toolbox-sidescale/sidescale/derp/derpproto"
)

// packetCodec marks a frame whose logical body is an opaque, end-to-end-encrypted payload the relay cannot decode.
var packetCodec = &wire.BodyCodec{Transforms: []string{"passthrough"}, ContentType: "application/octet-stream"}

// captureFrame emits a child frame flow under tunnelID for one steady-state frame,
// applies pushed rules for the source direction, and returns the frame bytes to forward.
func (h *Handler) captureFrame(ctx context.Context, tunnelID string, frame []byte, dir string) ([]byte, error) {
	t, _, ok := derpproto.FrameHeader(frame)
	if !ok {
		return nil, errors.New("derp: short frame")
	}
	f := decodeFrame(t, derpproto.FramePayload(frame))

	captured := wire.Flow{
		ProtocolTag:  frameProtocolTag,
		Direction:    dir,
		ParentFlowID: tunnelID,
		StartedAt:    time.Now(),
	}
	captured.CompletedAt = captured.StartedAt
	setMessage(&captured, dir, frameMessage(t, f))

	// rules apply only to a frame's logical text body (HEALTH); opaque packets and derived
	// X-Derp-* headers aren't a hot-path mutation surface (mutate those via replay)
	if f.bodyRaw != nil || len(f.body) == 0 {
		if _, err := h.conn.PushFlow(ctx, captured); err != nil {
			return nil, err
		}
		return frame, nil
	}
	bodyType := wire.RuleTypeRequestBody
	if dir == adapter.DirServerToClient {
		bodyType = wire.RuleTypeResponseBody
	}
	mutBody, fired := h.conn.Rules().ApplyBody(f.body, bodyType)
	if len(fired) == 0 {
		if _, err := h.conn.PushFlow(ctx, captured); err != nil {
			return nil, err
		}
		return frame, nil
	}

	mf := f
	mf.body = mutBody
	mutated := captured
	setMessage(&mutated, dir, frameMessage(t, mf))
	if _, err := h.conn.PushFlow(ctx, mutated); err != nil {
		return nil, err
	}
	return derpproto.EncodeFrame(t, encodePayload(mf)), nil
}

// frameMessage builds the flow message for a decoded frame: a text/JSON body, or an
// opaque packet payload as BodyRaw with a passthrough codec.
func frameMessage(t derpproto.FrameType, f frameFields) *wire.FlowMessage {
	msg := &wire.FlowMessage{Method: derpproto.FrameName(t), Path: framePath(t), Headers: f.headers}
	if f.bodyRaw != nil {
		msg.BodyRaw, msg.BodyCodec = f.bodyRaw, packetCodec
	} else {
		msg.Body = f.body
	}
	return msg
}

// captureHandshakeFrame emits a CLIENT_INFO / SERVER_INFO child flow carrying the
// decrypted JSON the sidecar recovered during login.
func (h *Handler) captureHandshakeFrame(ctx context.Context, tunnelID string, t derpproto.FrameType, nodePub key.NodePublic, box, infoJSON []byte, dir string) error {
	// capture-only visibility: the box is re-sealed separately, not a hot-path mutation seam
	headers := []wire.Header{
		{Name: "X-Derp-Node-Key", Value: nodePub.String()},
		{Name: "X-Derp-Box", Value: base64.StdEncoding.EncodeToString(box)},
	}
	flow := wire.Flow{
		ProtocolTag:  frameProtocolTag,
		Direction:    dir,
		ParentFlowID: tunnelID,
		StartedAt:    time.Now(),
	}
	flow.CompletedAt = flow.StartedAt
	setMessage(&flow, dir, &wire.FlowMessage{Method: derpproto.FrameName(t), Path: framePath(t), Headers: headers, Body: infoJSON})
	_, err := h.conn.PushFlow(ctx, flow)
	return err
}

// setMessage places msg on the request or response side of flow per direction.
func setMessage(flow *wire.Flow, dir string, msg *wire.FlowMessage) {
	if dir == adapter.DirServerToClient {
		flow.Response = msg
	} else {
		flow.Request = msg
	}
}

// framePath is the frame flow path: /derp/<frame_name_lower>.
func framePath(t derpproto.FrameType) string {
	return "/derp/" + strings.ToLower(derpproto.FrameName(t))
}

// frameFields is the decoded typed view of a frame the capture path operates on.
type frameFields struct {
	typ     derpproto.FrameType
	headers []wire.Header
	body    []byte // logical text (HEALTH); nil for packet/binary frames
	bodyRaw []byte // opaque packet payload; nil for non-packet frames
	tail    []byte // payload bytes preserved verbatim (e.g. PEER_PRESENT ip/port/flags)
}

// decodeFrame parses a steady-state frame payload into typed headers plus a body or
// opaque packet payload, per frame class.
func decodeFrame(t derpproto.FrameType, payload []byte) frameFields {
	f := frameFields{typ: t}
	switch t {
	case derpproto.FrameSendPacket, derpproto.FrameRecvPacket:
		keyHdr := "X-Derp-Src-Key"
		if t == derpproto.FrameSendPacket {
			keyHdr = "X-Derp-Dst-Key"
		}
		if len(payload) >= key.NodePublicRawLen {
			k := key.NodePublicFromRaw32(mem.B(payload[:key.NodePublicRawLen]))
			f.bodyRaw = payload[key.NodePublicRawLen:]
			f.headers = append([]wire.Header{{Name: keyHdr, Value: k.String()}}, packetMetaHeaders(f.bodyRaw)...)
		} else {
			f.bodyRaw = payload
		}
	case derpproto.FrameForwardPacket:
		if len(payload) >= 2*key.NodePublicRawLen {
			src := key.NodePublicFromRaw32(mem.B(payload[:key.NodePublicRawLen]))
			dst := key.NodePublicFromRaw32(mem.B(payload[key.NodePublicRawLen : 2*key.NodePublicRawLen]))
			f.bodyRaw = payload[2*key.NodePublicRawLen:]
			f.headers = []wire.Header{{Name: "X-Derp-Src-Key", Value: src.String()}, {Name: "X-Derp-Dst-Key", Value: dst.String()}}
			f.headers = append(f.headers, packetMetaHeaders(f.bodyRaw)...)
		} else {
			f.bodyRaw = payload
		}
	case derpproto.FramePeerGone:
		if len(payload) >= key.NodePublicRawLen+1 {
			peer := key.NodePublicFromRaw32(mem.B(payload[:key.NodePublicRawLen]))
			f.headers = []wire.Header{
				{Name: "X-Derp-Peer-Key", Value: peer.String()},
				{Name: "X-Derp-Peer-Gone-Reason", Value: strconv.Itoa(int(payload[key.NodePublicRawLen]))},
			}
		}
	case derpproto.FramePeerPresent:
		if len(payload) >= key.NodePublicRawLen {
			peer := key.NodePublicFromRaw32(mem.B(payload[:key.NodePublicRawLen]))
			f.headers = []wire.Header{{Name: "X-Derp-Peer-Key", Value: peer.String()}}
			f.tail = payload[key.NodePublicRawLen:]
			// carry the full tail (ip/port/flags) so a captured-frame replay round-trips; the flags header stays as a readable derived value
			f.headers = append(f.headers, wire.Header{Name: "X-Derp-Peer-Present-Tail", Value: base64.StdEncoding.EncodeToString(f.tail)})
			if len(f.tail) >= 1 {
				f.headers = append(f.headers, wire.Header{Name: "X-Derp-Peer-Present-Flags", Value: strconv.Itoa(int(f.tail[len(f.tail)-1]))})
			}
		}
	case derpproto.FrameNotePreferred:
		home := strconv.FormatBool(len(payload) >= 1 && payload[0] != 0)
		f.headers = []wire.Header{{Name: "X-Derp-Home", Value: home}}
	case derpproto.FrameClosePeer:
		if len(payload) >= key.NodePublicRawLen {
			peer := key.NodePublicFromRaw32(mem.B(payload[:key.NodePublicRawLen]))
			f.headers = []wire.Header{{Name: "X-Derp-Peer-Key", Value: peer.String()}}
		}
	case derpproto.FramePing, derpproto.FramePong:
		f.headers = []wire.Header{{Name: "X-Derp-Ping-Token", Value: base64.StdEncoding.EncodeToString(payload)}}
	case derpproto.FrameRestarting:
		if len(payload) >= 8 {
			f.headers = []wire.Header{
				{Name: "X-Derp-Reconnect-Ms", Value: strconv.FormatUint(uint64(binary.BigEndian.Uint32(payload[:4])), 10)},
				{Name: "X-Derp-Try-For-Ms", Value: strconv.FormatUint(uint64(binary.BigEndian.Uint32(payload[4:8])), 10)},
			}
		}
	case derpproto.FrameHealth:
		f.body = payload
	case derpproto.FrameKeepAlive, derpproto.FrameWatchConns:
		// empty payload
	default:
		f.bodyRaw = payload // unknown: opaque passthrough
	}
	return f
}

// packetMetaHeaders builds the length and disco-classification headers for a packet payload.
func packetMetaHeaders(payload []byte) []wire.Header {
	return []wire.Header{
		{Name: "X-Derp-Packet-Len", Value: strconv.Itoa(len(payload))},
		{Name: "X-Derp-Disco", Value: strconv.FormatBool(derpproto.IsDisco(payload))},
	}
}

// encodePayload rebuilds a frame payload from its typed fields, honoring header/body
// mutations. It is the inverse of decodeFrame for the fields the capture path exposes.
func encodePayload(f frameFields) []byte {
	switch f.typ {
	case derpproto.FrameSendPacket, derpproto.FrameRecvPacket:
		keyHdr := "X-Derp-Src-Key"
		if f.typ == derpproto.FrameSendPacket {
			keyHdr = "X-Derp-Dst-Key"
		}
		return append(rawKey(f.headers, keyHdr), f.bodyRaw...)
	case derpproto.FrameForwardPacket:
		out := append(rawKey(f.headers, "X-Derp-Src-Key"), rawKey(f.headers, "X-Derp-Dst-Key")...)
		return append(out, f.bodyRaw...)
	case derpproto.FramePeerGone:
		reason, _ := strconv.Atoi(headerValue(f.headers, "X-Derp-Peer-Gone-Reason"))
		return append(rawKey(f.headers, "X-Derp-Peer-Key"), byte(reason))
	case derpproto.FramePeerPresent:
		tail := f.tail
		if tail == nil {
			// on a message-reconstructed replay tail is nil, so recover the tail from the round-trip header
			tail, _ = base64.StdEncoding.DecodeString(headerValue(f.headers, "X-Derp-Peer-Present-Tail"))
		}
		return append(rawKey(f.headers, "X-Derp-Peer-Key"), tail...)
	case derpproto.FrameNotePreferred:
		if headerValue(f.headers, "X-Derp-Home") == "true" {
			return []byte{1}
		}
		return []byte{0}
	case derpproto.FrameClosePeer:
		return rawKey(f.headers, "X-Derp-Peer-Key")
	case derpproto.FramePing, derpproto.FramePong:
		tok, _ := base64.StdEncoding.DecodeString(headerValue(f.headers, "X-Derp-Ping-Token"))
		return tok
	case derpproto.FrameRestarting:
		reconnect, _ := strconv.ParseUint(headerValue(f.headers, "X-Derp-Reconnect-Ms"), 10, 32)
		tryFor, _ := strconv.ParseUint(headerValue(f.headers, "X-Derp-Try-For-Ms"), 10, 32)
		out := make([]byte, 8)
		binary.BigEndian.PutUint32(out[:4], uint32(reconnect))
		binary.BigEndian.PutUint32(out[4:8], uint32(tryFor))
		return out
	case derpproto.FrameHealth:
		return f.body
	case derpproto.FrameKeepAlive, derpproto.FrameWatchConns:
		return nil
	default:
		return f.bodyRaw
	}
}

// rawKey decodes the 32-byte node key from a typed header, or 32 zero bytes when absent.
func rawKey(headers []wire.Header, name string) []byte {
	var k key.NodePublic
	if v := headerValue(headers, name); v != "" {
		_ = k.UnmarshalText([]byte(v))
	}
	return k.AppendTo(make([]byte, 0, key.NodePublicRawLen))
}

func headerValue(headers []wire.Header, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}
