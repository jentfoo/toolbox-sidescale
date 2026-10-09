package derpproto

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/go-analyze/bulk"
	"go4.org/mem"
	"tailscale.com/derp"
	"tailscale.com/disco"
	"tailscale.com/types/key"
)

// Wire constants, aliased from tailscale.com/derp. All multi-byte integers on the DERP wire are big-endian.
const (
	Magic           = derp.Magic           // 8-byte FrameServerKey magic
	ProtocolVersion = derp.ProtocolVersion // 2
	KeyLen          = derp.KeyLen          // 32
	NonceLen        = derp.NonceLen        // 24
	FrameHeaderLen  = derp.FrameHeaderLen  // 1-byte type + 4-byte length
	MaxPacketSize   = derp.MaxPacketSize   // 64 KiB
	// MaxFrameBytes bounds a single frame; the client's frame-kill threshold
	MaxFrameBytes = derp.MaxInfoLen // 1 MiB
)

// FrameType is a DERP frame type byte.
type FrameType = derp.FrameType

// Named frame types, aliased from upstream.
const (
	FrameServerKey     = derp.FrameServerKey
	FrameClientInfo    = derp.FrameClientInfo
	FrameServerInfo    = derp.FrameServerInfo
	FrameSendPacket    = derp.FrameSendPacket
	FrameRecvPacket    = derp.FrameRecvPacket
	FrameKeepAlive     = derp.FrameKeepAlive
	FrameNotePreferred = derp.FrameNotePreferred
	FramePeerGone      = derp.FramePeerGone
	FramePeerPresent   = derp.FramePeerPresent
	FrameForwardPacket = derp.FrameForwardPacket
	FrameWatchConns    = derp.FrameWatchConns
	FrameClosePeer     = derp.FrameClosePeer
	FramePing          = derp.FramePing
	FramePong          = derp.FramePong
	FrameHealth        = derp.FrameHealth
	FrameRestarting    = derp.FrameRestarting
)

// frameNames maps known frame types to the method name carried on frame flows.
var frameNames = map[FrameType]string{
	FrameServerKey:     "SERVER_KEY",
	FrameClientInfo:    "CLIENT_INFO",
	FrameServerInfo:    "SERVER_INFO",
	FrameSendPacket:    "SEND_PACKET",
	FrameRecvPacket:    "RECV_PACKET",
	FrameKeepAlive:     "KEEP_ALIVE",
	FrameNotePreferred: "NOTE_PREFERRED",
	FramePeerGone:      "PEER_GONE",
	FramePeerPresent:   "PEER_PRESENT",
	FrameForwardPacket: "FORWARD_PACKET",
	FrameWatchConns:    "WATCH_CONNS",
	FrameClosePeer:     "CLOSE_PEER",
	FramePing:          "PING",
	FramePong:          "PONG",
	FrameHealth:        "HEALTH",
	FrameRestarting:    "RESTARTING",
}

var frameTypes = bulk.MapInvert(frameNames)

// FrameName returns the frame's method name, or FRAME_0xNN for an unknown type.
func FrameName(t FrameType) string {
	if n, ok := frameNames[t]; ok {
		return n
	}
	return fmt.Sprintf("FRAME_0x%02x", byte(t))
}

// FrameTypeByName returns the frame type for a known name and whether it matched.
func FrameTypeByName(name string) (FrameType, bool) {
	t, ok := frameTypes[name]
	return t, ok
}

// SplitFrame reports the leading frame's total length once fully buffered (ok=false
// with nil err means more bytes are needed). A non-nil err means the declared length
// exceeds MaxFrameBytes; the caller must tear the stream down rather than keep buffering.
func SplitFrame(buf []byte) (n int, ok bool, err error) {
	if len(buf) < FrameHeaderLen {
		return 0, false, nil
	}
	frameLen := binary.BigEndian.Uint32(buf[1:FrameHeaderLen])
	if frameLen > MaxFrameBytes {
		return 0, false, fmt.Errorf("derpproto: frame length %d exceeds max %d", frameLen, MaxFrameBytes)
	}
	total := FrameHeaderLen + int(frameLen)
	if len(buf) < total {
		return 0, false, nil
	}
	return total, true, nil
}

// FrameHeader parses a frame's type and declared payload length. ok is false when
// buf is shorter than a header; it does not enforce MaxFrameBytes, so callers can
// distinguish an over-cap frame from an incomplete one.
func FrameHeader(buf []byte) (t FrameType, frameLen int, ok bool) {
	if len(buf) < FrameHeaderLen {
		return 0, 0, false
	}
	return FrameType(buf[0]), int(binary.BigEndian.Uint32(buf[1:FrameHeaderLen])), true
}

// EncodeFrame builds one wire frame from a type and payload.
func EncodeFrame(t FrameType, payload []byte) []byte {
	out := make([]byte, FrameHeaderLen+len(payload))
	out[0] = byte(t)
	binary.BigEndian.PutUint32(out[1:FrameHeaderLen], uint32(len(payload)))
	copy(out[FrameHeaderLen:], payload)
	return out
}

// FramePayload returns the payload of a complete frame (the bytes after the header).
func FramePayload(frame []byte) []byte {
	if len(frame) < FrameHeaderLen {
		return nil
	}
	return frame[FrameHeaderLen:]
}

// ServerKeyPayload returns the FrameServerKey payload: the magic followed by the server's raw node public key.
func ServerKeyPayload(serverPub key.NodePublic) []byte {
	out := make([]byte, 0, len(Magic)+KeyLen)
	out = append(out, Magic...)
	return serverPub.AppendTo(out)
}

// ParseServerKey recovers the server node public key from a FrameServerKey payload.
func ParseServerKey(payload []byte) (key.NodePublic, error) {
	// TODO - lax validation for more protocol testing?
	if len(payload) < len(Magic)+KeyLen {
		return key.NodePublic{}, errors.New("derpproto: short FrameServerKey payload")
	} else if string(payload[:len(Magic)]) != Magic {
		return key.NodePublic{}, errors.New("derpproto: bad FrameServerKey magic")
	}
	return key.NodePublicFromRaw32(mem.B(payload[len(Magic) : len(Magic)+KeyLen])), nil
}

// ClientInfoPayload builds a FrameClientInfo payload: the client's raw node public
// key followed by a NaCl box of the ClientInfo JSON sealed to the server key.
func ClientInfoPayload(clientPriv key.NodePrivate, serverPub key.NodePublic, info *derp.ClientInfo) ([]byte, error) {
	js, err := json.Marshal(info)
	if err != nil {
		return nil, err
	}
	box := clientPriv.SealTo(serverPub, js)
	out := make([]byte, 0, KeyLen+len(box))
	out = clientPriv.Public().AppendTo(out)
	return append(out, box...), nil
}

// OpenClientInfo splits a FrameClientInfo payload, opens the box with the server
// private key, and returns the client node public key and decoded ClientInfo.
func OpenClientInfo(serverPriv key.NodePrivate, payload []byte) (key.NodePublic, *derp.ClientInfo, error) {
	if len(payload) < KeyLen {
		return key.NodePublic{}, nil, errors.New("derpproto: short FrameClientInfo payload")
	}
	clientPub := key.NodePublicFromRaw32(mem.B(payload[:KeyLen]))
	if clientPub.IsZero() {
		return key.NodePublic{}, nil, errors.New("derpproto: zero client key")
	}
	js, ok := serverPriv.OpenFrom(clientPub, payload[KeyLen:])
	if !ok {
		return key.NodePublic{}, nil, errors.New("derpproto: FrameClientInfo box open failed")
	}
	var info derp.ClientInfo
	if err := json.Unmarshal(js, &info); err != nil {
		return key.NodePublic{}, nil, err
	}
	return clientPub, &info, nil
}

// ServerInfoPayload builds a FrameServerInfo payload: a NaCl box of the ServerInfo
// JSON sealed from the server private key to the client key.
func ServerInfoPayload(serverPriv key.NodePrivate, clientPub key.NodePublic, info *derp.ServerInfo) ([]byte, error) {
	js, err := json.Marshal(info)
	if err != nil {
		return nil, err
	}
	return serverPriv.SealTo(clientPub, js), nil
}

// OpenServerInfo opens a FrameServerInfo box with the client private key.
func OpenServerInfo(clientPriv key.NodePrivate, serverPub key.NodePublic, payload []byte) (*derp.ServerInfo, error) {
	js, ok := clientPriv.OpenFrom(serverPub, payload)
	if !ok {
		return nil, errors.New("derpproto: FrameServerInfo box open failed")
	}
	var info derp.ServerInfo
	if err := json.Unmarshal(js, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// peerPresentTailBaseLen is the modern FramePeerPresent tail length before its app
// name: 16-byte IP + 2-byte BE port + 1-byte flags + 1-byte app-name length.
const peerPresentTailBaseLen = 20

// peerPresentAppNameMax is the app-name capacity of its one-byte wire length field.
const peerPresentAppNameMax = 0xff

// PeerPresentInfo is the decoded tail of a FramePeerPresent payload after its node key.
// Has* report which optional fields the frame actually carried. Legacy frames stop at any
// field boundary, matching the reference client's cut-each-field-independently parsing.
type PeerPresentInfo struct {
	IPPort     netip.AddrPort // zero unless HasIPPort, IPv4 arrives v6-mapped per the wire encoding
	HasIPPort  bool
	Flags      byte
	HasFlags   bool
	AppName    string
	HasAppName bool
}

// ParsePeerPresentTail decodes a FramePeerPresent tail laid out as
// [16B IP][2B BE port][1B flags][1B nameLen][name], recognizing a field only when the
// tail carries it complete, mirroring the reference client's incremental parsing.
func ParsePeerPresentTail(tail []byte) PeerPresentInfo {
	var info PeerPresentInfo
	if len(tail) < 18 { // ip + port
		return info
	}
	info.HasIPPort = true
	info.IPPort = netip.AddrPortFrom(netip.AddrFrom16([16]byte(tail[:16])).Unmap(), binary.BigEndian.Uint16(tail[16:18]))
	if len(tail) < 19 {
		return info
	}
	info.HasFlags = true
	info.Flags = tail[18]
	if len(tail) < 20 {
		return info
	}
	nameLen := int(tail[19])
	if len(tail)-20 < nameLen { // truncated app name, client keeps fields parsed so far
		return info
	}
	info.HasAppName = true
	info.AppName = string(tail[20 : 20+nameLen])
	return info
}

// BuildPeerPresentTail encodes a FramePeerPresent tail with the same layout, writing an
// all-zero IP and port when ipPort is zero. The app name's bytes pass through unvalidated;
// only its length is constrained to the one-byte wire field.
func BuildPeerPresentTail(ipPort netip.AddrPort, flags byte, appName string) ([]byte, error) {
	if len(appName) > peerPresentAppNameMax {
		return nil, fmt.Errorf("PEER_PRESENT app name %d bytes exceeds the %d-byte wire limit", len(appName), peerPresentAppNameMax)
	}
	out := make([]byte, peerPresentTailBaseLen+len(appName))
	a16 := ipPort.Addr().As16()
	copy(out[:16], a16[:]) // IPv4 rides v6-mapped, matching sendPeerPresent
	binary.BigEndian.PutUint16(out[16:18], ipPort.Port())
	out[18] = flags
	out[19] = byte(len(appName))
	copy(out[20:], appName)
	return out, nil
}

// IsDisco reports whether a relayed packet payload is a disco message, matching
// the classification the real server uses to route the disco send-queue.
func IsDisco(payload []byte) bool {
	return disco.LooksLikeDiscoWrapper(payload)
}
