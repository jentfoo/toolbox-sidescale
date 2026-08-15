package tsproto

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"slices"

	"tailscale.com/util/zstdframe"
)

// mapFrameLenBytes is the 4-byte little-endian length prefix preceding each MapResponse frame.
const mapFrameLenBytes = 4

// MaxMapFrameBytes bounds a single MapResponse frame (resource limit, not a protocol check).
const MaxMapFrameBytes = 10 << 20

// zstdMagic is the zstd frame magic (little-endian 0xFD2FB528). Compression is opt-in via MapRequest.Compress,
// so a frame body may be raw JSON instead; the magic disambiguates without keying off the request.
var zstdMagic = []byte{0x28, 0xB5, 0x2F, 0xFD}

// EncodeMapResponseFrame encodes a MapResponse JSON payload as one wire frame: zstd-compressed when compress is true,
// else raw JSON, prefixed by its 4-byte little-endian length. Preserve the source frame's mode when re-encoding so a
// client that did not request zstd still decodes the stream.
func EncodeMapResponseFrame(jsonPayload []byte, compress bool) []byte {
	body := jsonPayload
	if compress {
		body = zstdframe.AppendEncode(nil, jsonPayload)
	}
	out := make([]byte, mapFrameLenBytes, mapFrameLenBytes+len(body))
	binary.LittleEndian.PutUint32(out, uint32(len(body)))
	return append(out, body...)
}

// DecodeMapResponseFrame parses one MapResponse frame from buf, returning the JSON payload,
// whether the frame body was zstd-compressed, and the number of bytes consumed. It returns
// ok=false with no error when buf does not yet hold a complete frame.
func DecodeMapResponseFrame(buf []byte) (jsonPayload []byte, compressed bool, consumed int, ok bool, err error) {
	if len(buf) < mapFrameLenBytes {
		return nil, false, 0, false, nil
	}
	length := binary.LittleEndian.Uint32(buf[:mapFrameLenBytes])
	if length > MaxMapFrameBytes {
		return nil, false, 0, false, fmt.Errorf("tsproto: map frame length %d exceeds max %d", length, MaxMapFrameBytes)
	}
	end := mapFrameLenBytes + int(length)
	if len(buf) < end {
		return nil, false, 0, false, nil
	}
	body := buf[mapFrameLenBytes:end]
	if !bytes.HasPrefix(body, zstdMagic) {
		return slices.Clone(body), false, end, true, nil // uncompressed: raw JSON
	}
	payload, derr := zstdframe.AppendDecode(nil, body)
	if derr != nil {
		return nil, false, 0, false, derr
	}
	return payload, true, end, true, nil
}
