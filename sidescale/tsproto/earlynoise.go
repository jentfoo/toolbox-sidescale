package tsproto

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"tailscale.com/control/ts2021"
	"tailscale.com/tailcfg"
)

// maxEarlyNoiseBytes bounds a decoded EarlyNoise JSON payload.
const maxEarlyNoiseBytes = 10 << 20

// earlyNoiseHeaderLen is the 5-byte magic plus the 4-byte big-endian length.
const earlyNoiseHeaderLen = len(ts2021.EarlyPayloadMagic) + 4

// EncodeEarlyNoise frames an EarlyNoise message as the magic prefix, a 4-byte big-endian length, and the JSON payload.
func EncodeEarlyNoise(n *tailcfg.EarlyNoise) ([]byte, error) {
	payload, err := json.Marshal(n)
	if err != nil {
		return nil, err
	}
	if len(payload) > maxEarlyNoiseBytes {
		return nil, fmt.Errorf("tsproto: early noise payload %d exceeds max %d", len(payload), maxEarlyNoiseBytes)
	}
	out := make([]byte, 0, earlyNoiseHeaderLen+len(payload))
	out = append(out, ts2021.EarlyPayloadMagic...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(payload)))
	return append(out, payload...), nil
}

// ReadEarlyNoise reads an optional leading EarlyNoise frame from br. When the next bytes are an EarlyNoise frame
// it returns the raw frame and parsed message with ok=true; otherwise ok=false and br is left unconsumed.
func ReadEarlyNoise(br *bufio.Reader) (raw []byte, n *tailcfg.EarlyNoise, ok bool, err error) {
	magic := ts2021.EarlyPayloadMagic
	head, err := br.Peek(len(magic))
	if errors.Is(err, io.EOF) {
		return nil, nil, false, nil // no EarlyNoise: stream ended at the frame boundary
	} else if err != nil {
		return nil, nil, false, err
	} else if string(head) != magic {
		return nil, nil, false, nil
	}
	hdr := make([]byte, earlyNoiseHeaderLen)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return nil, nil, false, err
	}
	length := binary.BigEndian.Uint32(hdr[len(magic):])
	if length > maxEarlyNoiseBytes {
		return nil, nil, false, fmt.Errorf("tsproto: early noise length %d exceeds max %d", length, maxEarlyNoiseBytes)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(br, payload); err != nil {
		return nil, nil, false, err
	}
	var msg tailcfg.EarlyNoise
	if err := json.Unmarshal(payload, &msg); err != nil {
		return nil, nil, false, err
	}
	return append(hdr, payload...), &msg, true, nil
}

// DecodeEarlyNoise parses an EarlyNoise frame and returns the message plus the
// number of bytes consumed. It returns ok=false with no error when buf does not
// yet hold a complete frame, so a caller can accumulate more bytes and retry.
// TODO - review if useful for Encode/Decode symmetry, or remove
func DecodeEarlyNoise(buf []byte) (n *tailcfg.EarlyNoise, consumed int, ok bool, err error) {
	if len(buf) < earlyNoiseHeaderLen {
		return nil, 0, false, nil
	}
	magic := len(ts2021.EarlyPayloadMagic)
	if string(buf[:magic]) != ts2021.EarlyPayloadMagic {
		return nil, 0, false, errors.New("tsproto: bad early noise magic")
	}
	length := binary.BigEndian.Uint32(buf[magic:earlyNoiseHeaderLen])
	if length > maxEarlyNoiseBytes {
		return nil, 0, false, fmt.Errorf("tsproto: early noise length %d exceeds max %d", length, maxEarlyNoiseBytes)
	}
	end := earlyNoiseHeaderLen + int(length)
	if len(buf) < end {
		return nil, 0, false, nil
	}
	var msg tailcfg.EarlyNoise
	if err := json.Unmarshal(buf[earlyNoiseHeaderLen:end], &msg); err != nil {
		return nil, 0, false, err
	}
	return &msg, end, true, nil
}
