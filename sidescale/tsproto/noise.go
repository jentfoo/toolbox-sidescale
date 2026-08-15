package tsproto

import (
	"context"
	"encoding/binary"
	"errors"
	"net"

	"tailscale.com/control/controlbase"
	"tailscale.com/types/key"
)

// InitiationVersion reads the 2-byte big-endian protocol (capability) version from a Noise initiation (msg 1).
// It is carried through unchanged to the upstream initiation and the /key fetch.
func InitiationVersion(init []byte) (uint16, error) {
	if len(init) < 2 {
		return 0, errors.New("tsproto: initiation too short for version")
	}
	return binary.BigEndian.Uint16(init[:2]), nil
}

// Responder runs the client-facing Noise IK responder handshake over conn using controlKey
// (the sidecar's client-facing responder private key). init is the client's initiation
// recovered from the X-Tailscale-Handshake header. The returned Conn exposes the decrypted inner byte stream.
func Responder(ctx context.Context, conn net.Conn, controlKey key.MachinePrivate, init []byte) (*controlbase.Conn, error) {
	return controlbase.Server(ctx, conn, controlKey, init)
}

// Initiation is a prepared upstream initiator handshake.
type Initiation struct {
	// initiation (msg 1) to place base64-encoded in the X-Tailscale-Handshake header
	Header []byte
	cont   controlbase.HandshakeContinuation
}

// Initiator prepares the upstream (server-facing) initiator handshake: machineKey
// is the sidecar's upstream machine identity, controlKey the real upstream server
// pubkey, and version the client's capability version carried through unchanged.
func Initiator(machineKey key.MachinePrivate, controlKey key.MachinePublic, version uint16) (*Initiation, error) {
	header, cont, err := controlbase.ClientDeferred(machineKey, controlKey, version)
	if err != nil {
		return nil, err
	}
	return &Initiation{Header: header, cont: cont}, nil
}

// Complete finishes the initiator handshake over conn. The returned Conn exposes the decrypted inner stream.
func (i *Initiation) Complete(ctx context.Context, conn net.Conn) (*controlbase.Conn, error) {
	return i.cont(ctx, conn)
}
