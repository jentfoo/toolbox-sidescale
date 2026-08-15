package bindings

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// Annotation keys recorded when a binding strips fields it cannot rebind.
const (
	AnnStrippedFields = "stripped_fields"
	AnnBinding        = "binding"
	AnnReason         = "reason"
)

// Binding names recorded in the binding annotation.
const (
	bindingRegisterSignature = "register_signature"
	bindingHardwareAttest    = "hardware_attestation"
)

// reasonNoCert / reasonNoHWKey are the strip reasons for absent key material.
const (
	reasonNoCert  = "no_operator_cert_configured"
	reasonNoHWKey = "no_hardware_key_configured"
)

// Result is a rebind op's outcome.
type Result struct {
	// possibly-modified JSON body
	Body []byte
	// describes fields stripped for lack of key material
	Annotations map[string]any
}

// RegisterSigner is the operator device identity used to rebind a RegisterRequest signature.
type RegisterSigner struct {
	Key *rsa.PrivateKey
	// DER cert chain concatenated into DeviceCert
	CertChain [][]byte
}

// ResignRegisterRequest rebinds the RegisterRequest SignatureV2 over serverLegacyPub
// (the server legacy machine key the hash binds, not the Noise key) and machinePub.
// With signer set it re-signs; with signer nil it strips Signature, SignatureType, and
// DeviceCert and annotates the removal. It does not cover NodeKey.
func ResignRegisterRequest(body []byte, serverURL string, serverLegacyPub, machinePub key.MachinePublic, signer *RegisterSigner) (Result, error) {
	var req tailcfg.RegisterRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return Result{}, fmt.Errorf("bindings: register unmarshal: %w", err)
	}

	if signer == nil || signer.Key == nil {
		var stripped []string
		if req.Signature != nil {
			stripped = append(stripped, "Signature")
		}
		if req.SignatureType != tailcfg.SignatureNone {
			stripped = append(stripped, "SignatureType")
		}
		if req.DeviceCert != nil {
			stripped = append(stripped, "DeviceCert")
		}
		req.Signature = nil
		req.SignatureType = tailcfg.SignatureNone
		req.DeviceCert = nil
		return marshalStripped(&req, bindingRegisterSignature, stripped, reasonNoCert)
	}

	req.SignatureType = tailcfg.SignatureV2
	req.DeviceCert = slices.Concat(signer.CertChain...)
	var reqTime time.Time
	if req.Timestamp != nil {
		reqTime = *req.Timestamp
	}
	digest := hashRegisterV2(reqTime, serverURL, req.DeviceCert, serverLegacyPub, machinePub)
	sig, err := rsa.SignPSS(rand.Reader, signer.Key, crypto.SHA256, digest, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		return Result{}, fmt.Errorf("bindings: register sign: %w", err)
	}
	req.Signature = sig
	return marshalResult(&req)
}

// ResignHardwareAttestation rebinds the MapRequest hardware-attestation signature over its node key at time now.
// With key set it re-signs; with key nil it strips the attestation fields and annotates the removal.
func ResignHardwareAttestation(body []byte, now time.Time, hwKey *ecdsa.PrivateKey) (Result, error) {
	var req tailcfg.MapRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return Result{}, fmt.Errorf("bindings: map unmarshal: %w", err)
	}

	if hwKey == nil {
		var stripped []string
		if req.HardwareAttestationKeySignature != nil {
			stripped = append(stripped, "HardwareAttestationKeySignature")
		}
		if !req.HardwareAttestationKeySignatureTimestamp.IsZero() {
			stripped = append(stripped, "HardwareAttestationKeySignatureTimestamp")
		}
		if !req.HardwareAttestationKey.IsZero() {
			stripped = append(stripped, "HardwareAttestationKey")
		}
		req.HardwareAttestationKeySignature = nil
		req.HardwareAttestationKeySignatureTimestamp = time.Time{}
		req.HardwareAttestationKey = key.HardwareAttestationPublic{}
		return marshalStripped(&req, bindingHardwareAttest, stripped, reasonNoHWKey)
	}

	// the attestation key in the message must match the signing key, else the server
	// verifies the new signature against the victim's original key and rejects it
	pub, err := hardwareAttestationPublic(hwKey)
	if err != nil {
		return Result{}, err
	}
	req.HardwareAttestationKey = pub

	// whole-second timestamp to match the signed message
	ts := now.Truncate(time.Second)
	digest := sha256.Sum256([]byte(fmt.Sprintf("%d|%s", ts.Unix(), req.NodeKey.String())))
	sig, err := ecdsa.SignASN1(rand.Reader, hwKey, digest[:])
	if err != nil {
		return Result{}, fmt.Errorf("bindings: hardware attestation sign: %w", err)
	}
	req.HardwareAttestationKeySignature = sig
	req.HardwareAttestationKeySignatureTimestamp = ts
	return marshalResult(&req)
}

// ResetMapSession clears the MapRequest session handle and sequence so a captured
// MapRequest replays as a new session rather than resuming an existing one.
func ResetMapSession(body []byte) (Result, error) {
	var req tailcfg.MapRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return Result{}, fmt.Errorf("bindings: map unmarshal: %w", err)
	}
	req.MapSessionHandle = ""
	req.MapSessionSeq = 0
	return marshalResult(&req)
}

// hashRegisterV2 mirrors Tailscale's SignatureV2 register hash: SHA-256 over the RFC3339 UTC timestamp, server URL,
// device cert, and the full text form of the server legacy then machine public keys, concatenated with no separators.
func hashRegisterV2(ts time.Time, serverURL string, deviceCert []byte, serverLegacyPub, machinePub key.MachinePublic) []byte {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s%s%s%s%s", ts.UTC().Format(time.RFC3339), serverURL, deviceCert, serverLegacyPub, machinePub)
	return h.Sum(nil)
}

// hardwareAttestationPublic returns the wire public key for a P-256 attestation private
// key, for setting MapRequest.HardwareAttestationKey to match the re-signing key.
func hardwareAttestationPublic(k *ecdsa.PrivateKey) (key.HardwareAttestationPublic, error) {
	if k.Curve != elliptic.P256() {
		return key.HardwareAttestationPublic{}, errors.New("bindings: hardware attestation key must be P-256")
	}
	ek, err := k.ECDH()
	if err != nil {
		return key.HardwareAttestationPublic{}, fmt.Errorf("bindings: hardware attestation key: %w", err)
	}
	text := append([]byte("hwattestpub:"), []byte(hex.EncodeToString(ek.PublicKey().Bytes()))...)
	var pub key.HardwareAttestationPublic
	if err := pub.UnmarshalText(text); err != nil {
		return key.HardwareAttestationPublic{}, fmt.Errorf("bindings: hardware attestation public: %w", err)
	}
	return pub, nil
}

func marshalResult(v any) (Result, error) {
	out, err := json.Marshal(v)
	if err != nil {
		return Result{}, fmt.Errorf("bindings: marshal: %w", err)
	}
	return Result{Body: out}, nil
}

func marshalStripped(v any, binding string, fields []string, reason string) (Result, error) {
	out, err := json.Marshal(v)
	if err != nil {
		return Result{}, fmt.Errorf("bindings: marshal: %w", err)
	}
	if len(fields) == 0 {
		return Result{Body: out}, nil
	}
	return Result{
		Body: out,
		Annotations: map[string]any{
			AnnBinding:        binding,
			AnnStrippedFields: fields,
			AnnReason:         reason,
		},
	}, nil
}
