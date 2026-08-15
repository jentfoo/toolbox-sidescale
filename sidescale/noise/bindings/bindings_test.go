package bindings

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestResignRegisterRequest(t *testing.T) {
	t.Parallel()

	serverPub := key.NewMachine().Public()
	machinePub := key.NewMachine().Public()
	const serverURL = "https://control.example.com"
	ts := time.Unix(1_700_000_000, 0).UTC()

	body, err := json.Marshal(&tailcfg.RegisterRequest{Timestamp: &ts})
	require.NoError(t, err)

	t.Run("resigns_with_key", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		signer := &RegisterSigner{Key: rsaKey, CertChain: [][]byte{[]byte("der-a"), []byte("der-b")}}

		res, err := ResignRegisterRequest(body, serverURL, serverPub, machinePub, signer)
		require.NoError(t, err)
		assert.Nil(t, res.Annotations)

		var out tailcfg.RegisterRequest
		require.NoError(t, json.Unmarshal(res.Body, &out))
		assert.Equal(t, tailcfg.SignatureV2, out.SignatureType)
		assert.Equal(t, []byte("der-ader-b"), out.DeviceCert)

		digest := hashRegisterV2(ts, serverURL, out.DeviceCert, serverPub, machinePub)
		verr := rsa.VerifyPSS(&rsaKey.PublicKey, crypto.SHA256, digest, out.Signature, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		})
		assert.NoError(t, verr)
	})

	t.Run("strips_without_key", func(t *testing.T) {
		signed, err := ResignRegisterRequest(body, serverURL, serverPub, machinePub,
			&RegisterSigner{Key: mustRSA(t), CertChain: [][]byte{[]byte("der")}})
		require.NoError(t, err)

		res, err := ResignRegisterRequest(signed.Body, serverURL, serverPub, machinePub, nil)
		require.NoError(t, err)
		assert.Equal(t, bindingRegisterSignature, res.Annotations[AnnBinding])
		assert.Equal(t, reasonNoCert, res.Annotations[AnnReason])
		assert.ElementsMatch(t, []string{"Signature", "SignatureType", "DeviceCert"}, res.Annotations[AnnStrippedFields])

		var out tailcfg.RegisterRequest
		require.NoError(t, json.Unmarshal(res.Body, &out))
		assert.Nil(t, out.Signature)
		assert.Nil(t, out.DeviceCert)
		assert.Equal(t, tailcfg.SignatureNone, out.SignatureType)
	})

	t.Run("stock_no_signature_noop", func(t *testing.T) {
		res, err := ResignRegisterRequest(body, serverURL, serverPub, machinePub, nil)
		require.NoError(t, err)
		assert.Nil(t, res.Annotations)

		var out tailcfg.RegisterRequest
		require.NoError(t, json.Unmarshal(res.Body, &out))
		assert.Nil(t, out.Signature)
		assert.Nil(t, out.DeviceCert)
		assert.Equal(t, tailcfg.SignatureNone, out.SignatureType)
	})
}

func TestResignHardwareAttestation(t *testing.T) {
	t.Parallel()

	nodeKey := key.NewNode().Public()
	body, err := json.Marshal(&tailcfg.MapRequest{NodeKey: nodeKey})
	require.NoError(t, err)

	t.Run("resigns_with_key", func(t *testing.T) {
		hwKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		now := time.Unix(1_700_000_123, 456).UTC()

		res, err := ResignHardwareAttestation(body, now, hwKey)
		require.NoError(t, err)
		assert.Nil(t, res.Annotations)

		var out tailcfg.MapRequest
		require.NoError(t, json.Unmarshal(res.Body, &out))
		assert.Equal(t, now.Truncate(time.Second), out.HardwareAttestationKeySignatureTimestamp.UTC())

		digest := sha256.Sum256([]byte(fmt.Sprintf("%d|%s", now.Truncate(time.Second).Unix(), nodeKey.String())))
		assert.True(t, ecdsa.VerifyASN1(&hwKey.PublicKey, digest[:], out.HardwareAttestationKeySignature))
		// the attestation key in the message must match the signing key and verify
		assert.False(t, out.HardwareAttestationKey.IsZero())
		assert.True(t, ecdsa.VerifyASN1(out.HardwareAttestationKey.Verifier(), digest[:], out.HardwareAttestationKeySignature))
	})

	t.Run("rejects_non_p256", func(t *testing.T) {
		hwKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)
		_, err = ResignHardwareAttestation(body, time.Now(), hwKey)
		assert.ErrorContains(t, err, "P-256")
	})

	t.Run("strips_without_key", func(t *testing.T) {
		hwKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		signed, err := ResignHardwareAttestation(body, time.Now(), hwKey)
		require.NoError(t, err)

		res, err := ResignHardwareAttestation(signed.Body, time.Now(), nil)
		require.NoError(t, err)
		assert.Equal(t, bindingHardwareAttest, res.Annotations[AnnBinding])
		assert.Equal(t, reasonNoHWKey, res.Annotations[AnnReason])
		assert.ElementsMatch(t,
			[]string{"HardwareAttestationKeySignature", "HardwareAttestationKeySignatureTimestamp", "HardwareAttestationKey"},
			res.Annotations[AnnStrippedFields])
	})

	t.Run("stock_no_attestation_noop", func(t *testing.T) {
		res, err := ResignHardwareAttestation(body, time.Now(), nil)
		require.NoError(t, err)
		assert.Nil(t, res.Annotations)
	})
}

func TestResetMapSession(t *testing.T) {
	t.Parallel()

	body, err := json.Marshal(&tailcfg.MapRequest{MapSessionHandle: "handle-1", MapSessionSeq: 42})
	require.NoError(t, err)

	res, err := ResetMapSession(body)
	require.NoError(t, err)
	var out tailcfg.MapRequest
	require.NoError(t, json.Unmarshal(res.Body, &out))
	assert.Empty(t, out.MapSessionHandle)
	assert.Zero(t, out.MapSessionSeq)
}

func mustRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return k
}
