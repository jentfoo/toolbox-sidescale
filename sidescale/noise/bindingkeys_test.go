package noise

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeRSADevice writes an RSA device key (PKCS#1 or PKCS#8 PEM) plus a matching
// self-signed cert, returning their paths.
func writeRSADevice(t *testing.T, pkcs8 bool) (certPath, keyPath string) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	dir := t.TempDir()

	keyDER, keyType := x509.MarshalPKCS1PrivateKey(priv), "RSA PRIVATE KEY"
	if pkcs8 {
		keyDER, err = x509.MarshalPKCS8PrivateKey(priv)
		require.NoError(t, err)
		keyType = "PRIVATE KEY"
	}
	keyPath = filepath.Join(dir, "device.key")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: keyType, Bytes: keyDER}), 0o600))

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "device"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	certPath = filepath.Join(dir, "device.crt")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600))
	return certPath, keyPath
}

// writeECKey writes an ECDSA private key (SEC1 or PKCS#8 PEM) on the given curve.
func writeECKey(t *testing.T, curve elliptic.Curve, pkcs8 bool) string {
	t.Helper()

	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	der, typ := mustMarshalEC(t, priv, pkcs8)
	path := filepath.Join(t.TempDir(), "hw.key")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600))
	return path
}

func mustMarshalEC(t *testing.T, priv *ecdsa.PrivateKey, pkcs8 bool) (der []byte, blockType string) {
	t.Helper()

	if pkcs8 {
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		require.NoError(t, err)
		return der, "PRIVATE KEY"
	}
	der, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	return der, "EC PRIVATE KEY"
}

func TestLoadBindingKeys(t *testing.T) {
	t.Parallel()

	t.Run("no_paths_returns_nil", func(t *testing.T) {
		signer, hwKey, err := LoadBindingKeys(&ControlConfig{})
		require.NoError(t, err)
		assert.Nil(t, signer)
		assert.Nil(t, hwKey)
	})

	t.Run("device_rsa_pkcs1", func(t *testing.T) {
		certPath, keyPath := writeRSADevice(t, false)
		signer, _, err := LoadBindingKeys(&ControlConfig{DeviceCertPath: certPath, DeviceKeyPath: keyPath})
		require.NoError(t, err)
		require.NotNil(t, signer)
		assert.NotNil(t, signer.Key)
		assert.NotEmpty(t, signer.CertChain)
	})

	t.Run("device_rsa_pkcs8", func(t *testing.T) {
		certPath, keyPath := writeRSADevice(t, true)
		signer, _, err := LoadBindingKeys(&ControlConfig{DeviceCertPath: certPath, DeviceKeyPath: keyPath})
		require.NoError(t, err)
		require.NotNil(t, signer)
		assert.NotNil(t, signer.Key)
	})

	t.Run("device_key_not_rsa", func(t *testing.T) {
		certPath, _ := writeRSADevice(t, false)
		ecPath := writeECKey(t, elliptic.P256(), true) // PKCS#8 EC parses but is not RSA
		_, _, err := LoadBindingKeys(&ControlConfig{DeviceCertPath: certPath, DeviceKeyPath: ecPath})
		require.ErrorContains(t, err, "not RSA")
	})

	t.Run("device_key_bad_pem", func(t *testing.T) {
		certPath, _ := writeRSADevice(t, false)
		badPath := filepath.Join(t.TempDir(), "bad.key")
		require.NoError(t, os.WriteFile(badPath, []byte("not a pem"), 0o600))
		_, _, err := LoadBindingKeys(&ControlConfig{DeviceCertPath: certPath, DeviceKeyPath: badPath})
		require.ErrorContains(t, err, "no PEM block")
	})

	t.Run("hw_ec_sec1_p256", func(t *testing.T) {
		path := writeECKey(t, elliptic.P256(), false)
		_, hwKey, err := LoadBindingKeys(&ControlConfig{HWKeyPath: path})
		require.NoError(t, err)
		require.NotNil(t, hwKey)
		assert.Equal(t, elliptic.P256(), hwKey.Curve)
	})

	t.Run("hw_ec_pkcs8_p256", func(t *testing.T) {
		path := writeECKey(t, elliptic.P256(), true)
		_, hwKey, err := LoadBindingKeys(&ControlConfig{HWKeyPath: path})
		require.NoError(t, err)
		require.NotNil(t, hwKey)
	})

	t.Run("hw_ec_wrong_curve", func(t *testing.T) {
		path := writeECKey(t, elliptic.P384(), false)
		_, _, err := LoadBindingKeys(&ControlConfig{HWKeyPath: path})
		require.ErrorContains(t, err, "P-256")
	})
}
