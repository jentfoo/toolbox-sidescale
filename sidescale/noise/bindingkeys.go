package noise

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/jentfoo/toolbox-sidescale/sidescale/noise/bindings"
)

// LoadBindingKeys loads the replay rebind key material from the configured PEM paths;
// missing paths yield nil (bindings then strip), a malformed PEM is an error.
func LoadBindingKeys(cfg *ControlConfig) (*bindings.RegisterSigner, *ecdsa.PrivateKey, error) {
	var signer *bindings.RegisterSigner
	if cfg.DeviceCertPath != "" && cfg.DeviceKeyPath != "" {
		keyPEM, err := os.ReadFile(cfg.DeviceKeyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("sidescale: read device key: %w", err)
		}
		rsaKey, err := parseRSAPrivateKey(keyPEM)
		if err != nil {
			return nil, nil, err
		}
		certPEM, err := os.ReadFile(cfg.DeviceCertPath)
		if err != nil {
			return nil, nil, fmt.Errorf("sidescale: read device cert: %w", err)
		}
		chain, err := parseCertChain(certPEM)
		if err != nil {
			return nil, nil, err
		}
		signer = &bindings.RegisterSigner{Key: rsaKey, CertChain: chain}
	}

	var hwKey *ecdsa.PrivateKey
	if cfg.HWKeyPath != "" {
		keyPEM, err := os.ReadFile(cfg.HWKeyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("sidescale: read hw key: %w", err)
		}
		if hwKey, err = parseECPrivateKey(keyPEM); err != nil {
			return nil, nil, err
		}
	}
	return signer, hwKey, nil
}

func parseRSAPrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("sidescale: device key: no PEM block")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("sidescale: parse device key: %w", err)
	}
	rsaKey, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("sidescale: device key is not RSA")
	}
	return rsaKey, nil
}

func parseECPrivateKey(pemData []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("sidescale: hw key: no PEM block")
	}
	ecKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// SEC1 parse failed, try PKCS#8
		k, perr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if perr != nil {
			return nil, fmt.Errorf("sidescale: parse hw key: %w", perr)
		}
		var ok bool
		if ecKey, ok = k.(*ecdsa.PrivateKey); !ok {
			return nil, errors.New("sidescale: hw key is not ECDSA")
		}
	}
	if ecKey.Curve != elliptic.P256() {
		return nil, errors.New("sidescale: hw key must be P-256")
	}
	return ecKey, nil
}

// parseCertChain returns the DER bytes of each certificate in a PEM chain.
func parseCertChain(pemData []byte) ([][]byte, error) {
	var chain [][]byte
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			chain = append(chain, block.Bytes)
		}
	}
	if len(chain) == 0 {
		return nil, errors.New("sidescale: device cert: no certificates in PEM")
	}
	return chain, nil
}
