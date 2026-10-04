package adapter

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"unicode/utf8"
)

type Key struct {
	algorithm string
	id        string
	material  any
	private   bool
}

func algorithmValid(algorithm string) bool {
	return algorithm == "HS256" || algorithm == "RS256" || algorithm == "ES256" || algorithm == "EdDSA"
}

func validID(id string) bool {
	return len(id) <= 256 && utf8.ValidString(id) && !strings.ContainsAny(id, "\x00\r\n")
}

func HMACKey(secret []byte, id string) (Key, string) {
	if len(secret) < 32 || len(secret) > 65536 || bytes.Contains(secret, []byte("-----BEGIN ")) || !validID(id) {
		return Key{}, "key: HS256 requires 32..65536 secret bytes and a valid key id"
	}
	return Key{algorithm: "HS256", id: id, material: bytes.Clone(secret), private: true}, ""
}

func PEMKey(algorithm, input, id string, private bool) (Key, string) {
	if algorithm == "HS256" || !algorithmValid(algorithm) || len(input) > 65536 || !validID(id) {
		return Key{}, "key: invalid PEM key configuration"
	}
	trimmed := strings.TrimSpace(input)
	// pem.Decode searches past malformed blocks, so rest alone cannot prove
	// that the supplied input contained exactly one block.
	if !strings.HasPrefix(trimmed, "-----BEGIN ") || strings.Count(trimmed, "-----BEGIN ") != 1 {
		return Key{}, "key: expected one PEM block"
	}
	block, rest := pem.Decode([]byte(trimmed))
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 {
		return Key{}, "key: expected one unencrypted PEM block"
	}
	var material any
	var err error
	if private {
		switch block.Type {
		case "PRIVATE KEY":
			material, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		case "RSA PRIVATE KEY":
			material, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			material, err = x509.ParseECPrivateKey(block.Bytes)
		default:
			return Key{}, "key: unsupported private PEM block"
		}
	} else {
		switch block.Type {
		case "PUBLIC KEY":
			material, err = x509.ParsePKIXPublicKey(block.Bytes)
		case "RSA PUBLIC KEY":
			material, err = x509.ParsePKCS1PublicKey(block.Bytes)
		default:
			return Key{}, "key: expected public key PEM, not a certificate or private key"
		}
	}
	if err != nil {
		return Key{}, "key: invalid key encoding"
	}
	valid := false
	switch key := material.(type) {
	case *rsa.PrivateKey:
		valid = algorithm == "RS256" && key.N.BitLen() >= 2048 && key.N.BitLen() <= 8192 && key.Validate() == nil
	case *rsa.PublicKey:
		valid = algorithm == "RS256" && key.N.BitLen() >= 2048 && key.N.BitLen() <= 8192 && key.E >= 3 && key.E%2 == 1
	case *ecdsa.PrivateKey:
		valid = algorithm == "ES256" && key.Curve == elliptic.P256()
	case *ecdsa.PublicKey:
		valid = algorithm == "ES256" && key.Curve == elliptic.P256() && key.Curve.IsOnCurve(key.X, key.Y)
	case ed25519.PrivateKey:
		valid = algorithm == "EdDSA" && len(key) == ed25519.PrivateKeySize
	case ed25519.PublicKey:
		valid = algorithm == "EdDSA" && len(key) == ed25519.PublicKeySize
	}
	if !valid {
		return Key{}, "key: key type or strength does not match algorithm"
	}
	return Key{algorithm: algorithm, id: id, material: material, private: private}, ""
}

func KeyID(key Key) string { return key.id }

func KeyAlgorithm(key Key) string { return key.algorithm }
