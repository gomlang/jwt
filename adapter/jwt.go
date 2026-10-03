package adapter

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"time"
)

func Now() int64 { return time.Now().Unix() }

func validLimit(limit int) bool { return limit >= 256 && limit <= 1048576 }

func decodeSegment(segment string, limit int) ([]byte, bool) {
	if len(segment) == 0 || len(segment) > limit || len(segment)%4 == 1 {
		return nil, false
	}
	for _, ch := range []byte(segment) {
		if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
			return nil, false
		}
	}
	value, err := base64.RawURLEncoding.Strict().DecodeString(segment)
	return value, err == nil
}

func signature(key Key, input []byte) ([]byte, string) {
	if !key.private {
		return nil, "key: signing requires a private key"
	}
	digest := sha256.Sum256(input)
	switch material := key.material.(type) {
	case []byte:
		if key.algorithm != "HS256" {
			break
		}
		mac := hmac.New(sha256.New, material)
		mac.Write(input)
		return mac.Sum(nil), ""
	case *rsa.PrivateKey:
		if key.algorithm != "RS256" {
			break
		}
		value, err := rsa.SignPKCS1v15(rand.Reader, material, crypto.SHA256, digest[:])
		if err != nil {
			return nil, "signature: RSA signing failed"
		}
		return value, ""
	case *ecdsa.PrivateKey:
		if key.algorithm != "ES256" {
			break
		}
		r, s, err := ecdsa.Sign(rand.Reader, material, digest[:])
		if err != nil {
			return nil, "signature: ECDSA signing failed"
		}
		value := make([]byte, 64)
		r.FillBytes(value[:32])
		s.FillBytes(value[32:])
		return value, ""
	case ed25519.PrivateKey:
		if key.algorithm != "EdDSA" {
			break
		}
		return ed25519.Sign(material, input), ""
	}
	return nil, "key: invalid signing key"
}

func verifySignature(key Key, input, signature []byte) bool {
	digest := sha256.Sum256(input)
	material := key.material
	switch private := material.(type) {
	case *rsa.PrivateKey:
		material = &private.PublicKey
	case *ecdsa.PrivateKey:
		material = &private.PublicKey
	case ed25519.PrivateKey:
		material = private.Public()
	}
	switch public := material.(type) {
	case []byte:
		if key.algorithm != "HS256" || len(signature) != 32 {
			return false
		}
		mac := hmac.New(sha256.New, public)
		mac.Write(input)
		return hmac.Equal(signature, mac.Sum(nil))
	case *rsa.PublicKey:
		return key.algorithm == "RS256" && rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature) == nil
	case *ecdsa.PublicKey:
		return key.algorithm == "ES256" && len(signature) == 64 && ecdsa.Verify(public, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:]))
	case ed25519.PublicKey:
		return key.algorithm == "EdDSA" && ed25519.Verify(public, input, signature)
	}
	return false
}

func Sign(key Key, claims, tokenType string, limit int) (string, string) {
	if !validLimit(limit) || len(claims) > limit || len(tokenType) == 0 || len(tokenType) > 256 || !validID(tokenType) {
		return "", "limit: invalid signing limits or token type"
	}
	object, err := strictObject(claims)
	if err != "" {
		return "", err
	}
	if err := validateClaimTypes(object); err != "" {
		return "", err
	}
	header := map[string]string{"alg": key.algorithm, "typ": tokenType}
	if key.id != "" {
		header["kid"] = key.id
	}
	headerJSON, _ := json.Marshal(header)
	input := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString([]byte(claims))
	signature, err := signature(key, []byte(input))
	if err != "" {
		return "", err
	}
	token := input + "." + base64.RawURLEncoding.EncodeToString(signature)
	if len(token) > limit {
		return "", "limit: signed token exceeds configured limit"
	}
	return token, ""
}

func Verify(keys []Key, token string, allowed []string, issuer, audience, tokenType string, now, leeway int64, requireExpiration, checkIssuedAt bool, limit int) (string, string, string) {
	if !validLimit(limit) || len(token) > limit || len(keys) == 0 || len(keys) > 64 || len(allowed) == 0 || len(allowed) > 4 || leeway < 0 || leeway > 86400 || now < -253402300799 || now > 253402300799 || len(issuer) > 4096 || len(audience) > 4096 || len(tokenType) > 256 {
		return "", "", "limit: invalid verification configuration or token size"
	}
	algorithms := map[string]bool{}
	for _, alg := range allowed {
		if !algorithmValid(alg) || algorithms[alg] {
			return "", "", "algorithm: invalid allowlist"
		}
		algorithms[alg] = true
	}
	if strings.Count(token, ".") != 2 {
		return "", "", "format: expected three compact JWS segments"
	}
	parts := strings.Split(token, ".")
	headerBytes, ok := decodeSegment(parts[0], 8192)
	if !ok {
		return "", "", "format: invalid header base64url"
	}
	header, err := strictObject(string(headerBytes))
	if err != "" {
		return "", "", err
	}
	alg, ok := header["alg"].(string)
	if !ok || !algorithms[alg] {
		return "", "", "algorithm: disallowed token algorithm"
	}
	for _, field := range []string{"crit", "b64", "jku", "jwk", "x5u", "x5c"} {
		if _, exists := header[field]; exists {
			return "", "", "header: unsupported JOSE extension or embedded key"
		}
	}
	id := ""
	if value, exists := header["kid"]; exists {
		id, ok = value.(string)
		if !ok || id == "" || !validID(id) {
			return "", "", "header: invalid key id"
		}
	}
	if value, exists := header["typ"]; exists {
		typ, ok := value.(string)
		if !ok || len(typ) > 256 || (tokenType != "" && typ != tokenType) {
			return "", "", "header: unexpected token type"
		}
	} else if tokenType != "" {
		return "", "", "header: missing token type"
	}
	var key Key
	matches := 0
	for _, candidate := range keys {
		if candidate.algorithm == alg && (id == "" || candidate.id == id) {
			key = candidate
			matches++
		}
	}
	if matches != 1 {
		return "", "", "key: unknown or ambiguous key id"
	}
	sig, ok := decodeSegment(parts[2], 2048)
	if !ok {
		return "", "", "format: invalid signature base64url"
	}
	if !verifySignature(key, []byte(parts[0]+"."+parts[1]), sig) {
		return "", "", "signature: verification failed"
	}
	payload, ok := decodeSegment(parts[1], limit)
	if !ok {
		return "", "", "format: invalid claims base64url"
	}
	claims, err := strictObject(string(payload))
	if err != "" {
		return "", "", err
	}
	if err := validateClaims(claims, issuer, audience, now, leeway, requireExpiration, checkIssuedAt); err != "" {
		return "", "", err
	}
	return string(payload), key.id, ""
}
