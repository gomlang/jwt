package adapter

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"math/big"
)

func publicAlgorithm(algorithm string) bool {
	return algorithm == "RS256" || algorithm == "ES256" || algorithm == "EdDSA"
}

// PublicJWK imports public verification material without inferring policy from JSON.
func PublicJWK(algorithm, input string) (Key, string) {
	if len(input) > 65536 {
		return Key{}, "limit: JWK exceeds 65536 bytes"
	}
	if !publicAlgorithm(algorithm) {
		return Key{}, "algorithm: JWK requires an asymmetric verification algorithm"
	}
	object, failure := strictObject(input)
	if failure != "" {
		return Key{}, failure
	}
	return publicJWK(algorithm, object)
}

// PublicJWKS imports the complete set or returns no keys. Unknown or disallowed
// key types are errors, not entries silently removed from a rotation set.
func PublicJWKS(input string, allowed []string) ([]Key, string) {
	if len(input) > 1048576 {
		return nil, "limit: JWKS exceeds 1048576 bytes"
	}
	if len(allowed) == 0 || len(allowed) > 3 {
		return nil, "algorithm: invalid JWK algorithm allowlist"
	}
	algorithms := make(map[string]bool, len(allowed))
	for _, algorithm := range allowed {
		if !publicAlgorithm(algorithm) || algorithms[algorithm] {
			return nil, "algorithm: invalid JWK algorithm allowlist"
		}
		algorithms[algorithm] = true
	}
	object, failure := strictObject(input)
	if failure != "" {
		return nil, failure
	}
	entries, ok := object["keys"].([]any)
	if !ok {
		return nil, "key: JWKS requires a keys array"
	}
	if len(entries) == 0 || len(entries) > 64 {
		return nil, "limit: JWKS requires 1..64 keys"
	}
	keys := make([]Key, 0, len(entries))
	ids := make(map[string]bool, len(entries))
	for _, entry := range entries {
		jwk, ok := entry.(map[string]any)
		if !ok {
			return nil, "key: JWKS entries must be objects"
		}
		var algorithm string
		switch jwk["kty"] {
		case "RSA":
			algorithm = "RS256"
		case "EC":
			algorithm = "ES256"
		case "OKP":
			algorithm = "EdDSA"
		}
		if !algorithms[algorithm] {
			return nil, "algorithm: unsupported or disallowed JWK key type"
		}
		key, failure := publicJWK(algorithm, jwk)
		if failure != "" {
			return nil, failure
		}
		if key.id == "" || ids[key.id] {
			return nil, "key: JWKS requires nonempty unique key ids"
		}
		ids[key.id] = true
		keys = append(keys, key)
	}
	return keys, ""
}

func jwkBytes(object map[string]any, name string, maxEncoded int) ([]byte, bool) {
	value, ok := object[name].(string)
	if !ok {
		return nil, false
	}
	return decodeSegment(value, maxEncoded)
}

func publicJWK(algorithm string, object map[string]any) (Key, string) {
	for _, name := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		if _, exists := object[name]; exists {
			return Key{}, "key: private or symmetric JWK material is not accepted"
		}
	}
	if value, exists := object["alg"]; exists && value != algorithm {
		return Key{}, "algorithm: JWK algorithm does not match policy"
	}
	if value, exists := object["use"]; exists && value != "sig" {
		return Key{}, "key: JWK use must be sig"
	}
	if value, exists := object["key_ops"]; exists {
		operations, ok := value.([]any)
		if !ok || len(operations) != 1 || operations[0] != "verify" {
			return Key{}, "key: JWK key_ops must contain only verify"
		}
	}
	id := ""
	if value, exists := object["kid"]; exists {
		var ok bool
		id, ok = value.(string)
		if !ok || id == "" || !validID(id) {
			return Key{}, "key: invalid JWK key id"
		}
	}
	kty, ok := object["kty"].(string)
	if !ok || (algorithm == "RS256" && kty != "RSA") ||
		(algorithm == "ES256" && kty != "EC") || (algorithm == "EdDSA" && kty != "OKP") {
		return Key{}, "key: JWK type does not match algorithm"
	}
	for _, name := range []string{"n", "e", "crv", "x", "y"} {
		permitted := (kty == "RSA" && (name == "n" || name == "e")) ||
			(kty == "EC" && (name == "crv" || name == "x" || name == "y")) ||
			(kty == "OKP" && (name == "crv" || name == "x"))
		if _, exists := object[name]; exists && !permitted {
			return Key{}, "key: conflicting JWK key parameters"
		}
	}
	key := Key{algorithm: algorithm, id: id}
	switch kty {
	case "RSA":
		n, nOK := jwkBytes(object, "n", 1366)
		e, eOK := jwkBytes(object, "e", 6)
		if !nOK || !eOK || len(n) == 0 || len(e) == 0 || n[0] == 0 || e[0] == 0 {
			return Key{}, "key: invalid RSA JWK integer encoding"
		}
		modulus, exponent := new(big.Int).SetBytes(n), new(big.Int).SetBytes(e)
		if modulus.BitLen() < 2048 || modulus.BitLen() > 8192 || modulus.Bit(0) == 0 ||
			exponent.BitLen() > 31 || exponent.Int64() < 3 || exponent.Bit(0) == 0 {
			return Key{}, "key: invalid RSA JWK modulus or exponent"
		}
		key.material = &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}
	case "EC":
		x, xOK := jwkBytes(object, "x", 43)
		y, yOK := jwkBytes(object, "y", 43)
		if object["crv"] != "P-256" || !xOK || !yOK || len(x) != 32 || len(y) != 32 {
			return Key{}, "key: ES256 JWK requires P-256 and 32-byte coordinates"
		}
		pointX, pointY := new(big.Int).SetBytes(x), new(big.Int).SetBytes(y)
		if !elliptic.P256().IsOnCurve(pointX, pointY) {
			return Key{}, "key: invalid P-256 JWK point"
		}
		key.material = &ecdsa.PublicKey{Curve: elliptic.P256(), X: pointX, Y: pointY}
	case "OKP":
		x, ok := jwkBytes(object, "x", 43)
		if object["crv"] != "Ed25519" || !ok || len(x) != ed25519.PublicKeySize {
			return Key{}, "key: EdDSA JWK requires Ed25519 and a 32-byte public key"
		}
		key.material = ed25519.PublicKey(x)
	}
	return key, ""
}
