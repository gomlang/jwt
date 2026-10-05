package adapter

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"sync"
	"testing"
)

const edJWK = `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`

func jwkJSON(value any) string       { data, _ := json.Marshal(value); return string(data) }
func jwkEncoded(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }
func jwkObject(input string) map[string]any {
	var object map[string]any
	_ = json.Unmarshal([]byte(input), &object)
	return object
}
func jwkField(input, name string, value any) string {
	object := jwkObject(input)
	object[name] = value
	return jwkJSON(object)
}

func TestJWKIndependentSignaturesAndConcurrentVerification(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPrivate := ed25519.NewKeyFromSeed(make([]byte, 32))
	cases := []struct {
		algorithm string
		object    map[string]any
		private   crypto.Signer
	}{
		{"RS256", map[string]any{"kty": "RSA", "n": jwkEncoded(rsaKey.N.Bytes()), "e": "AQAB"}, rsaKey},
		{"ES256", map[string]any{"kty": "EC", "crv": "P-256", "x": jwkEncoded(ecKey.X.FillBytes(make([]byte, 32))), "y": jwkEncoded(ecKey.Y.FillBytes(make([]byte, 32)))}, ecKey},
		{"EdDSA", map[string]any{"kty": "OKP", "crv": "Ed25519", "x": jwkEncoded(edPrivate.Public().(ed25519.PublicKey))}, edPrivate},
	}
	entries := []any{}
	tokens := []string{}
	for _, tc := range cases {
		tc.object["kid"] = tc.algorithm
		tc.object["alg"] = tc.algorithm
		tc.object["use"] = "sig"
		tc.object["key_ops"] = []string{"verify"}
		entries = append(entries, tc.object)
		public, failure := PublicJWK(tc.algorithm, jwkJSON(tc.object))
		if failure != "" {
			t.Fatal(failure)
		}
		if public.private || KeyID(public) != tc.algorithm || KeyAlgorithm(public) != tc.algorithm {
			t.Fatal("incorrect key binding")
		}
		input := jwkEncoded([]byte(jwkJSON(map[string]string{"alg": tc.algorithm, "typ": "JWT", "kid": tc.algorithm}))) + "." + jwkEncoded([]byte(`{"exp":200,"sub":"independent"}`))
		digest := sha256.Sum256([]byte(input))
		var signature []byte
		switch key := tc.private.(type) {
		case *rsa.PrivateKey:
			signature, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		case *ecdsa.PrivateKey:
			var r, s *big.Int
			r, s, err = ecdsa.Sign(rand.Reader, key, digest[:])
			signature = make([]byte, 64)
			r.FillBytes(signature[:32])
			s.FillBytes(signature[32:])
		case ed25519.PrivateKey:
			signature = ed25519.Sign(key, []byte(input))
		}
		if err != nil {
			t.Fatal(err)
		}
		token := input + "." + jwkEncoded(signature)
		tokens = append(tokens, token)
		if _, _, failure = Verify([]Key{public}, token, []string{tc.algorithm}, "", "", "JWT", 100, 0, true, true, 65536); failure != "" {
			t.Fatal(failure)
		}
		if _, failure = Sign(public, `{"exp":200}`, "JWT", 65536); !strings.HasPrefix(failure, "key:") {
			t.Fatal("public JWK signed")
		}
		for _, wrong := range []string{"HS256", "RS256", "ES256", "EdDSA"} {
			if wrong != tc.algorithm {
				if _, failure := PublicJWK(wrong, jwkJSON(tc.object)); failure == "" {
					t.Fatal("algorithm confusion")
				}
			}
		}
	}
	set, failure := PublicJWKS(jwkJSON(map[string]any{"keys": entries}), []string{"RS256", "ES256", "EdDSA"})
	if failure != "" || len(set) != 3 {
		t.Fatal(failure)
	}
	// Import returns material independent of the input object and later imports.
	for _, entry := range entries {
		clear(entry.(map[string]any))
	}
	var wait sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for round := 0; round < 20; round++ {
				for _, token := range tokens {
					if _, _, failure := Verify(set, token, []string{"RS256", "ES256", "EdDSA"}, "", "", "JWT", 100, 0, true, true, 65536); failure != "" {
						t.Error(failure)
					}
				}
			}
		}()
	}
	wait.Wait()
}

func TestJWKMetadataAndPrivateMaterialRejection(t *testing.T) {
	for _, field := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k", "n", "e", "y"} {
		for _, value := range []any{nil, "", []any{}, map[string]any{}} {
			if _, failure := PublicJWK("EdDSA", jwkField(edJWK, field, value)); !strings.HasPrefix(failure, "key:") {
				t.Fatalf("accepted %s: %s", field, failure)
			}
		}
	}
	for field, values := range map[string][]any{
		"kty": {nil, []any{}, "oct", "EC", "okp", 1}, "crv": {nil, []any{}, "X25519", "Ed448", "ed25519"},
		"alg": {nil, []any{}, "HS256", "Ed25519", "none", ""}, "use": {nil, []any{}, "enc", "SIG", ""},
		"key_ops": {nil, "verify", []any{}, []any{"verify", "verify"}, []any{"sign", "verify"}, []any{"encrypt"}, []any{nil}, []any{map[string]any{}}},
		"kid":     {nil, []any{}, "", "bad\x00id", "bad\rid", "bad\nid", strings.Repeat("é", 129)},
	} {
		for _, value := range values {
			if _, failure := PublicJWK("EdDSA", jwkField(edJWK, field, value)); failure == "" {
				t.Fatalf("accepted %s", field)
			}
		}
	}
	for _, input := range []string{edJWK, jwkField(edJWK, "kid", strings.Repeat("é", 128)), jwkField(edJWK, "use", "sig"), jwkField(edJWK, "key_ops", []string{"verify"}), jwkField(edJWK, "x5u", "https://unused.invalid/key"), jwkField(edJWK, "x5c", []string{"ignored"}), jwkField(edJWK, "extension", map[string]any{"nested": true})} {
		if _, failure := PublicJWK("EdDSA", input); failure != "" {
			t.Fatal(failure)
		}
	}
	for _, field := range []string{"kty", "crv", "x"} {
		object := jwkObject(edJWK)
		delete(object, field)
		if _, failure := PublicJWK("EdDSA", jwkJSON(object)); failure == "" {
			t.Fatalf("accepted missing %s", field)
		}
	}
}

func TestJWKCanonicalEncodingAndStrictJSON(t *testing.T) {
	validX := jwkObject(edJWK)["x"].(string)
	for _, x := range []any{nil, 3, "", validX + "=", validX + "\n", strings.Replace(validX, "_", "/", 1), validX[:42] + "p", jwkEncoded(make([]byte, 31)), jwkEncoded(make([]byte, 33))} {
		if _, failure := PublicJWK("EdDSA", jwkField(edJWK, "x", x)); !strings.HasPrefix(failure, "key:") {
			t.Fatalf("invalid x accepted: %s", failure)
		}
	}
	for _, input := range []string{"[]", "null", edJWK + " {}", `{"kty":"OKP","kty":"OKP"}`, `{"kty":"OKP","\u006bty":"OKP"}`, jwkField(edJWK, "extra", nil)[:len(jwkField(edJWK, "extra", nil))-1] + `,"extra":false}`, `{"a":{"n":1,"\u006e":2}}`, `{"x":"\ud800"}`, "{\"x\":\"\xff\"}", `{"x":` + strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65) + "}", `{"x":[` + strings.Repeat("0,", 16384) + "0]}"} {
		if _, failure := PublicJWK("EdDSA", input); !strings.HasPrefix(failure, "json:") {
			t.Fatalf("strict JSON: %s", failure)
		}
	}
	if _, failure := PublicJWK("EdDSA", edJWK+strings.Repeat(" ", 65536-len(edJWK))); failure != "" {
		t.Fatal(failure)
	}
	if _, failure := PublicJWK("EdDSA", strings.Repeat(" ", 65537)); !strings.HasPrefix(failure, "limit:") {
		t.Fatal(failure)
	}
	for _, alg := range []string{"", "none", "HS256", "Ed25519"} {
		if _, failure := PublicJWK(alg, edJWK); !strings.HasPrefix(failure, "algorithm:") {
			t.Fatal(failure)
		}
	}
}

func TestJWKRSAAndECCoordinateBounds(t *testing.T) {
	modulus := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 2047), big.NewInt(1))
	rsaObject := map[string]any{"kty": "RSA", "n": jwkEncoded(modulus.Bytes()), "e": "AQAB"}
	for _, bits := range []uint{2048, 8192} {
		n := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), bits-1), big.NewInt(1))
		if _, failure := PublicJWK("RS256", jwkField(jwkJSON(rsaObject), "n", jwkEncoded(n.Bytes()))); failure != "" {
			t.Fatal(failure)
		}
	}
	for _, n := range [][]byte{nil, {0}, append([]byte{0}, modulus.Bytes()...), new(big.Int).Lsh(big.NewInt(1), 2047).Bytes(), new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 2046), big.NewInt(1)).Bytes(), new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 8192), big.NewInt(1)).Bytes()} {
		if _, failure := PublicJWK("RS256", jwkField(jwkJSON(rsaObject), "n", jwkEncoded(n))); failure == "" {
			t.Fatal("invalid modulus accepted")
		}
	}
	for _, e := range [][]byte{nil, {0}, {1}, {2}, {4}, {0, 1, 0, 1}, {128, 0, 0, 1}, {1, 0, 0, 0, 1}} {
		if _, failure := PublicJWK("RS256", jwkField(jwkJSON(rsaObject), "e", jwkEncoded(e))); failure == "" {
			t.Fatal("invalid exponent accepted")
		}
	}
	for _, e := range [][]byte{{3}, {1, 0, 1}, {127, 255, 255, 255}} {
		if _, failure := PublicJWK("RS256", jwkField(jwkJSON(rsaObject), "e", jwkEncoded(e))); failure != "" {
			t.Fatal(failure)
		}
	}
	for _, field := range []string{"n", "e"} {
		object := jwkObject(jwkJSON(rsaObject))
		delete(object, field)
		if _, failure := PublicJWK("RS256", jwkJSON(object)); failure == "" {
			t.Fatal("missing RSA parameter")
		}
	}
	curve := elliptic.P256()
	x, y := curve.ScalarBaseMult([]byte{1})
	// Find a genuine P-256 point needing a leading zero coordinate octet.
	for scalar := int64(1); x.BitLen() > 248 && scalar < 10000; scalar++ {
		x, y = curve.ScalarBaseMult(big.NewInt(scalar).Bytes())
	}
	if x.BitLen() > 248 {
		t.Fatal("leading zero fixture not found")
	}
	ecObject := map[string]any{"kty": "EC", "crv": "P-256", "x": jwkEncoded(x.FillBytes(make([]byte, 32))), "y": jwkEncoded(y.FillBytes(make([]byte, 32)))}
	if _, failure := PublicJWK("ES256", jwkJSON(ecObject)); failure != "" {
		t.Fatal(failure)
	}
	for _, field := range []string{"x", "y"} {
		for _, bad := range []any{nil, jwkEncoded(make([]byte, 31)), jwkEncoded(make([]byte, 33)), jwkEncoded(curve.Params().P.FillBytes(make([]byte, 32))), jwkEncoded(make([]byte, 32))} {
			if _, failure := PublicJWK("ES256", jwkField(jwkJSON(ecObject), field, bad)); failure == "" {
				t.Fatal("invalid EC coordinate accepted")
			}
		}
	}
	if _, failure := PublicJWK("ES256", jwkField(jwkJSON(ecObject), "crv", "P-384")); failure == "" {
		t.Fatal("wrong curve accepted")
	}
}

func TestJWKSAllOrNothingSelectionAndBounds(t *testing.T) {
	valid := jwkField(edJWK, "kid", "active")
	input := `{"keys":[` + valid + `]}`
	for _, allow := range [][]string{{"EdDSA"}, {"RS256", "ES256", "EdDSA"}} {
		if keys, failure := PublicJWKS(input, allow); failure != "" || len(keys) != 1 {
			t.Fatal(failure)
		}
	}
	for _, allow := range [][]string{nil, {"HS256"}, {"EdDSA", "EdDSA"}, {"RS256"}, {"EdDSA", "RS256", "ES256", "HS256"}} {
		if keys, failure := PublicJWKS(input, allow); failure == "" || keys != nil {
			t.Fatal("invalid allowlist accepted or partial result")
		}
	}
	for _, bad := range []string{`{}`, `{"keys":null}`, `{"keys":{}}`, `{"keys":[]}`, `{"keys":[null]}`, `{"keys":[` + edJWK + `]}`, `{"keys":[` + valid + `,` + valid + `]}`, `{"keys":[` + valid + `,{}]}`, `{"keys":[],"\u006beys":[]}`} {
		if keys, failure := PublicJWKS(bad, []string{"EdDSA"}); failure == "" || keys != nil {
			t.Fatalf("invalid set accepted: %s", bad)
		}
	}
	entries := []any{}
	for i := 0; i < 64; i++ {
		entries = append(entries, jwkObject(jwkField(edJWK, "kid", big.NewInt(int64(i)).String())))
	}
	maximum := jwkJSON(map[string]any{"keys": entries})
	if keys, failure := PublicJWKS(maximum, []string{"EdDSA"}); failure != "" || len(keys) != 64 {
		t.Fatal(failure)
	}
	if _, failure := PublicJWKS(maximum+strings.Repeat(" ", 1048576-len(maximum)), []string{"EdDSA"}); failure != "" {
		t.Fatal(failure)
	}
	entries = append(entries, jwkObject(valid))
	if keys, failure := PublicJWKS(jwkJSON(map[string]any{"keys": entries}), []string{"EdDSA"}); !strings.HasPrefix(failure, "limit:") || keys != nil {
		t.Fatal(failure)
	}
	if _, failure := PublicJWKS(strings.Repeat(" ", 1048577), []string{"EdDSA"}); !strings.HasPrefix(failure, "limit:") {
		t.Fatal(failure)
	}
	// IDs are globally unique even across different algorithm families.
	ec := map[string]any{"kty": "EC", "crv": "P-256", "kid": "active", "x": jwkEncoded(elliptic.P256().Params().Gx.FillBytes(make([]byte, 32))), "y": jwkEncoded(elliptic.P256().Params().Gy.FillBytes(make([]byte, 32)))}
	if keys, failure := PublicJWKS(`{"keys":[`+valid+`,`+jwkJSON(ec)+`]}`, []string{"EdDSA", "ES256"}); !strings.HasPrefix(failure, "key:") || keys != nil {
		t.Fatal("cross-alg duplicate id accepted")
	}
}
