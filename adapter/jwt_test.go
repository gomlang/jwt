package adapter

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"sync"
	"testing"
)

const testSecret = "0123456789abcdef0123456789abcdef"
const basicHeader = `{"alg":"HS256","typ":"JWT"}`

func mustHMAC(t *testing.T, id string) Key {
	t.Helper()
	key, err := HMACKey([]byte(testSecret), id)
	if err != "" {
		t.Fatal(err)
	}
	return key
}

func independentHMAC(header, claims string) string {
	input := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(claims))
	return independentHMACInput(input)
}

func independentHMACInput(input string) string {
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write([]byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func verifyTest(keys []Key, token string, now, leeway int64, issuer, audience string) string {
	_, _, err := Verify(keys, token, []string{"HS256"}, issuer, audience, "JWT", now, leeway, true, true, 65536)
	return err
}

func TestRFC7515AppendixA1(t *testing.T) {
	secret, err := base64.RawURLEncoding.DecodeString("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")
	if err != nil {
		t.Fatal(err)
	}
	key, failure := HMACKey(secret, "")
	if failure != "" {
		t.Fatal(failure)
	}
	token := "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	payload, _, failure := Verify([]Key{key}, token, []string{"HS256"}, "joe", "", "JWT", 1300819379, 0, true, true, 65536)
	if failure != "" || !strings.Contains(payload, `"iss":"joe"`) {
		t.Fatalf("RFC JWT rejected: %s", failure)
	}
	if !strings.HasPrefix(verifyTest([]Key{key}, token, 1300819380, 0, "joe", ""), "expired:") {
		t.Fatal("expiration boundary accepted")
	}
}

func TestRFC8037AppendixA4(t *testing.T) {
	public, _ := base64.RawURLEncoding.DecodeString("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
	sig, _ := base64.RawURLEncoding.DecodeString("hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg")
	key := Key{algorithm: "EdDSA", material: ed25519.PublicKey(public)}
	input := "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"
	if !verifySignature(key, []byte(input), sig) {
		t.Fatal("RFC EdDSA vector rejected")
	}
	_, _, err := Verify([]Key{key}, input+"."+base64.RawURLEncoding.EncodeToString(sig), []string{"EdDSA"}, "", "", "", 0, 0, false, true, 65536)
	if !strings.HasPrefix(err, "json:") {
		t.Fatal("non-JSON JWS payload accepted as JWT")
	}
}

func TestMalformedSignedTokens(t *testing.T) {
	key := mustHMAC(t, "")
	claims := []string{
		`{"exp":200,"exp":300}`, `{"exp":200,"\u0065xp":300}`,
		`{"exp":200,"data":{"a":1,"\u0061":2}}`, `{"exp":200} {}`,
		`{"exp":200,"x":"\ud800"}`, `{"exp":200,"x":"\udc00"}`,
		`{"exp":200,"x":"\ud800\u0041"}`, "{\"exp\":200,\"x\":\"\xff\"}",
		`{"exp":"200"}`, `{"exp":null}`, `{"exp":1e999999}`, `{"exp":1e-999999}`,
		`{"exp":200,"nbf":false}`, `{"exp":200,"iat":[]}`, `{"exp":200,"iss":4}`,
		`{"exp":200,"aud":[]}`, `{"exp":200,"aud":["api",false]}`, `[]`, `null`,
		`{"exp":200,"nested":` + strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65) + "}",
	}
	for _, value := range claims {
		t.Run(value, func(t *testing.T) {
			if err := verifyTest([]Key{key}, independentHMAC(basicHeader, value), 100, 0, "", ""); err == "" {
				t.Fatal("malformed claims accepted")
			}
		})
	}
	headers := []string{
		`{"alg":"HS256","alg":"HS256","typ":"JWT"}`,
		`{"alg":"HS256","\u0061lg":"HS256","typ":"JWT"}`,
		`{"alg":"none","typ":"JWT"}`, `{"alg":"RS256","typ":"JWT"}`,
		`{"alg":"HS256","typ":"JWT","crit":[]}`, `{"alg":"HS256","typ":"JWT","b64":true}`,
		`{"alg":"HS256","typ":"JWT","jku":"https://example.test"}`,
		`{"alg":"HS256","typ":"JWT","jwk":{}}`, `{"alg":"HS256","typ":"JWT","kid":null}`,
		`{"alg":"HS256","typ":"JWT","kid":""}`, `{"alg":"HS256","typ":"other"}`,
		`{"alg":"HS256"}`, `{"alg":"HS256","typ":"JWT","kid":"missing"}`,
	}
	for _, header := range headers {
		if err := verifyTest([]Key{key}, independentHMAC(header, `{"exp":200}`), 100, 0, "", ""); err == "" {
			t.Fatalf("malformed header accepted: %s", header)
		}
	}
	if err := verifyTest([]Key{key}, independentHMAC(basicHeader, `{"exp":200,"x":"\ud83d\ude00"}`), 100, 0, "", ""); err != "" {
		t.Fatal(err)
	}
}

func TestCanonicalBase64AndCompactShape(t *testing.T) {
	key := mustHMAC(t, "")
	token := independentHMAC(basicHeader, `{"exp":200}`)
	parts := strings.Split(token, ".")
	mutations := []string{"", token + ".", "." + parts[1] + "." + parts[2], parts[0] + "=." + parts[1] + "." + parts[2], parts[0] + "\n." + parts[1] + "." + parts[2], parts[0] + "." + parts[1] + ".", "A." + parts[1] + "." + parts[2]}
	for _, bad := range mutations {
		if verifyTest([]Key{key}, bad, 100, 0, "", "") == "" {
			t.Fatal("invalid compact form accepted")
		}
	}
	encoded := base64.RawURLEncoding.EncodeToString([]byte(`{"exp":200}`))
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, encoded[len(encoded)-1])
	badPayload := encoded[:len(encoded)-1] + string(alphabet[last+1])
	if _, err := base64.RawURLEncoding.DecodeString(badPayload); err != nil {
		t.Fatal("test must differ only in unused bits")
	}
	if err := verifyTest([]Key{key}, independentHMACInput(parts[0]+"."+badPayload), 100, 0, "", ""); !strings.HasPrefix(err, "format:") {
		t.Fatalf("signed noncanonical payload accepted: %s", err)
	}
	last = strings.IndexByte(alphabet, parts[2][len(parts[2])-1])
	badSignature := parts[2][:len(parts[2])-1] + string(alphabet[last+1])
	if verifyTest([]Key{key}, parts[0]+"."+parts[1]+"."+badSignature, 100, 0, "", "") == "" {
		t.Fatal("noncanonical signature accepted")
	}
}

func TestClaimPolicyBoundaries(t *testing.T) {
	key := mustHMAC(t, "")
	cases := []struct {
		claims                   string
		now, leeway              int64
		issuer, audience, prefix string
	}{
		{`{"exp":100}`, 100, 0, "", "", "expired:"},
		{`{"exp":100}`, 100, 1, "", "", ""},
		{`{"exp":100.000000000000000001}`, 100, 0, "", "", ""},
		{`{"exp":1e2}`, 100, 0, "", "", "expired:"},
		{`{"exp":200,"nbf":101}`, 100, 0, "", "", "not_yet_valid:"},
		{`{"exp":200,"nbf":101}`, 100, 1, "", "", ""},
		{`{"exp":200,"iat":101}`, 100, 0, "", "", "issued_at:"},
		{`{"exp":200,"iat":100}`, 100, 0, "", "", ""},
		{`{}`, 100, 0, "", "", "claims:"},
		{`{"exp":200,"iss":"issuer","aud":["other","api"]}`, 100, 0, "issuer", "api", ""},
		{`{"exp":200,"iss":"Issuer"}`, 100, 0, "issuer", "", "issuer:"},
		{`{"exp":200,"aud":"api"}`, 100, 0, "", "", "audience:"},
		{`{"exp":200,"aud":"api"}`, 100, 0, "", "api", ""},
		{`{"exp":200}`, 100, 0, "", "api", "audience:"},
	}
	for _, tc := range cases {
		err := verifyTest([]Key{key}, independentHMAC(basicHeader, tc.claims), tc.now, tc.leeway, tc.issuer, tc.audience)
		if tc.prefix == "" && err != "" || tc.prefix != "" && !strings.HasPrefix(err, tc.prefix) {
			t.Fatalf("%s: got %s, want %s", tc.claims, err, tc.prefix)
		}
	}
}

func TestKeySelectionLimitsAndSnapshot(t *testing.T) {
	secret := []byte(testSecret)
	key, err := HMACKey(secret, "v2")
	if err != "" {
		t.Fatal(err)
	}
	secret[0] ^= 1
	token := independentHMAC(`{"alg":"HS256","typ":"JWT","kid":"v2"}`, `{"exp":200}`)
	if err := verifyTest([]Key{mustHMAC(t, "v1"), key}, token, 100, 0, "", ""); err != "" {
		t.Fatal(err)
	}
	if verifyTest([]Key{key, key}, token, 100, 0, "", "") == "" {
		t.Fatal("ambiguous kid accepted")
	}
	if verifyTest([]Key{key, mustHMAC(t, "v1")}, independentHMAC(basicHeader, `{"exp":200}`), 100, 0, "", "") == "" {
		t.Fatal("ambiguous missing kid accepted")
	}
	for _, allowed := range [][]string{nil, {"none"}, {"HS256", "HS256"}, {"RS256"}} {
		if _, _, err := Verify([]Key{key}, token, allowed, "", "", "JWT", 100, 0, true, true, 65536); err == "" {
			t.Fatal("invalid algorithm allowlist accepted")
		}
	}
	for _, limit := range []int{0, 255, 1048577} {
		if _, _, err := Verify([]Key{key}, token, []string{"HS256"}, "", "", "JWT", 100, 0, true, true, limit); err == "" {
			t.Fatal("invalid limit accepted")
		}
	}
	if verifyTest([]Key{key}, token, 100, -1, "", "") == "" || verifyTest([]Key{key}, token, 100, 86401, "", "") == "" {
		t.Fatal("invalid leeway accepted")
	}
	for _, secret := range [][]byte{nil, []byte("short"), []byte("-----BEGIN PUBLIC KEY----- long enough secret")} {
		if _, err := HMACKey(secret, ""); err == "" {
			t.Fatal("weak or confusing secret accepted")
		}
	}
	if _, err := Sign(key, `{"exp":200,"blob":"`+strings.Repeat("x", 1000)+`"}`, "JWT", 256); !strings.HasPrefix(err, "limit:") {
		t.Fatal("oversized signed token accepted")
	}
}

func TestAsymmetricIndependentInteroperability(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		alg     string
		private crypto.Signer
	}{{"RS256", rsaKey}, {"ES256", ecKey}, {"EdDSA", edKey}} {
		t.Run(tc.alg, func(t *testing.T) {
			privateDER, err := x509.MarshalPKCS8PrivateKey(tc.private)
			if err != nil {
				t.Fatal(err)
			}
			publicDER, err := x509.MarshalPKIXPublicKey(tc.private.Public())
			if err != nil {
				t.Fatal(err)
			}
			privatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))
			publicPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))
			private, failure := PEMKey(tc.alg, privatePEM, "rotation", true)
			if failure != "" {
				t.Fatal(failure)
			}
			public, failure := PEMKey(tc.alg, publicPEM, "rotation", false)
			if failure != "" {
				t.Fatal(failure)
			}
			token, failure := Sign(private, `{"exp":200,"sub":"account"}`, "JWT", 65536)
			if failure != "" {
				t.Fatal(failure)
			}
			parts := strings.Split(token, ".")
			input := []byte(parts[0] + "." + parts[1])
			sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
			digest := sha256.Sum256(input)
			switch key := tc.private.Public().(type) {
			case *rsa.PublicKey:
				if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
					t.Fatal(err)
				}
			case *ecdsa.PublicKey:
				if len(sig) != 64 || !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
					t.Fatal("invalid independent ECDSA verification")
				}
			case ed25519.PublicKey:
				if !ed25519.Verify(key, input, sig) {
					t.Fatal("invalid independent Ed25519 verification")
				}
			}
			var external []byte
			switch key := tc.private.(type) {
			case *rsa.PrivateKey:
				external, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
			case *ecdsa.PrivateKey:
				var r, s *big.Int
				r, s, err = ecdsa.Sign(rand.Reader, key, digest[:])
				external = make([]byte, 64)
				r.FillBytes(external[:32])
				s.FillBytes(external[32:])
			case ed25519.PrivateKey:
				external = ed25519.Sign(key, input)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, _, failure := Verify([]Key{public}, string(input)+"."+base64.RawURLEncoding.EncodeToString(external), []string{tc.alg}, "", "", "JWT", 100, 0, true, true, 65536); failure != "" {
				t.Fatal(failure)
			}
			if _, failure := Sign(public, `{"exp":200}`, "JWT", 65536); failure == "" {
				t.Fatal("public key signed")
			}
			for _, wrong := range []string{"HS256", "RS256", "ES256", "EdDSA"} {
				if wrong == tc.alg {
					continue
				}
				if _, failure := PEMKey(wrong, publicPEM, "", false); failure == "" {
					t.Fatal("key algorithm confusion accepted")
				}
			}
			if _, failure := PEMKey(tc.alg, publicPEM+publicPEM, "", false); failure == "" {
				t.Fatal("multiple PEM blocks accepted")
			}
			if _, failure := PEMKey(tc.alg, privatePEM, "", false); failure == "" {
				t.Fatal("private key accepted through public import")
			}
		})
	}
}

func TestSharedKeysConcurrent(t *testing.T) {
	key := mustHMAC(t, "shared")
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 20 {
				token, err := Sign(key, `{"exp":200}`, "JWT", 65536)
				if err != "" {
					t.Error(err)
					return
				}
				if err := verifyTest([]Key{key}, token, 100, 0, "", ""); err != "" {
					t.Error(err)
					return
				}
			}
		})
	}
	workers.Wait()
}

func FuzzVerify(f *testing.F) {
	key, _ := HMACKey([]byte(testSecret), "")
	f.Add(independentHMAC(basicHeader, `{"exp":200}`))
	f.Add("..")
	f.Fuzz(func(t *testing.T, token string) {
		Verify([]Key{key}, token, []string{"HS256"}, "", "", "JWT", 100, 0, true, true, 65536)
	})
}
