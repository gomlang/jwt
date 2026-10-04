package adapter

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestPEMKeyRejectsSkippedMalformedBlocks(t *testing.T) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		der     []byte
		private bool
	}{
		{"PUBLIC KEY", publicDER, false},
		{"PRIVATE KEY", privateDER, true},
	} {
		valid := string(pem.EncodeToMemory(&pem.Block{Type: tc.name, Bytes: tc.der}))
		for _, prefix := range []string{
			"-----BEGIN " + tc.name + "-----\nnot base64!\n-----END " + tc.name + "-----\n",
			"-----BEGIN " + tc.name + "-----\nAAAA\n-----END WRONG TYPE-----\n",
			"-----BEGIN " + tc.name + "-----\n",
		} {
			t.Run(tc.name+"/"+prefix, func(t *testing.T) {
				if _, failure := PEMKey("EdDSA", prefix+valid, "", tc.private); failure == "" {
					t.Fatal("malformed leading PEM block was silently skipped")
				}
			})
		}
		for _, input := range []string{valid, " \t\n" + valid + " \t\n", strings.ReplaceAll(valid, "\n", "\r\n")} {
			if _, failure := PEMKey("EdDSA", input, "", tc.private); failure != "" {
				t.Fatalf("valid single PEM block rejected: %s", failure)
			}
		}
	}
}
