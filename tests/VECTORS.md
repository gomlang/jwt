# JWT test vectors

The complete test suite is GoML and runs without an adapter or native Go test dependency. All keys and secrets below are public test material.

`jwt_test.goml` uses the HS256 key and compact token from RFC 7515 Appendix A.1. `security_reference_test.goml` authenticates the Ed25519 JWS from RFC 8037 Appendix A.4 before rejecting its non-JSON payload, and checks that a corrupted signature fails before JSON parsing.

`jwk_test.goml` retains the three frozen independent RS256, ES256 and Ed25519 JWTs previously used by the GoML public API suite. They were produced with Go 1.26 `crypto/rsa.SignPKCS1v15`, `crypto/ecdsa.Sign`, and `crypto/ed25519.Sign`. The P-256 private scalar is 1; the Ed25519 seed is 32 zero bytes. Only their public JWK parameters are imported by these tests.

`pem_reference_test.goml` contains frozen independently generated Go 1.26.8 PKCS#8/PKIX fixtures, a 2048-bit two-prime RSA key, a 2048-bit three-prime RSA key, a P-256 key with scalar 1, and Ed25519 with a zero seed. PKCS#1 RSA private/public and SEC1 EC forms are also exercised. The exact compact JWT signatures were produced by the Go standard library; deterministic RSA and Ed25519 signing must reproduce the complete reference token byte for byte. ECDSA signatures are independently authenticated, while the curve suite checks actual random ECDSA signing with a separate arbitrary-precision affine verifier. No runtime oracle or generated-key self-roundtrip is used as the only signature correctness check.

`security_reference_test.goml` freezes independently signed malformed and exact NumericDate cases. Signatures were produced with Python 3 `hmac` and `hashlib.sha256`, over precisely encoded byte strings including an invalid UTF-8 payload. The malformed corpus includes nested/escaped duplicate members, invalid Unicode surrogates, malformed registered claims, unsupported JOSE headers, compact-segment syntax and nonzero base64 unused bits. NumericDates exercise sub-integer differences, positive/negative range endpoints and exponent limits.

`jwk_bounds_test.goml` exercises metadata and private-material rejection, canonical RSA integers, 2048/8192-bit modulus boundaries, exponent bounds, P-256 coordinate widths and field boundaries, strict JSON budgets, exact JWK/JWKS byte bounds, shared-key concurrency and forged signatures. `pem_rejection_test.goml` checks malformed leading blocks, truncation, trailing DER, indefinite lengths, encrypted headers, certificate labels and corrupted RSA factors/CRT parameters.

The curve suite's independent vectors and formulas are documented in `../curves/tests/KNOWN_ANSWERS.md`. Concurrent tests explicitly join every spawned task so assertion failures propagate, and run under the ecosystem race-detector workflow.

## Previous native coverage mapping

| Previous Go test | GoML coverage |
| --- | --- |
| `TestRFC7515AppendixA1` | `rfc7515_hmac_vector_passes_through_public_api`, expiration boundary tests |
| `TestRFC8037AppendixA4` | `rfc8037_signature_authenticates_before_non_json_payload_is_rejected` |
| `TestMalformedSignedTokens` | `independently_signed_malformed_tokens_fail_closed` |
| `TestCanonicalBase64AndCompactShape` | independently signed malformed corpus and compact mutation corpus |
| `TestClaimPolicyBoundaries` | exact independent NumericDate cases and issuer/audience policy tests |
| `TestKeySelectionLimitsAndSnapshot` | `secret_snapshot_and_limits_are_preserved`, key-selection public tests |
| `TestAsymmetricIndependentInteroperability` | frozen PEM reference suite plus independent curve verifier and exact signing vectors |
| `TestSharedKeysConcurrent` | `shared_keys_support_concurrent_signing_and_verification`, eight workers × twenty iterations |
| `FuzzVerify` default seed corpus | malformed compact token mutation corpus, plus independently signed valid/malformed fixtures |
| `TestJWKIndependentSignaturesAndConcurrentVerification` | independent JWK vectors and eight workers × twenty iterations × three algorithms |
| `TestJWKMetadataAndPrivateMaterialRejection` | metadata acceptance/rejection matrix and original JWK policy tests |
| `TestJWKCanonicalEncodingAndStrictJSON` | canonical JWK cases, malformed JSON and exact byte-bound tests |
| `TestJWKRSAAndECCoordinateBounds` | RSA integer/modulus/exponent and P-256 coordinate tests |
| `TestJWKSAllOrNothingSelectionAndBounds` | original rotation/unique-ID/64-key tests plus byte bounds and allowlist failures |
| `TestPEMKeyRejectsSkippedMalformedBlocks` | original public PEM regression and private/public malformed DER/PEM suite |

The weak-RSA rejection fixture is derived from the two-prime PEM reference by choosing the next prime `q = p + 508`. It has a 2048-bit modulus, correct CRT parameters and a 2047-bit private exponent, but only nine bits of prime separation; Go 1.26.8 rejects it as `|p - q| too small`. Nested SEC1 malformed-OID and BIT STRING padding cases were independently confirmed rejected by Go 1.26.8. The valid leading-zero P-256 coordinate was found by scalar multiplication with Go’s `crypto/elliptic` and frozen as a public JWK.
