# jwt

`ecosystem::jwt` signs and verifies compact JSON Web Tokens with an explicit verification policy. It supports HS256, RS256, ES256 and EdDSA with Ed25519, typed `std::serde` claims, dynamic JSON claims, local key rotation, bounded parsing and injectable time.

GoML 0.1.57 or newer and Go 1.26 are required. Cryptographic operations, PEM decoding, strict JSON scanning and NumericDate comparison use the bundled Go adapter and Go's standard library. There are no third-party Go dependencies and no cgo dependency. Consumers using native dependencies need a minimal `go.mod`; `goml verify` exercises this from an independent consumer module.

```toml
[dependencies]
"ecosystem::jwt" = "0.1.0"
```

This is a source repository; the dependency version above is a registry coordinate, not a claim that an immutable registry release has been published. For a local checkout use `goml add ecosystem::jwt --path ../jwt`.

## Example

```goml
use ecosystem::jwt;
use ecosystem::jwt::{Algorithm, Key, Validation};
use std::serde::Deserialize;

#[derive(Deserialize)]
struct Claims {
    sub: string,
    exp: i64,
    scope: string,
}

fn authenticate(token: string, trusted_key: Key) -> Result[string, string] {
    let policy = Validation {
        issuer: Option::Some("https://issuer.example"),
        audience: Option::Some("example-api"),
        token_type: "at+jwt",
        ..Validation::new(Algorithm::RS256)
    };
    let verified = jwt::verify(token, Vec::from_array([trusted_key]), policy)
        .map_err(|_| "invalid access token")?;
    let claims: Claims = verified.claims().map_err(|_| "invalid claims")?;
    if claims.scope != "read" {
        return Result::Err("read permission required")
    }
    Result::Ok(claims.sub)
}
```

`examples/basic` implements a complete typed access-token producer and authorization consumer, including scope and expiration failures. Its fixed secret and clock are test data. Production applications supply high-entropy secrets or securely loaded private keys and normally leave `Validation.now` as `None` to use the system clock.

## API

| API | Behavior |
| --- | --- |
| `Key::hmac(secret: Vec[u8], key_id)` | Copies a 32–65536-byte HS256 secret. Rejects PEM-shaped material. An empty ID omits `kid`. |
| `Key::private_pem(algorithm, pem, key_id)` | Imports an unencrypted PKCS#8, PKCS#1 RSA or SEC1 EC private PEM key. |
| `Key::public_pem(algorithm, pem, key_id)` | Imports a PKIX public key or PKCS#1 RSA public key PEM. Rejects private keys and certificates. |
| `Key::public_jwk(algorithm, json)` | Imports one public RSA, P-256 or Ed25519 JWK for the explicitly chosen verification algorithm. |
| `jwt::public_jwks(json, algorithms)` | Imports a complete public JWK Set into `Vec[Key]`, with an explicit algorithm allowlist and unique nonempty IDs. |
| `Key.key_id()`, `Key.algorithm()` | Return metadata without exposing key material. |
| `jwt::sign(key, claims, SignOptions)` | Serializes a `Serialize` value with bounded JSON encoding and signs it. |
| `jwt::sign_json(key, claims_json, SignOptions)` | Validates an object and registered claim types, then signs the original JSON bytes. |
| `jwt::verify(token, keys, Validation)` | Authenticates the compact token, validates registered claims and returns `Verified`. |
| `Verified.claims[T]()` | Deserializes authenticated claims into a `Deserialize` type. |
| `Verified.value()` | Returns authenticated claims as `std::json::Value`. |
| `Verified.claims_json()`, `Verified.key_id()` | Return authenticated JSON and the selected local key's ID. |

Keys bind permanently to one algorithm. RS256 keys require 2048–8192-bit RSA, ES256 requires P-256, and EdDSA supports Ed25519 only. ES256 signatures use the JWS 64-byte `R || S` representation. Signing requires a private key; private keys may also verify. Key handles contain no mutating API and support concurrent calls. Secret input is copied. `Key` and `Verified` do not implement `Debug`, and library error messages contain no token, claims, PEM or secret values. Garbage collection does not provide guaranteed key erasure.

PEM import accepts one unencrypted block with optional surrounding whitespace.
Extra blocks, including malformed blocks before an otherwise valid key, are rejected.

### Public JWK and JWK Set import

```goml
let keys = jwt::public_jwks(trusted_jwks_json, Vec::from_array([Algorithm::RS256]))?;
let verified = jwt::verify(token, keys, Validation::new(Algorithm::RS256))?;
```

Applications must obtain the JSON from a trusted source. Import performs no network access, certificate validation or discovery, and token headers cannot supply trusted keys. Imported keys only verify; they cannot sign. Import policy and token verification policy are both explicit.

- `RSA` binds to RS256, `EC` with `crv = "P-256"` to ES256, and `OKP` with `crv = "Ed25519"` to EdDSA. `kty` and the corresponding public parameters are required. A JWK's optional `alg` must exactly match this binding and the requested algorithm. JWKS allows a nonempty list of up to three distinct asymmetric algorithms; every entry must match the list, including entries without `alg`. Unsupported or disallowed entries fail the entire import, with no partial key set returned.
- Optional `use` must be `"sig"`. Optional `key_ops` must be exactly `["verify"]`. Both may be present when consistent. Missing optional fields are allowed; `null`, wrong types, empty IDs and duplicate operations are rejected. Accepting only the verification operation is a library policy narrower than the general JWK format.
- A single JWK may omit `kid`, producing an empty local ID. A JWKS requires a nonempty `kid` on every entry and rejects duplicate IDs across all algorithms. IDs obey the existing 256-byte UTF-8 limit and cannot contain NUL, CR or LF. This unique-ID policy is stricter than RFC 7517. Import preserves the JSON array's order; verification retains its existing exact ID/algorithm selection rules.
- RSA `n` and `e` use unpadded, canonical base64url of the shortest unsigned big-endian integer, with no leading zero byte. The modulus must be odd and 2048–8192 bits; the exponent must be odd and between 3 and 2147483647. These are structural public-key checks, not a proof of modulus factorization. P-256 `x` and `y` each require exactly 32 bytes (including necessary leading zero bytes) and a point on the curve. Ed25519 `x` requires exactly 32 bytes, with signature verification delegated to Go's `crypto/ed25519`, as for PEM keys.
- Presence of any `d`, `p`, `q`, `dp`, `dq`, `qi`, `oth` or `k` field is rejected, even if null. Known public parameters belonging to another supported key type are also rejected. Unknown extension members are ignored after strict JSON validation. In particular, `x5u`, `x5c` and other certificate metadata are not fetched, parsed or trusted; only the public key parameters are imported.

Single-JWK input is limited to 65536 bytes. JWKS input is limited to 1048576 bytes and 1–64 keys. Both use the existing strict JSON bounds of 64 nesting levels and 16384 values, reject duplicate members at every depth (including escaped duplicate names), and require canonical unpadded base64url with zero unused bits. Errors expose categories and fixed messages without echoing input key material. Byte limits are checked before JSON parsing, and set cardinality is checked before constructing keys.

`SignOptions::new()` selects `typ = "JWT"` and a 65536-byte final-token limit. Set `token_type` explicitly when producing a more specific token kind such as `at+jwt`.

## Verification policy

`Validation::new(algorithm)` allows exactly that algorithm, requires `exp`, checks future `iat` when present, validates `nbf` when present, requires `typ = "JWT"`, uses the system clock and allows zero clock skew. No algorithm is inferred from key contents or accepted solely because the header requests it. `none` is never supported.

- `algorithms` is an explicit, nonempty list of distinct supported algorithms.
- `issuer = Some(value)` requires exact, case-sensitive `iss` equality. `None` does not require an issuer. Configured empty issuer strings are rejected.
- `audience = Some(value)` requires membership in a string or array `aud` claim. A token containing `aud` is rejected if no expected audience is configured. Configured empty audience strings are rejected.
- `now = Some(seconds)` injects integral Unix time. `leeway_seconds` is 0–86400. At zero leeway, `now == exp` is expired and `now == nbf` is valid. Expiration uses `now - leeway`; future checks use `now + leeway`.
- `exp`, `nbf` and `iat` accept bounded decimal JSON NumericDates, including fractions and exponent notation. Comparisons use exact rational arithmetic. Supported dates and injected time are between -253402300799 and 253402300799 seconds; date literals are at most 64 bytes with exponent between -100 and 100.
- `require_expiration = false` permits a missing expiration but still validates one that is present. `check_issued_at = false` disables the future-issuance check while retaining the claim's type check.
- `token_type` is compared exactly. An empty value explicitly permits a missing or arbitrary string `typ`. Distinct application token purposes should use distinct expected types and issuer/audience policies.

An explicit `kid` must match exactly one supplied key with the requested algorithm. Unknown and ambiguous IDs fail. If `kid` is absent, there must be exactly one key matching the algorithm. IDs are never interpreted as file paths or URLs. The returned key ID identifies the selected local key even when the header omitted `kid`.

## Bounds and supported JOSE scope

The final token limit is configurable from 256 to 1048576 bytes. Verification accepts at most 64 keys and 4 algorithms. Encoded headers are limited to 8192 bytes, encoded signatures to 2048 bytes, PEM to 65536 bytes, key IDs to 256 UTF-8 bytes, JSON nesting to 64 levels and JSON values to 16384 nodes. Audience arrays contain 1–128 strings. Invalid limits return errors.

The parser rejects padded or noncanonical base64url, whitespace in encoded segments, nonzero unused bits, extra segments, non-object JSON, duplicate object members at every depth, escaped duplicate names, invalid UTF-8, unpaired Unicode surrogates, trailing data and malformed registered claim types. Signature authentication precedes claims parsing. JSON encoding and typed decoding also have explicit bounds.

This release supports compact signed JWTs and local public JWK/JWKS import. It does not implement JWE, detached payloads, unencoded payloads, general JWS JSON serialization, private or symmetric JWK import, JWK/JWKS retrieval, certificate trust validation, OAuth2, replay storage, revocation or automatic key fetching. Headers carrying `crit`, `b64`, `jku`, `jwk`, `x5u` or `x5c` are rejected. Applications provision trusted local keys and enforce their own authorization and replay policy after verification.

## Validation and references

```sh
goml bind-go bindings.json
goml fmt --check
goml test
goml verify
go test -race ./...
```

Bindings in `bindings/generated.goml` and `adapter/generated.go` are generated by `goml bind-go`; the companion hash manifest must be retained. The adapter tests include published HMAC and EdDSA vectors, independent RSA/ECDSA/Ed25519 sign/verify operations, signed malformed inputs, algorithm/key confusion, canonical encoding, claim boundaries and concurrency. The GoML suite verifies the public API and the independent authorization consumer.

Design references: [JWS, RFC 7515](https://www.rfc-editor.org/rfc/rfc7515), [JWK, RFC 7517](https://www.rfc-editor.org/rfc/rfc7517), [JWA, RFC 7518](https://www.rfc-editor.org/rfc/rfc7518), [JWT, RFC 7519](https://www.rfc-editor.org/rfc/rfc7519), [JWT best practices, RFC 8725](https://www.rfc-editor.org/rfc/rfc8725) and [EdDSA in JOSE, RFC 8037](https://www.rfc-editor.org/rfc/rfc8037). These references describe the protocols; the supported subset and stricter input policy are listed above.
