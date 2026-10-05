# JWT test vectors

`adapter/jwt_test.go` and `tests/jwt_test.goml` use the public HS256 key and compact JWT from [RFC 7515 Appendix A.1](https://www.rfc-editor.org/rfc/rfc7515#appendix-A.1).

`adapter/jwt_test.go` also uses the public Ed25519 key and signature from [RFC 8037 Appendix A.4](https://www.rfc-editor.org/rfc/rfc8037#appendix-A.4). Its payload is a JWS text payload, so the crypto test accepts the signature and the JWT API separately rejects the non-JSON payload.

The other RSA, ECDSA and Ed25519 interoperability tests generate fresh ephemeral keys and compare the adapter with direct Go standard-library crypto calls. No production credential, private developer key or external service is used. Fixed HMAC values in tests and examples are public test-only material.

The public JWK import tests include three fixed JWTs produced independently with
Go 1.26 `crypto/rsa.SignPKCS1v15`, `crypto/ecdsa.Sign` (converted to fixed-width
`R || S`) and `crypto/ed25519.Sign`. The RSA key was generated for the tests;
the P-256 fixture uses scalar 1 and the Ed25519 fixture an all-zero 32-byte seed.
These are test keys, not production secrets or published RFC vectors. The GoML
suite imports only their public JWK parameters, verifies the JWTs, and exercises
mixed-algorithm JWKS rotation. Native tests generate fresh RSA/P-256 keys and
independent signatures, check coordinate/integer boundary representations,
reject policy conflicts and private material, and verify shared imported keys
concurrently under the race detector. The Ed25519 import rejection cases also
use the public key from RFC 8037 Appendix A.2.
