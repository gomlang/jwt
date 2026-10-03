# JWT test vectors

`adapter/jwt_test.go` and `tests/jwt_test.goml` use the public HS256 key and compact JWT from [RFC 7515 Appendix A.1](https://www.rfc-editor.org/rfc/rfc7515#appendix-A.1).

`adapter/jwt_test.go` also uses the public Ed25519 key and signature from [RFC 8037 Appendix A.4](https://www.rfc-editor.org/rfc/rfc8037#appendix-A.4). Its payload is a JWS text payload, so the crypto test accepts the signature and the JWT API separately rejects the non-JSON payload.

The other RSA, ECDSA and Ed25519 interoperability tests generate fresh ephemeral keys and compare the adapter with direct Go standard-library crypto calls. No production credential, private developer key or external service is used. Fixed HMAC values in tests and examples are public test-only material.
