P-256 fixtures were generated with the independent Go 1.26.8 crypto/ecdsa and
crypto/elliptic standard-library implementations. Scalars include 1, 2, 3, n-1,
and SHA-256("independent P256"). Signatures use SHA-256 and fresh Go randomness.

The first three Ed25519 fixtures are RFC 8032 section 7.1 test vectors. The four
additional fixtures were produced with Go 1.26.8 crypto/ed25519, using seeds
SHA-256("independent Ed25519 N") for N = 0..3 and messages of lengths 31, 64,
127, and 1025 whose bytes are the successive indices modulo 256.

Boundary tests preserve Go crypto/ed25519 behavior for noncanonical public
identity encodings, while rejecting noncanonical signature R and S encodings.
The fixtures contain no application secrets and require no Go adapter at runtime.

`ed25519_go_edges.tsv` freezes 799 distinct adversarial inputs evaluated by
Go 1.26.8 `crypto/ed25519.Verify`: 64 accepted and 735 rejected. Columns are
case identifier, public-key hex, message hex, signature hex, and the exact Go
boolean result. The suite requires all results to match, including eight
explicit accepted weak-key cases, one for every member of the order-eight
subgroup. It does not infer expected acceptance from the GoML implementation.

Cases cover 256 combinations of small-order A/R, two messages, and S=0 or S=1;
64 combinations of prime-order points with every possible torsion component;
168 noncanonical A/R encodings; 200 known weak-key positives and last-byte
A/R/S bit mutations; 56 scalar-boundary cases; 28 invalid point encodings;
and 27 ordinary RFC 8032 signature mutations and length errors. Inputs are
deduplicated before freezing. Scalar cases include L-1, L, L+1, multiples of
L, 2^252 boundaries, high bits through bit 255, and S+L/S+2L/S+8L mutations
of a valid RFC 8032 signature. Noncanonical y encodings span p through p+18
with both sign bits, including invalid encodings. Noncanonical x=0 sign-bit
encodings and alternate encodings of identity and order-four points are
included as A and R.

The eight subgroup encodings, in successive multiples of the generator, are:

```text
0100000000000000000000000000000000000000000000000000000000000000
c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a
0000000000000000000000000000000000000000000000000000000000000080
26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05
ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85
0000000000000000000000000000000000000000000000000000000000000000
c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa
```

Inputs were constructed independently with Python integer arithmetic using
the Edwards curve equation and affine addition. The generator is [L]P for
the first decodable y >= 2 whose [L]P has exact order eight. Construction
asserts [8]T=identity, [4]T!=identity, and eight distinct multiples. Mixed-order
cases use A=[123456789]B+[i]T and R=[987654321]B+[j]T, with S computed from the
standard challenge. Expected results come exclusively from the separate Go
program. Go's local `edwards25519_test.go` noncanonical-encoding cases and
`ed25519vectors_test.go` describe the edge behavior being preserved.
