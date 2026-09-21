# mooncred

Credential formats for MoonBit: JSON Web Tokens, and the keys they are verified
with.

```moonbit
// The key is whatever signs. Here, HMAC over SHA-256.
let key = @jwt.mac(fn() {
  @hmac.Hmac::new(secret[:], fn() { @sha2.Hasher::new() })
})

let token = @jwt.sign(claims, HS256, key)

// The algorithm is the caller's, not the token's.
let got = @jwt.verify(token[:], HS256, key, now=now_seconds,
                      issuer=Some("moonbitstack"), audience=Some("moonapi"))
```

## Packages

| Package | What | Specification |
|:--:|:--|:--|
| `jwt` | JWS compact serialisation, all thirteen JOSE algorithms | RFC 7515, 7518, 7519, 8037 |
| `jwk` | JSON Web Key and key sets: reading, writing, choosing | RFC 7517, RFC 7518 §6 |

## The algorithm is not the token's to choose

`verify` takes the algorithm as an argument and refuses any token whose header
names a different one. This is not a convenience — it is the whole of the fix
for the two attacks that have defeated JWT libraries repeatedly:

- **`alg: none`.** A token with an empty signature that a verifier accepts
  because the token said not to check. There is no `none` in the `Alg` type, so
  there is nothing to accept.
- **Algorithm confusion.** A token signed with HMAC, keyed on the RSA public key
  that everybody has, offered to a verifier that reads `alg` from the header and
  obliges. Here the caller has already decided; the header must agree with it.

`header` reads the unverified header, for one purpose: getting `kid` so the
right key can be fetched before anything is verified.

## Keys are contracts, not implementations

Signing takes anything implementing `mooncrypt/spec`'s `Signer`; verification,
anything implementing `Verifier`. This package imports no algorithm at all, so a
program that issues only HS256 tokens does not link an elliptic curve, and one
that verifies only ES256 does not link RSA.

`@jwt.mac` turns a keyed MAC into both — HMAC is symmetric, and what it proves
is that someone with the shared secret issued the token, not who.

`jwk` reads key material as bytes rather than as keys, for the same reason:
building a key means choosing an implementation, and the program is what knows
which ones it wants. The bridge is two lines:

```moonbit
match key.material() {
  Okp(x~, ..) => @ed25519.PublicKey::new(x[:])
  _ => …
}
```

## What is checked

Every one of the thirteen algorithms is verified against a token produced by a
third-party signer, and the ten deterministic ones are reproduced byte for byte.
RFC 7515 §A.1's worked example verifies exactly as printed, line breaks and all.
The key sets of RFC 7517 §A.1 and §A.3 and the Ed25519 key of RFC 8037 §A.1 read
to the bytes they stand for.

Alongside the vectors: a token whose header names another algorithm, one with
`alg: none`, one whose signature was replaced, one verified under another key,
expiry and not-before at the exact second, `iss` and `aud`, and ten shapes that
are not tokens — all refused, each with its own reason.

## What is not here yet

X.509 certificates and path validation, certificate signing requests, PKCS#12,
COSE and CWT, PASETO, and JWE. They are planned in that order; the tracking list
lives with the project. Online revocation needs an HTTP client and belongs with
the network, not here.

## Install

```bash
moon add moonbitstack/mooncred
```

## Licence

Apache-2.0.
