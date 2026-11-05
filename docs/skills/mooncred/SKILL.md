---
name: mooncred
description: Credential formats for MoonBit — JWT, JWS, JWE, JWK and key sets, X.509 certificates and certification paths, CSRs, encrypted private keys, PKCS#12, CRLs and OCSP, CWT and COSE. Use when a program must issue or check a token, read or write a certificate, validate a chain to a set of roots, or open a key file.
---

# mooncred

## Install

```bash
moon add moonbitstack/mooncred moonbitstack/mooncrypt
```

`mooncrypt` is where the primitives live — the key that signs, the hash behind a MAC — so a
program that issues or checks anything adds both.

```moonbit
import {
  "moonbitstack/mooncred/jwt",
  "moonbitstack/mooncred/x509",
}
```

These packages carry formats, not primitives: the signature comes from `mooncrypt`, and the
program says which. `jwt`, `jwe`, `cose` and `token` take a signer, a verifier or a MAC as
an argument; `x509` and `csr` read the signature out of the message and check it themselves.

## Issue and check a token

```moonbit
let key = @jwt.mac(fn() { @hmac.Hmac::new(secret[:], fn() { @sha2.Hasher::new() }) })

let claims : Map[String, Json] = Map([])
claims["sub"] = Json::string("heke1228")
claims["exp"] = Json::number(4102444800.0, repr="4102444800")

let token = @jwt.sign(claims, HS256, key)

// The algorithm is the verifier's argument, never the token's claim.
let got = @jwt.verify(token[:], HS256, key, now=At(1758412800L), issuer="moonbitstack")
```

`@jwt.mac` adapts a `mooncrypt` MAC; a `mooncrypt` signer or verifier is passed as it is —
`@jwt.sign(claims, EdDSA, @ed25519.PrivateKey::new(seed[:]))`. `verify` returns the claims
it checked; expiry, not-before, `iss`, `aud` and `sub` are checked when the policy or the
call asks for them.

## Validate a certificate chain

```moonbit
let anchors = @roots.mozilla()                    // or @x509.Roots::pem(bundle)
let chain = @x509.pems(leaf_and_intermediates)    // leaf first, DER
let path = @x509.verify(chain[:], anchors, now=unix_seconds, host="api.example.com")
```

`now` is data, in seconds since the epoch: the time the request is judged at, not a clock.
`host` is compared against subjectAltName only, never the common name; leave it out to skip
the name check. The path returned is the leaf, the intermediates the search used and the
anchor it ended on, so certificates the peer sent but the path did not need are dropped. A
refusal is an `@x509.Refused` naming the position in the chain it is about.

## Open a key file

```moonbit
let key = @x509.PrivateKey::pem(text)                            // PKCS#8, SEC1 or PKCS#1
let locked = @x509.PrivateKey::pem_encrypted(text, passphrase="…")
let pfx = @pkcs12.parse(der).contents(passphrase="…")             // MAC checked first
```

`pkcs12` verifies the container's MAC before it decrypts anything and raises rather than
returning a half-read container. A `PrivateKey` has no `Show`: it does not print.

## What bites

- There is no way to verify without naming the algorithm. `@jwt.verify` takes the `Alg` and
  refuses a token whose header names another one.
- `jwt`, `jwe`, `cose` and `token` hold no clock; `now` is passed in. `Clock::Ignored` turns
  the time checks off and is the wrong default.
- An anchor in `x509.Roots` is a name and a key. Its own expiry and extensions are not
  examined, which is what lets a long-lived root carry an old signature.
- A leaf that is itself a CA is refused, as is a chain whose issuer lacks
  `basicConstraints` or `keyCertSign`.
- `jwk` reads a private RSA key down to `n`, `e` and `d`; the primes are not kept.
- Everything that can fail raises. Nothing returns a partially filled value.
