---
name: mooncred
description: "Credential formats for MoonBit — JWT, JWS over arbitrary octets, JWE in both serialisations with every RFC 7518 key-management algorithm, JWK and key sets, X.509 certificates and certification paths, CSRs, encrypted private keys, PKCS#12, CRLs and OCSP, CWT and COSE. Use when a program must issue or check a token, encrypt a payload to one or more recipients, read or write a certificate, validate a chain to a set of roots, or open a key file."
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
let secret = b"a shared secret nobody else has"
let key = @jwt.mac(fn() {
  @hmac.Hmac::new(secret[:], fn() { @sha2.Hasher::new() })
})

let claims : Map[String, Json] = Map([])
claims["sub"] = Json::string("heke1228")
claims["exp"] = Json::number(4102444800.0, repr="4102444800")

let token = @jwt.sign(claims, HS256, key)

// The algorithm is the verifier's argument, never the token's claim.
let got = @jwt.verify(token[:], HS256, key, now=At(1758412800L), issuer="moonbitstack")
assert_eq(got.get("sub"), Some(Json::string("heke1228")))
```

`@jwt.mac` adapts a `mooncrypt` MAC; a `mooncrypt` signer or verifier is passed as it is —
`@jwt.sign(claims, EdDSA, @ed25519.PrivateKey::new(seed[:]))`. `verify` returns the claims
it checked; expiry, not-before, `iss`, `aud` and `sub` are checked when the policy or the
call asks for them.

## Sign octets that are not a claims set

`sign_bytes` takes any payload, and RFC 7797's `b64: false` signs it as it stands; `detached`
leaves it out of the token entirely, for a caller that sends the octets another way.

```moonbit
let secret = b"a shared secret nobody else has"
let key = @jwt.mac(fn() {
  @hmac.Hmac::new(secret[:], fn() { @sha2.Hasher::new() })
})

let token = @jwt.sign_bytes(b"$.02", HS256, key, b64=false, detached=true)
let payload = @jwt.verify_bytes(token[:], HS256, key, b64=false, payload=b"$.02")
assert_eq(payload, b"$.02")
```

A payload that is not ASCII, or that contains a dot, cannot travel in the compact form
unencoded: the form is cut at its dots and its other two parts are text. Such a payload
travels detached, or encoded.

## Several signatures, and headers that travel beside them

```moonbit
let secret = b"a shared secret nobody else has"
let key = @jwt.mac(fn() {
  @hmac.Hmac::new(secret[:], fn() { @sha2.Hasher::new() })
})
let kid : Map[String, Json] = Map([])
kid["kid"] = Json::string("2026-09")

let message = @jwt.Message::new(b"{\"iss\":\"moonbitstack\"}").sign(HS256, key, header=kid)
let flattened = @json.dumps(message.flattened())
let checked = @jwt.verify_json(flattened[:], checks=[@jwt.Check::new(HS256, key)])
assert_eq(checked.payload, b"{\"iss\":\"moonbitstack\"}")
```

`Message::sign` adds one signature at a time, each with its own protected and unprotected
header, so one payload can be signed by several keys. `verify_json` tries only the algorithm
and key pairs the caller offers, and reports which signature opened the message.

## Encrypt a payload

```moonbit
let shared = b"a 16-octet key"
let content = b"0001020304050607"
let sealed = @jwe.encrypt(
  b"card ending 4242",
  key=Shared(shared),
  alg=Dir,
  enc=A128Gcm,
  iv=b"twelve bytes",
)
let plain = @jwe.decrypt(sealed[:], key=Shared(shared), alg=Dir, enc=A128Gcm)
assert_eq(plain, b"card ending 4242")
```

Every parameter that would be random is an argument: the IV, the content key, the RSA padding
seed, the PBES2 salt and count, the AES-GCM wrap nonce, the ECDH-ES ephemeral scalar. Draw
them fresh from a CSPRNG; nothing here generates them.

`jwe.seal` writes the JSON serialisation, which carries several recipients, additional
authenticated data and compression. `jwe.open` reads either serialisation and takes the
identities the caller is willing to open with.

```moonbit
let content = b"0001020304050607"
let message = @jwe.seal(
  b"card ending 4242",
  enc=A128Gcm,
  recipients=[
    {
      ..@jwe.Recipient::new(A128Kw, Shared(b"sixteen byte key")),
      cek: Some(content),
    },
  ],
  iv=b"twelve bytes",
  aad=b"tenant=42",
)
let opened = @jwe.open(
  @json.dumps(message)[:],
  enc=A128Gcm,
  unseal=[@jwe.Unseal::new(A128Kw, Shared(b"sixteen byte key"))],
)
assert_eq(opened.plain, b"card ending 4242")
```

## Validate a certificate chain

```moonbit
let seed = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
let key : @x509.PrivateKey = MlDsa(@mldsa.PrivateKey::from_seed(kind=D65, seed))
let der = @x509.self_signed(
  key=key,
  cn="api.example.com",
  serial=b"\x01",
  not_before=1793232000L,
  not_after=1824768000L,
  exts={ ..@x509.Exts::empty(), san: [Dns("api.example.com")] },
)
let chain : Array[Bytes] = [der]
let anchors = @x509.Roots::new(certs=chain[:])
let path = @x509.verify(chain[:], anchors, now=1793232000L, host="api.example.com")
assert_eq(path.length(), 1)
```

`now` is data, in seconds since the epoch: the time the request is judged at, not a clock.
`host` is compared against subjectAltName only, never the common name; leave it out to skip
the name check. The path returned is the leaf, the intermediates the search used and the
anchor it ended on, so certificates the peer sent but the path did not need are dropped. A
refusal is an `@x509.Refused` naming the position in the chain it is about.

## Open a key file

```moonbit
let seed = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
let key : @x509.PrivateKey = MlDsa(@mldsa.PrivateKey::from_seed(kind=D65, seed))
let text = key.pkcs8_pem()
let again = @x509.PrivateKey::pem(text)                       // PKCS#8, SEC1 or PKCS#1
let locked = @x509.PrivateKey::pem_encrypted(
  again.encrypt_pem(passphrase="…", salt=b"0123456789abcdef", iv=b"0123456789abcdef"),
  passphrase="…",
)
assert_true(locked.public() is MlDsa(_))
```

`pkcs12` verifies the container's MAC before it decrypts anything and raises rather than
returning a half-read container. A `PrivateKey` has no `Show`: it does not print.

## What bites

- There is no way to verify without naming the algorithm. `@jwt.verify` takes the `Alg` and
  refuses a token whose header names another one.
- `jwt`, `jwe`, `cose` and `token` hold no clock; `now` is passed in. `Clock::Ignored` turns
  the time checks off and is the wrong default.
- Nothing here draws randomness. Every IV, salt, nonce, seed and ephemeral scalar is an
  argument, and reusing one is a break, not a convenience.
- `RSA1_5` and `RSA-OAEP` with SHA-1 are refused unless the call passes `policy=@jwe.legacy`.
  `RSA-OAEP-256` is accepted by default.
- A `b64: false` payload with a dot in it, or one that is not ASCII, cannot travel in the
  compact form; sign it detached instead. A token whose `b64` disagrees with the caller's is
  refused, not reconciled.
- An anchor in `x509.Roots` is a name and a key. Its own expiry and extensions are not
  examined, which is what lets a long-lived root carry an old signature.
- A leaf that is itself a CA is refused, as is a chain whose issuer lacks
  `basicConstraints` or `keyCertSign`.
- `jwk` keeps an RSA private key's `p`, `q`, `dp`, `dq` and `qi` when the document carries
  them, and answers `crt()` with `None` when it does not.
- Everything that can fail raises. Nothing returns a partially filled value.
