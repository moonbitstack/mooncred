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
| `x509` | X.509 v3 certificates: read one down to its extensions, check its signature under RSA, ECDSA or Ed25519, match it against a host, validate a chain to a set of trust anchors; build a self-signed P-256 one; read the private key that goes with it | RFC 5280, RFC 6125, RFC 7468, RFC 5958, RFC 5915 |
| `roots` | The Mozilla CA store as trust anchors, from curl's extract | — |

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

## Configuration precedence

Everything a verification checks is a setting, and every setting can be given
two ways: in a `Policy` assembled once for a deployment, or as an argument to
the call in front of you. There are three layers, each overriding the one
before:

```
@jwt.policy        <        the policy you pass        <        the arguments you pass
```

The per-call argument wins by default because it is the more specific of the
two — the same rule [Axios](https://axios-http.com/docs/config_defaults),
[Terraform](https://developer.hashicorp.com/terraform/language/values/variables)
and [Spring Boot](https://docs.spring.io/spring-boot/reference/features/external-config.html)
use for the same question.

Both of those are parameters too:

- `wins` turns the last two layers around. `Base` makes the policy
  authoritative and the arguments advisory.
- `clash` decides what happens when a setting is given twice: `Ignore` merges
  quietly, `Panic` refuses, and `Handle(f)` gives your function the base and the
  merged result and takes whichever it returns.

```moonbit
// A policy for the deployment, assembled once.
let ours = @jwt.Policy::new(issuer=Some("moonbitstack"), audience=["moonapi"])
// The same thing written as a record update.
let ours : @jwt.Policy = { ..@jwt.policy, issuer: Some("moonbitstack") }

// Used as it is, and used with one thing changed for this call.
@jwt.verify(token[:], HS256, key, now=At(seconds), policy=ours)
@jwt.verify(token[:], HS256, key, now=At(seconds), policy=ours, leeway=60L)

// Reading a token without asking whether it has expired.
@jwt.verify(token[:], HS256, key, now=Ignored)
```

`now` is not configuration but data, so it is always an argument and never a
policy field.

The same three layers, the same two switches and the same words appear wherever
this ecosystem takes a configuration record.

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

### When a setting takes a bare value and when it takes `Some`

A setting whose preset is unset is written plainly, because there is nothing to
clear:

```moonbit
@jwt.Policy::new(issuer="https://issuer.example", leeway=30)
@jwt.verify(token[:], HS256, key, now=At(seconds), issuer="https://issuer.example")
```

A setting whose preset is a value takes an option, because clearing it is one of
the things a caller needs to say. `sign` writes `typ: "JWT"` unless told
otherwise, and `None` is how a caller asks for no `typ` header at all:

```moonbit
@jwt.sign(claims, HS256, key)                      // typ: "JWT"
@jwt.sign(claims, HS256, key, typ=Some("at+jwt"))  // typ: "at+jwt"
@jwt.sign(claims, HS256, key, typ=None)            // no typ header
```

The shape follows from the preset, never from the label, so the same rule reads
the same way in every library here.

## Certificates

```moonbit
// Validate what a server sent, against the Mozilla roots.
let roots = @roots.mozilla()                     // build once, keep
let path = @x509.verify(chain[:], roots, now~, host="example.com")
// path: the leaf, the intermediates it runs through, the anchor

// Or one certificate on its own.
let cert = @x509.parse(der[:])
cert.matches("a.example.com")     // subjectAltName names and addresses
cert.signed_by(issuer.spki)       // raises for an algorithm it does not check
```

`verify` takes the leaf and whatever intermediates the peer sent, in any order,
and refuses with a reason and the position of the certificate it is about:
`Expired(at=1)`, `Host("example.com")`, `Constraint(at=0, name=...)`. What it
holds a chain to, and whose rule each is:

| Rule | From |
|:--|:--|
| Names come from subjectAltName only, never the commonName; an IP literal is held to the iPAddress entries | RFC 6125, Go, webpki |
| Every issuer is a CA, has keyCertSign when it lists key usages, respects its pathLenConstraint; a CA is not a leaf | RFC 5280 §4.2.1.9, webpki |
| Validity on every certificate but the anchor | RFC 5280 §6.1.3 |
| The leaf allows the purpose asked for; an issuer that lists purposes allows it too | RFC 5280 §4.2.1.12, Go |
| An unknown critical extension refuses the chain | RFC 5280 §4.2 |
| Name constraints over dNSName, iPAddress, rfc822Name, directoryName and URI hosts | RFC 5280 §4.2.1.10 |
| RSA PKCS#1 and PSS, ECDSA on four curves, Ed25519; no SHA-1 | webpki, Go |
| At most six intermediates and a hundred signature checks | webpki |

The two limits and the purpose are a `Policy`, with `policy` as the preset.

`roots` is its own package, so a program that brings its own anchors never
links the bundle. The certificates are checked against the SHA-256 fingerprints
curl lists beside them.

The key a server signs with reads from any file `openssl` writes:

```moonbit
let key = @x509.PrivateKey::pem(text)     // PRIVATE KEY, EC PRIVATE KEY, RSA PRIVATE KEY
key.public() == cert.spki.key()           // whether the two belong together
```

PKCS#8, SEC1 and PKCS#1 are told apart by their structure, so `PrivateKey::read`
takes the DER of any of them. A key whose parts disagree (primes that do not
make the modulus, an embedded public point that is not its own, two curves) is
`Malformed`; an encrypted key is `Unsupported`.

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

Certificate signing requests, PKCS#12, CRL and OCSP responses, COSE and CWT,
PASETO, and JWE. They are planned in that order; the tracking list
lives with the project. Online revocation needs an HTTP client and belongs with
the network, not here.

## Install

```bash
moon add moonbitstack/mooncred
```

## Licence

Apache-2.0.
