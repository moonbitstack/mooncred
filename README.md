<div align="center">

<h1>mooncred</h1>

<p><b>Credential formats for MoonBit.</b><br>
Tokens, certificates, the requests that ask for them, the containers they travel in,<br>
and the ways they are judged.</p>

<p>
<a href="https://moonbitstack.github.io/mooncred/">Home</a> ·
<a href="https://moonbitstack.github.io/mooncred/guide.html">Guide</a> ·
<a href="https://moonbitstack.github.io/mooncred/api.html">API</a> ·
<a href="https://mooncakes.io/docs/moonbitstack/mooncred">mooncakes</a>
</p>

</div>

```bash
moon add moonbitstack/mooncred
```

One rule runs through all of it: the algorithm a message claims is never the
algorithm a verifier uses. Every reader here takes the algorithm as an argument,
compares it with what the message says, and refuses the message when the two
disagree.

```moonbit
// The key is whatever signs. Here, HMAC over SHA-256.
let key = @jwt.mac(fn() {
  @hmac.Hmac::new(secret[:], fn() { @sha2.Hasher::new() })
})

let token = @jwt.sign(claims, HS256, key)

// The algorithm is the caller's, not the token's.
let got = @jwt.verify(token[:], HS256, key, now=At(seconds),
                      issuer="moonbitstack", audience=["moonapi"])
```

## Packages

| Package | What | Specification |
|:--:|:--|:--|
| `jwt` | JWS compact serialisation, all thirteen JOSE algorithms | RFC 7515, 7518, 7519, 8037 |
| `jwk` | JSON Web Key and key sets: reading, writing, choosing | RFC 7517, RFC 7518 §6 |
| `jwe` | JSON Web Encryption: five-part compact serialisation, key wrapping, GCM and CBC-HMAC | RFC 7516, RFC 7518, RFC 3394 |
| `token` | A signed string for a cookie or a URL: expiry on verify, a salt per purpose, key rotation | — |
| `x509` | X.509 v3 certificates: read one down to its extensions, check its signature under RSA, ECDSA or Ed25519, match it against a host, validate a chain to a set of trust anchors; build a self-signed P-256 one; read the private key that goes with it | RFC 5280, RFC 6125, RFC 7468, RFC 5958, RFC 5915 |
| `csr` | Certificate signing requests: read one, check its signature, see what it asks for, and write one | RFC 2986, RFC 2985 §5.4 |
| `pbe` | Encrypted private keys: PBES2 with PBKDF2, and the older PBES1 and PKCS#12 derivations openssl still writes | RFC 8018, RFC 7292 §B.2 |
| `pkcs12` | PFX containers: the certificate chain and the key, with a MAC, read and written | RFC 7292, RFC 5652 |
| `revoke` | Revocation lists and OCSP responses: read one and judge a certificate good, revoked or unknown | RFC 5280 §5, RFC 6960 |
| `policy` | Certificate policies over a chain: the §6.1 tree, mappings and the three counters | RFC 5280 §6.1 |
| `cbor` | CBOR, the subset COSE and CWT are written in | RFC 8949 |
| `cose` | COSE_Sign1, COSE_Mac0, COSE_Encrypt0, and CWT claim sets | RFC 9052, RFC 9053, RFC 8392 |
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
let ours = @jwt.Policy::new(issuer="moonbitstack", audience=["moonapi"])
// The same thing written as a record update.
let same : @jwt.Policy = { ..@jwt.policy, issuer: Some("moonbitstack"), audience: ["moonapi"] }

// Used as it is, and used with one thing changed for this call.
let a = @jwt.verify(token[:], HS256, key, now=At(seconds), policy=ours)
let b = @jwt.verify(token[:], HS256, key, now=At(seconds), policy=ours, leeway=60)

// Reading a token without asking whether it has expired.
let c = @jwt.verify(token[:], HS256, key, now=Ignored)
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
let verifier = match key.material() {
  Okp(x~, ..) => @ed25519.PublicKey::new(x[:])
  _ => abort("not an Ed25519 key")
}
```

### When a setting takes a bare value and when it takes `Some`

A setting whose preset is unset is written plainly, because there is nothing to
clear:

```moonbit
let policy = @jwt.Policy::new(issuer="https://issuer.example", leeway=30)
let got = @jwt.verify(token[:], HS256, key, now=At(seconds), issuer="https://issuer.example")
```

A setting whose preset is a value takes an option, because clearing it is one of
the things a caller needs to say. `sign` writes `typ: "JWT"` unless told
otherwise, and `None` is how a caller asks for no `typ` header at all:

```moonbit
let plain = @jwt.sign(claims, HS256, key)                      // typ: "JWT"
let access = @jwt.sign(claims, HS256, key, typ=Some("at+jwt"))  // typ: "at+jwt"
let bare = @jwt.sign(claims, HS256, key, typ=None)              // no typ header
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
let serves = cert.matches("a.example.com")    // subjectAltName names and addresses
let signed = cert.signed_by(issuer.spki)      // raises for an algorithm it does not check
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
let spki = @x509.Spki::read(@x509.Spki::encode(key.public()))
let pairs = spki == cert.spki             // whether the two belong together
```

PKCS#8, SEC1 and PKCS#1 are told apart by their structure, so `PrivateKey::read`
takes the DER of any of them. A key whose parts disagree (primes that do not
make the modulus, an embedded public point that is not its own, two curves) is
`Malformed`; an encrypted key is `Unsupported` — unless it is handed to
`read_encrypted` with the passphrase, which is what `pbe` is for.

## Requests, containers and revocation

The rest of what a certificate authority does, in the same shape: a reader that
takes octets, a writer that produces them, and no decision made on the caller's
behalf.

```moonbit
// A request to be signed, and the same request read back.
let pem = @csr.self_signed_pem(key, subject=@x509.common_name("csr.example.com"))
let request = @csr.Request::pem(pem)
let sound = request.verified()              // the signature, over the octets that arrived
let mine = request.asks_for(key.public())   // whether it asks for this key

// A key at rest, and the container that holds it.
let locked = key.encrypt(passphrase~, salt~, iv~, scheme=Aes256Cbc)
let back = @x509.PrivateKey::read_encrypted(locked[:], passphrase~)
let pfx = @pkcs12.build(certs~, key=Some(key.pkcs8()), passphrase~, salt~, iv~, mac_salt~)
let inside = @pkcs12.parse(pfx[:]).contents(passphrase~)

// Revocation, without a network in the library.
let list = @revoke.Crl::pem(text)
let fresh = list.fresh(now)                 // thisUpdate and nextUpdate, against the caller's clock
let status = list.status(cert)              // Good, Revoked(entry), or Unknown
```

`pbe` and `pkcs12` carry the two derivations openssl writes without being asked:
PBES2 with PBKDF2, which is what every current file uses, and PBES1 with the
older PKCS#12 key derivation, which is what a file from 2009 uses. Both are read;
only the modern one is written, because a writer can choose.

There is no entropy anywhere in this library. Salts, IVs and the seed RSA-OAEP
pads with are arguments, so a caller that has a source of randomness can use it
and a caller that has a test vector can pin one.

## Signed strings, JWE and COSE

Three ways to carry a credential that is not a JWT, each with the property that
made it worth having.

`token` is the smallest of them: a payload, an optional timestamp, and an HMAC
over both, in one URL-safe string. A `salt` is mixed in, so a token issued for
one purpose does not verify for another even under the same key, and `Keys`
holds a current and a previous key so rotation does not invalidate what was
already issued.

```moonbit
let text = @token.sign(payload, keys~, salt="session", at=Some(now))
let value = @token.verify(text[:], keys~, salt="session", max_age=Some(86400L), now~)
```

`jwe` is RFC 7516 with the key management and content encryption named
separately, because that is what they are: `dir` and the AES key wrapping
algorithms put a content key on the wire, RSA-OAEP-256 puts it somewhere only
the recipient can reach, and GCM or CBC-HMAC spends it on the payload. The
header is the additional data of the AEAD, so an edited header does not decrypt.

`cose` is the same three ideas in CBOR, for the networks where a JSON header is
too much: COSE_Sign1, COSE_Mac0 and COSE_Encrypt0, and the CWT claim set they
carry. `cbor` is its own package, so a program that reads a CWT does not link the
rest.

```moonbit
let message = @cose.sign1(payload, alg=Es256, signer, kid=Some(kid))
let opened = @cose.verify1(message[:], alg=Es256, verifier)

let claims = @cose.Claims::new(iss="moonbitstack", exp=4102444800L)
let cwt = @cose.signed(claims, alg=Hs256, mac)
let checked = @cose.verified(cwt[:], alg=Hs256, mac, now=At(seconds))
```

## Policy, when a chain has to be valid for a purpose

`x509.verify` answers whether a chain is trustworthy. `policy` answers a
narrower question that some deployments also ask: whether the chain is valid for
a particular *policy* — a statement an authority makes about what a certificate
may be used for. It is a separate package and a separate call, so a program that
never asks the question never links the answer.

```moonbit
let path = @x509.verify(chain[:], roots, now~)
let certs = []
for cert in path {
  certs.push(@policy.read(cert.raw))
}
let held = @policy.policies(certs, initial=["2.23.140.1.2.1"])   // empty: not valid for it
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

The new formats are measured against `openssl` rather than against themselves.
`scripts/gen_credentials.py` builds every fixture with it — a request with an
extensionRequest, PKCS#12 containers with and without a MAC, PBES2 keys under
five schemes, a CRL and three OCSP responses from a CA that issued, revoked and
never recorded a certificate, and an RSA key with a key wrapped to it — and each
reader is tested on a file it did not write. The writers are checked the other
way round: a CSR this library signs passes `openssl req -verify`, a container it
builds opens under `openssl pkcs12 -info`, and an OAEP-256 key it wraps decrypts
under `openssl pkeyutl`.

CBOR is checked against RFC 8949 Appendix A item by item, and the three COSE
structures against the layouts RFC 9052 §4.4, §5.3 and §6.3 print, byte for
byte.

## What is not here yet

PASETO, and signing with ML-DSA: the primitives both need are not in
`mooncrypt` yet, and this library does not implement primitives of its own.

Online revocation is not here on purpose — fetching a CRL or an OCSP response
needs an HTTP client, and judging one does not. `revoke` reads and judges; the
caller fetches. The same split applies to every package here: no clock, no
randomness, no network.

## Licence

Apache-2.0.
