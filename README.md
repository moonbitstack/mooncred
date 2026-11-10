<div align="center">

<h1>mooncred</h1>

<p><b>Credential formats for MoonBit.</b><br>
Tokens, certificates, the requests that ask for them, the containers they travel in,<br>
and the ways they are judged.</p>

<p>
<a href="https://moonbitstack.github.io/mooncred/">Home</a> ·
<a href="https://moonbitstack.github.io/mooncred/guide.html">Guide</a> ·
<a href="https://moonbitstack.github.io/mooncred/api.html">API</a> ·
<a href="https://moonbitstack.github.io/mooncred/try.html">Desk</a> ·
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
let secret = b"a shared secret nobody else has"
let key = @jwt.mac(fn() {
  @hmac.Hmac::new(secret[:], fn() { @sha2.Hasher::new() })
})

let claims : Map[String, Json] = {
  "sub": "heke1228",
  "iss": "moonbitstack",
  "aud": "moonapi",
  "exp": 1793235600,
}
let token = @jwt.sign(claims, HS256, key)

// The instant the claims are judged at, in Unix seconds: data, not a clock.
let seconds = 1793232000L

// The algorithm is the caller's, not the token's.
let got = @jwt.verify(token[:], HS256, key, now=At(seconds),
                      issuer="moonbitstack", audience=["moonapi"])
```

## Packages

| Package | What | Specification |
|:--:|:--|:--|
| `jwt` | JWS in both serialisations, with unencoded payloads; JWT; all thirteen JOSE algorithms | RFC 7515, 7518, 7519, 7797, 8037 |
| `jwk` | JSON Web Key and key sets: reading, writing, choosing | RFC 7517, RFC 7518 §6 |
| `jwe` | JSON Web Encryption in both serialisations: every RFC 7518 key-management algorithm, several recipients, additional data, compression | RFC 7516, 7518, 3394, 1951 |
| `token` | A signed string for a cookie or a URL: expiry on verify, a salt per purpose, key rotation | — |
| `x509` | X.509 v3 certificates: read one down to its extensions, check its signature under RSA, ECDSA, Ed25519 or ML-DSA, match it against a host, validate a chain to a set of trust anchors; build a self-signed one for any key; read the private key that goes with it | RFC 5280, RFC 6125, RFC 7468, RFC 5958, RFC 5915, RFC 9881 |
| `csr` | Certificate signing requests: read one, check its signature, see what it asks for, and write one | RFC 2986, RFC 2985 §5.4 |
| `pbe` | Encrypted private keys: PBES2 with PBKDF2, and the older PBES1 and PKCS#12 derivations openssl still writes | RFC 8018, RFC 7292 §B.2 |
| `pkcs12` | PFX containers: the certificate chain and the key, with a MAC, read and written | RFC 7292, RFC 5652 |
| `revoke` | Revocation lists and OCSP responses: read one and judge a certificate good, revoked or unknown | RFC 5280 §5, RFC 6960 |
| `policy` | Certificate policies over a chain: the §6.1 tree, mappings and the three counters | RFC 5280 §6.1 |
| `cbor` | CBOR, the subset COSE and CWT are written in | RFC 8949 |
| `cose` | COSE_Sign1, COSE_Mac0, COSE_Encrypt0, and CWT claim sets | RFC 9052, 9053, 8392 |
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
- `clash` decides what happens when a setting is given twice with different
  values: `Ignore` merges quietly, `Warn(f)` merges and passes one line to `f`,
  `Panic` aborts, and `Handle(f)` gives your function the names, the base and
  the merged result and takes what it returns.

Both types are [moonknob](https://github.com/moonbitstack/moonknob)'s, so the
same arguments work the same way in every library of the family.

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

## A payload that is not a claim set

A JWS carries octets. They need not be a claims set, and — under RFC 7797 — they
need not be base64url encoded either: the signature then covers the payload as
it stands, and the token can leave it out altogether for a caller that sends it
by another road. That is how a firmware image, an XML document, or a byte string
some protocol defined is signed without first turning it into JSON.

```moonbit
let signer = @jwt.mac(fn() {
  @hmac.Hmac::new(b"a shared secret nobody else has"[:], fn() { @sha2.Hasher::new() })
})

// b64: false, and the payload travels beside the token (RFC 7797 §4).
let detached = @jwt.sign_bytes(b"$.02", HS256, signer, b64=false, detached=true)
let octets = @jwt.verify_bytes(detached[:], HS256, signer, b64=false, payload=b"$.02")
assert_eq(octets, b"$.02")

// A payload that is not ASCII cannot travel in the compact form unencoded, so
// the compact form encodes it; the JSON serialisation can carry it either way.
let binary = @jwt.sign_bytes(b"\x00\x01\x02", HS256, signer)
assert_eq(@jwt.verify_bytes(binary[:], HS256, signer), b"\x00\x01\x02")
```

`crit` is read, not skipped: a token that lists a critical parameter this reader
does not implement is refused, because RFC 7515 §4.1.11 says a signature whose
extension you did not process is a signature you did not check. `b64` is the one
critical parameter understood here, and a token whose `b64` disagrees with the
caller's is refused rather than reconciled — the two readings cover different
octets.

The JSON serialisations carry more than the compact one: a parameter can travel
beside the signature instead of inside it, and one payload can carry several
signatures by different keys.

```moonbit
fn kid_of(kid : String) -> Map[String, Json] {
  let out : Map[String, Json] = Map([])
  out["kid"] = Json::string(kid)
  out
}
```

```moonbit
let message = @jwt.Message::new(b"{\"iss\":\"moonbitstack\"}")
  // The key's name travels unprotected; `alg` is always signed.
  .sign(HS256, signer, header=kid_of("2026-09"))
  // A second signature by the same key with no signed header at all
  // (RFC 7515 §A.5): the payload is authenticated and nothing about it is.
  .sign(HS256, signer, header=kid_of("2027-03"), bare=true)

let general = @json.dumps(message.json())
let flattened = @json.dumps(message.flattened())   // refused unless there is one
ignore(flattened)

// Each signature is offered with the algorithm and key that may open it, and
// nothing else is tried.
let checked = @jwt.verify_json(general[:], checks=[@jwt.Check::new(HS256, signer)])
assert_eq(checked.payload, b"{\"iss\":\"moonbitstack\"}")
```

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
let published = @jwk.Jwk::parse(
  "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}",
)
let verifier : &@spec.Verifier = match published.material() {
  Okp(x~, ..) => (@ed25519.PublicKey::new(x[:]) : &@spec.Verifier)
  _ => abort("not an Ed25519 key")
}
```

A private key keeps what the document gave it, down to the primes: `Jwk::crt`
hands back `p`, `q`, `dp`, `dq` and `qi` for a key that carries them, and
writing the key out puts them back.

```moonbit
let material = @jwk.Jwk::parse(
  "{\"kty\":\"oct\",\"k\":\"aGVsbG8gdGhlcmUgdGhpcyBpcyBhIGtleQ\",\"alg\":\"HS256\"}",
)
assert_eq(material.alg(), Some("HS256"))
assert_eq(material.crt(), None)
```

### When a setting takes a bare value and when it takes `Some`

A setting whose preset is unset is written plainly, because there is nothing to
clear:

```moonbit
let rules = @jwt.Policy::new(issuer="https://issuer.example", leeway=30)
let checked = @jwt.verify(token[:], HS256, key, now=At(seconds), issuer="https://issuer.example")
ignore(rules)
ignore(checked)
```

A setting whose preset is a value takes an option, because clearing it is one of
the things a caller needs to say. `sign` writes `typ: "JWT"` unless told
otherwise, and `None` is how a caller asks for no `typ` header at all:

```moonbit
let plain = @jwt.sign(claims, HS256, key)                      // typ: "JWT"
let access = @jwt.sign(claims, HS256, key, typ=Some("at+jwt"))  // typ: "at+jwt"
let bare = @jwt.sign(claims, HS256, key, typ=None)              // no typ header
ignore(plain)
ignore(access)
ignore(bare)
```

The shape follows from the preset, never from the label, so the same rule reads
the same way in every library here.

## Certificates

The certificate this section runs on is one the library made, so every line
below executes as written; a real program reads the leaf and intermediates the
peer sent instead.

```moonbit
let seed = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
let issue_key : @x509.PrivateKey = MlDsa(@mldsa.PrivateKey::from_seed(kind=D65, seed))
let der = @x509.self_signed(
  key=issue_key,
  cn="example.com",
  serial=b"\x01",
  not_before=1793232000L,                  // seconds since the Unix epoch
  not_after=1824768000L,
  exts={ ..@x509.Exts::empty(), san: [Dns("example.com")] },
)
let chain : Array[Bytes] = [der]
let anchors = @x509.Roots::new(certs=chain[:])
let now = 1793232000L
```

Validate it the way a client validates a server:

```moonbit
// The peer's leaf first, then whatever intermediates it sent, in any order.
let path = @x509.verify(chain[:], anchors, now~, host="example.com")
// path: the leaf, the intermediates it runs through, the anchor

// Or one certificate on its own.
let cert = @x509.parse(der[:])
let serves = cert.matches("example.com")     // subjectAltName names and addresses
let signed = cert.signed_by(cert.spki)       // raises for an algorithm it does not check
let every_anchor = @roots.mozilla()          // the bundle, its own package
assert_true(serves)
assert_true(signed)
assert_eq(path.length(), 1)
assert_true(every_anchor.length() > 100)
```

`verify` refuses with a reason and the position of the certificate it is about:
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
| RSA PKCS#1 and PSS, ECDSA on four curves, Ed25519, ML-DSA at all three sets; no SHA-1 | webpki, Go, RFC 9881 |
| An ML-DSA key asserts no keyEncipherment or keyAgreement, which a signing key cannot do | RFC 9881 §5 |
| At most six intermediates and a hundred signature checks | webpki |

The two limits and the purpose are a `Policy`, with `policy` as the preset.

`roots` is its own package, so a program that brings its own anchors never
links the bundle. The certificates are checked against the SHA-256 fingerprints
curl lists beside them.

The key a server signs with reads from any file `openssl` writes:

```moonbit
let text = issue_key.pkcs8_pem()              // what a PRIVATE KEY file contains
let loaded = @x509.PrivateKey::pem(text)      // PRIVATE KEY, EC PRIVATE KEY, RSA PRIVATE KEY
let pairs = cert.spki.holds(loaded.public())  // whether the two belong together
assert_true(pairs)
```

PKCS#8, SEC1 and PKCS#1 are told apart by their structure, so `PrivateKey::read`
takes the DER of any of them. A key whose parts disagree (primes that do not
make the modulus, an embedded public point that is not its own, two curves) is
`Malformed`; an encrypted key is `Unsupported` — unless it is handed to
`read_encrypted` with the passphrase, which is what `pbe` is for.

A post-quantum certificate is the same call with a different key, because the
signature algorithm follows the key: ML-DSA at all three parameter sets, the
chosen one in the certificate's own identifier and in the signature over its
TBS (RFC 9881 §3). `moon run src/examples/pqc` writes one out, and
`openssl verify` accepts it.

## Requests, containers and revocation

The rest of what a certificate authority does, in the same shape: a reader that
takes octets, a writer that produces them, and no decision made on the caller's
behalf.

```moonbit
// A request to be signed, and the same request read back.
let pem = @csr.self_signed_pem(issue_key, subject=@x509.common_name("csr.example.com"))
let request = @csr.Request::pem(pem)
let sound = request.verified()                   // the signature, over the octets that arrived
let mine = request.asks_for(issue_key.public())  // whether it asks for this key
assert_true(sound)
assert_true(mine)
```

```moonbit
// A key at rest, and the container that holds it.
let salt = b"0123456789abcdef"
let passphrase = "a passphrase for the container"
let locked = issue_key.encrypt(passphrase~, salt~, iv=salt[:], scheme=Aes256Cbc)
let back = @x509.PrivateKey::read_encrypted(locked[:], passphrase~)
let pfx = @pkcs12.build(
  certs=chain[:],
  key=Some(issue_key.pkcs8()),
  passphrase~,
  salt~,
  iv=salt[:],
  mac_salt=salt[:],
)
let inside = @pkcs12.parse(pfx[:]).contents(passphrase~)
assert_true(back.public() is MlDsa(_))
assert_true(inside.key is Some(_))
```

Revocation is read and judged, never fetched: the caller brings the CRL or the
OCSP response, and this library answers what it says.

```moonbit
fn standing(crl_pem : String, cert : @x509.Cert, at : Int64) -> String raise {
  let list = @revoke.Crl::pem(crl_pem)
  if !list.fresh(at) {
    return "stale"
  }
  match list.status(cert) {
    Good => "good"
    Revoked(_) => "revoked"
    Unknown => "unknown"
  }
}
```

`pbe` and `pkcs12` carry the two derivations openssl writes without being asked:
PBES2 with PBKDF2, which is what every current file uses, and PBES1 with the
older PKCS#12 key derivation, which is what a file from 2009 uses. Both are read;
only the modern one is written, because a writer can choose.

There is no entropy anywhere in this library. Salts, IVs and the seed RSA-OAEP
pads with are arguments, so a caller that has a source of randomness can use it
and a caller that has a test vector can pin one.

## A signed string for a cookie

`token` is the smallest credential here: a payload, an optional timestamp, and
an HMAC over both, in one URL-safe string. A `salt` is mixed in, so a token
issued for one purpose does not verify for another even under the same key, and
`Keys` holds a current and a previous key so rotation does not invalidate what
was already issued.

```moonbit
let keys = @token.Keys::new(b"the key that signs session cookies")
let text = @token.sign(b"user=heke1228", keys~, salt="session", at=seconds)
let value = @token.verify(text[:], keys~, salt="session", max_age=86400L, now=seconds)
assert_eq(value, b"user=heke1228")
```

## JWE: one payload, keys chosen per recipient

`jwe` is RFC 7516 with the key management and content encryption named
separately, because that is what they are. The content-encryption key is
protected once per recipient, by whichever algorithm that recipient's key
allows:

| Key management | What the recipient holds | Wrapped key on the wire |
|:--|:--|:--|
| `dir` | the content key itself | nothing |
| `A128KW`, `A192KW`, `A256KW` | a shared key-encryption key | the content key, AES key wrap (RFC 3394) |
| `A128GCMKW`, `A192GCMKW`, `A256GCMKW` | a shared key-encryption key | the content key under AES-GCM; nonce and tag in the header |
| `RSA-OAEP-256` | an RSA key | the content key under RSAES-OAEP with SHA-256 |
| `ECDH-ES` | an elliptic-curve key | nothing: the content key is derived |
| `ECDH-ES+A128KW`, `+A192KW`, `+A256KW` | an elliptic-curve key | the content key under a derived key-encryption key |
| `PBES2-HS256+A128KW`, `HS384+A192KW`, `HS512+A256KW` | a password | the content key under a key derived from it |

Every algorithm RFC 7518 names is supported and accepted without being asked,
including `RSA1_5` and `RSA-OAEP` (SHA-1): a library that can only read what it
would itself have written cannot be put in front of the traffic that already
exists. The two can be refused — the first carries a padding oracle in its own
construction, the second is the same construction under a hash that is no longer
a barrier — and then neither sealing nor opening will use them:

```moonbit
let shared = b"a 16-octet key"
let content = b"0001020304050607"
let iv = b"twelve bytes"

// dir: the shared key is the content key.
let direct = @jwe.encrypt(
  b"card ending 4242",
  key=Shared(shared),
  alg=Dir,
  enc=A128Gcm,
  iv~,
)
assert_eq(@jwe.decrypt(direct[:], key=Shared(shared), alg=Dir, enc=A128Gcm), b"card ending 4242")

// A key wrapped under a password: the salt and the count are the caller's,
// and the key is derived rather than held.
let sealed = @jwe.encrypt(
  b"card ending 4242",
  key=Password(b"a passphrase for the auditor"),
  alg=Pbes2Hs256A128Kw,
  enc=A128Gcm,
  cek=content,
  iv~,
  salt=b"sixteen byte sal",
  count=4096,
)
let opened = @jwe.decrypt(
  sealed[:],
  key=Password(b"a passphrase for the auditor"),
  alg=Pbes2Hs256A128Kw,
  enc=A128Gcm,
)
assert_eq(opened, b"card ending 4242")

// Every algorithm is accepted by default.
assert_eq(@jwe.policy.rsa1_5, true)
assert_eq(@jwe.policy.rsa_oaep, true)

// A deployment that will not answer for the two says so once, and both
// directions obey it.
let only_modern = @jwe.strict
assert_eq(only_modern.rsa1_5, false)

// Or one at a time.
let no_rsa1_5 = @jwe.Policy::new(rsa1_5=false)
assert_eq(no_rsa1_5.rsa_oaep, true)
```

The JSON serialisation is where the compact form runs out: one ciphertext for
several recipients, data that is authenticated but not carried in a header, and
compression.

```moonbit
let content = b"0001020304050607"
let message = @jwe.seal(
  b"card ending 4242",
  enc=A128Gcm,
  recipients=[
    {
      ..@jwe.Recipient::new(A128Kw, Shared(b"sixteen byte key")),
      cek: Some(content),
      header: kid_of("ops"),
    },
    {
      ..@jwe.Recipient::new(
        Pbes2Hs256A128Kw,
        Password(b"a passphrase for the auditor"),
      ),
      cek: Some(content),
      salt: Some(b"sixteen byte sal"),
      count: Some(4096),
      header: kid_of("audit"),
    },
  ],
  iv=b"twelve bytes",
  aad=b"tenant=42",
)
let document = @json.dumps(message)
let opened = @jwe.open(
  document[:],
  enc=A128Gcm,
  unseal=[@jwe.Unseal::new(A128Kw, Shared(b"sixteen byte key"))],
)
assert_eq(opened.index, 0)                      // which recipient opened it
assert_eq(opened.aad, b"tenant=42")             // authenticated, not carried
assert_eq(opened.plain, b"card ending 4242")
```

`zip: DEF` deflates the payload before it is encrypted, which is what makes a
JWE of a document smaller than the document: `compress=true` on the seal, and
the reader inflates what the header says. `layout` says whether `alg` and `enc`
travel protected, per recipient, or not at all — RFC 7516 leaves that open, and
a reader takes any of the three.

## COSE

`cose` is the same three ideas in CBOR, for the networks where a JSON header is
too much: COSE_Sign1, COSE_Mac0 and COSE_Encrypt0, and the CWT claim set they
carry. `cbor` is its own package, so a program that reads a CWT does not link the
rest.

```moonbit
let signature_key = @ed25519.PrivateKey::new(seed)
let message = @cose.sign1(b"payload", alg=EdDSA, signature_key, kid=b"2026-09")
let opened = @cose.verify1(message[:], alg=EdDSA, signature_key.public())
assert_eq(opened, b"payload")

let claims : @cose.Claims = { ..@cose.Claims::new(), iss: Some("moonbitstack"), exp: Some(4102444800L) }
let cwt = @cose.signed(claims, alg=EdDSA, signature_key)
let checked = @cose.verified(cwt[:], alg=EdDSA, signature_key.public(), now=At(seconds))
assert_eq(checked.iss, Some("moonbitstack"))
```

## Policy, when a chain has to be valid for a purpose

`x509.verify` answers whether a chain is trustworthy. `policy` answers a
narrower question that some deployments also ask: whether the chain is valid for
a particular *policy* — a statement an authority makes about what a certificate
may be used for. It is a separate package and a separate call, so a program that
never asks the question never links the answer.

```moonbit
let certificates = []
for one in path {
  certificates.push(@policy.read(one.raw))
}
let held = @policy.policies(certificates, initial=["2.23.140.1.2.1"])
assert_eq(held.length(), 0)   // this certificate carries no policy of that name
```

## What is checked

Every one of the thirteen algorithms is verified against a token produced by a
third-party signer, and the ten deterministic ones are reproduced byte for byte.
RFC 7515 §A.1's worked example verifies exactly as printed, line breaks and all.
RFC 7797's unencoded-payload example is reproduced signature for signature. The
key sets of RFC 7517 §A.1 and §A.3 and the Ed25519 key of RFC 8037 §A.1 read to
the bytes they stand for.

Alongside the vectors: a token whose header names another algorithm, one with
`alg: none`, one whose signature was replaced, one verified under another key,
expiry and not-before at the exact second, `iss` and `aud`, a token whose `b64`
contradicts the caller's, one with a critical parameter this reader does not
know, and ten shapes that are not tokens — all refused, each with its own
reason.

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

## Conformance

The path validator is measured against the C2SP [x509-limbo][limbo] suite at commit
`519f4bc` of 2 November 2026. It holds 9,807 cases — a chain, a set of anchors, a
time, and the verdict a validator is supposed to reach — of which 9,721 end here
the way the suite says they should.

Thirty-four are outside what `verify` takes: twenty-two ask about a revocation
list, ten name an email address as the peer, and two constrain the key usage of
the leaf. The other 52 are judged differently, and each of those is a rule this
library states rather than an oversight:

| The rule | Cases |
|:--|:--|
| The trusted anchor is a name and a key: its own validity, extensions and criticality are not examined. | `rfc5280::aki::critical-aki`, `rfc5280::aki::cross-signed-root-missing-aki`, `rfc5280::nc::permitted-dns-match-noncritical`, `rfc5280::root-inconsistent-ca-extensions`, `rfc5280::root-missing-basic-constraints`, `rfc5280::root-non-critical-basic-constraints`, `rfc5280::ski::root-missing-ski`, `rfc5280::unknown-critical-extension-root`, `rfc5280::validity::expired-root`, `webpki::aki::root-with-aki-all-fields`, `webpki::aki::root-with-aki-authoritycertissuer`, `webpki::aki::root-with-aki-authoritycertserialnumber`, `webpki::aki::root-with-aki-missing-keyidentifier`, `webpki::aki::root-with-aki-ski-mismatch`, `webpki::eku::root-has-eku` |
| A leaf certificate that is itself a CA is refused. | `pathlen::validation-ignores-pathlen-in-leaf`, `rfc5280::ca-as-leaf` |
| The profile rules that decide how a certificate may be issued, rather than whether a path is trustworthy: a common name that repeats its subject alternative name character for character, the criticality of a subject alternative name or a key purpose, the shape of an authority information access extension, wildcards over a public suffix. | `webpki::cn::case-mismatch`, `webpki::cn::ipv4-hex-mismatch`, `webpki::cn::ipv4-leading-zeros-mismatch`, `webpki::cn::ipv6-non-rfc5952-mismatch`, `webpki::cn::ipv6-uncompressed-mismatch`, `webpki::cn::ipv6-uppercase-mismatch`, `webpki::cn::not-in-san`, `webpki::cn::punycode-not-in-san`, `webpki::cn::utf8-vs-punycode-mismatch`, `webpki::eku::ee-anyeku`, `webpki::eku::ee-critical-eku`, `webpki::eku::ee-without-eku`, `webpki::malformed-aia`, `webpki::san::public-suffix-multi-label-wildcard-san`, `webpki::san::public-suffix-private-namespace-wildcard-san`, `webpki::san::san-critical-with-nonempty-subject` |
| An authority key identifier or a subject key identifier, which the path algorithm never reads. | `rfc5280::aki::intermediate-missing-aki`, `rfc5280::aki::leaf-missing-aki`, `rfc5280::ski::critical-ski`, `rfc5280::ski::intermediate-missing-ski` |
| The strength of the key that signs, which `policy.bits` bounds, and not the shape of the key the leaf carries. | `webpki::forbidden-dsa-leaf`, `webpki::forbidden-p192-leaf`, `webpki::forbidden-rsa-key-not-divisible-by-8-in-leaf`, `webpki::forbidden-rsa-not-divisible-by-8-in-root`, `webpki::forbidden-weak-rsa-in-leaf` |
| The issuance rules for a certificate's own extensions, which a validator is not asked to audit: a serial number of zero or over twenty octets, `keyCertSign` on an end entity, name constraints in an end entity, the criticality of policy constraints. | `rfc5280::ca-empty-subject`, `rfc5280::leaf-ku-keycertsign`, `rfc5280::nc::not-allowed-in-ee-critical`, `rfc5280::nc::not-allowed-in-ee-noncritical`, `rfc5280::pc::ica-noncritical-pc`, `rfc5280::san::noncritical-with-empty-subject`, `rfc5280::san::underscore-dns`, `rfc5280::serial::too-long`, `rfc5280::serial::zero` |
| A constraint written with a leading period, read as every name below it. | `rfc5280::nc::invalid-dnsname-leading-period` |

The JOSE side is measured against [RFC 7520][7520] and against [go-jose][gojose],
and both directions are replayed. RFC 7520's eight JWS examples (§4.1–§4.8) and
thirteen JWE examples (§5.1–§5.13) are read from the values the RFC prints: each
signature is verified and made again, and each message is opened. The examples
whose octets are a function of the parameters they publish are sealed again and
compared octet for octet — §4.1 and §4.4 among the signatures, and §5.3, §5.6,
§5.7, §5.8, §5.10, §5.11 and §5.12 among the messages. The rest draw a nonce
the RFC does not publish (RSA's padding, an OAEP seed, an ephemeral scalar, a
DEFLATE stream) or an ECDSA nonce, so for those the check is that the published
octets open and that this library's own octets verify.

`scripts/gen_jose_vectors.py` runs [go-jose][gojose] over the same ground in both
directions: go-jose seals twelve messages and this library opens them; this
library seals nine with every parameter pinned, go-jose opens them, and the
plaintext it recovered is recorded beside the token. ECDH-ES, PBES2, AES-GCM key
wrap, RSA-OAEP-256, compression, several recipients and additional data each
cross at least one boundary.

One case is a disagreement, and the RFC is on this library's side: go-jose writes
the `payload` member base64url encoded even under `b64: false`, where RFC 7797 §3
says the payload is then represented as itself. The token it wrote is kept, and
the test asserts that this library refuses it rather than reading it the other
way round.

[limbo]: https://github.com/C2SP/x509-limbo
[7520]: https://www.rfc-editor.org/rfc/rfc7520
[gojose]: https://github.com/go-jose/go-jose

## What is not here yet

PASETO, and SLH-DSA certificates: the primitives they need are not in
`mooncrypt` yet, and this library does not implement primitives of its own.

Online revocation is not here on purpose — fetching a CRL or an OCSP response
needs an HTTP client, and judging one does not. `revoke` reads and judges; the
caller fetches. The same split applies to every package here: no clock, no
randomness, no network.

## Licence

Apache-2.0.
