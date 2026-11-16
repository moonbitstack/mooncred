// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
let oid_ec_key : String = "1.2.840.10045.2.1"

///|
let oid_rsa : String = "1.2.840.113549.1.1.1"

///|
let oid_rsa_pss : String = "1.2.840.113549.1.1.10"

///|
/// id-dsa (RFC 3279 §2.3.2), whose parameters are the domain p, q and g.
let oid_dsa : String = "1.2.840.10040.4.1"

///|
/// dhpublicnumber (RFC 3279 §2.3.3, X9.42): a Diffie-Hellman key with p, g and q.
let oid_dh : String = "1.2.840.10046.2.1"

///|
/// dhKeyAgreement (PKCS #3): a Diffie-Hellman key with p and g, which is what OpenSSL writes.
let oid_dh_pkcs3 : String = "1.2.840.113549.1.3.1"

///|
let oid_ed25519 : String = "1.3.101.112"

///|
let oid_p256 : String = "1.2.840.10045.3.1.7"

///|
let oid_p384 : String = "1.3.132.0.34"

///|
let oid_p521 : String = "1.3.132.0.35"

///|
let oid_secp256k1 : String = "1.3.132.0.10"

///|
let oid_brainpool_p256r1 : String = "1.3.36.3.3.2.8.1.1.7"

///|
let oid_brainpool_p384r1 : String = "1.3.36.3.3.2.8.1.1.11"

///|
let oid_brainpool_p512r1 : String = "1.3.36.3.3.2.8.1.1.13"

///|
let oid_ml_dsa_44 : String = "2.16.840.1.101.3.4.3.17"

///|
let oid_ml_dsa_65 : String = "2.16.840.1.101.3.4.3.18"

///|
let oid_ml_dsa_87 : String = "2.16.840.1.101.3.4.3.19"

///|
/// The parameter set one of the three ML-DSA identifiers names (RFC 9881 §2), or `None` when the
/// identifier is some other algorithm. An ML-DSA public key and an ML-DSA signature are told apart
/// by nothing but this: the identifier is the algorithm and the parameter set at once.
fn ml_dsa_of(oid : String) -> @mldsa.Kind? {
  match oid {
    o if o == oid_ml_dsa_44 => Some(D44)
    o if o == oid_ml_dsa_65 => Some(D65)
    o if o == oid_ml_dsa_87 => Some(D87)
    _ => None
  }
}

///|
/// The object identifier arcs the same three sets are written by, for a writer that has the key
/// rather than the identifier.
fn ml_dsa_arcs(kind : @mldsa.Kind) -> Array[Int32] {
  match kind {
    D44 => [2, 16, 840, 1, 101, 3, 4, 3, 17]
    D65 => [2, 16, 840, 1, 101, 3, 4, 3, 18]
    D87 => [2, 16, 840, 1, 101, 3, 4, 3, 19]
  }
}

///|
/// A SubjectPublicKeyInfo: the algorithm OID, the parameter OID when the algorithm takes one, and
/// the key bits. For an EC key the parameter is the named curve; for an RSASSA-PSS key it is the
/// digest its parameters hold it to, read in the one shape `pss_params` takes, and `None` when it
/// is held to none. Absent and NULL parameters both read as `None`, which is what every algorithm
/// reachable from here means by either. `domain` is the parameters as DER when they are a
/// structure rather than an identifier: a DSA key's p, q and g (RFC 3279 §2.3.2), a
/// Diffie-Hellman key's p and g with whatever else its form adds.
#derive(Eq, Debug)
pub(all) struct Spki {
  alg : String
  params : String?
  domain : Bytes?
  key : @asn1.Bits
}

///|
/// A public key as a signature can be checked against. An RSA or EC key is held with the digest
/// its own algorithm defaults to; a certificate's signature algorithm decides the digest it is
/// actually checked with, so the key is re-read for each signature rather than fixed here.
pub(all) enum Key {
  Rsa(@rsa.PublicKey)
  Ec(@ecdsa.PublicKey)
  Ed25519(@ed25519.PublicKey)
  MlDsa(@mldsa.PublicKey)
  /// DSA over its own domain (FIPS 186-4), for TLS 1.2's DSS suites and the chains they show.
  Dsa(@dsa.PublicKey)
  /// A static Diffie-Hellman key: the prime, the generator and the public value, big-endian. It
  /// agrees on a secret and signs nothing; TLS 1.2's DH_RSA and DH_DSS suites put one in the
  /// server's certificate.
  Dh(prime~ : Bytes, generator~ : Bytes, public~ : Bytes)
}

///|
/// An AlgorithmIdentifier from its DER: the OID in dotted-decimal form and the parameters as
/// they were encoded, or `None` when the identifier has none. A certificate, a request, a
/// revocation list and a response all carry one, and `signature_ok` takes exactly this pair.
pub fn algorithm(der : BytesView) -> (String, Bytes?) raise @asn1.Refused {
  let (oid, params) = read_alg(@asn1.only(der))
  (oid, params.map(p => p.to_owned()))
}

///|
fn read_alg(tlv : @asn1.Tlv) -> (String, BytesView?) raise @asn1.Refused {
  if tlv.tag != 0x30 {
    raise @asn1.Malformed("AlgorithmIdentifier is not a SEQUENCE")
  }
  let items = tlv.items()
  if items.length() == 0 || items.length() > 2 {
    raise @asn1.Malformed(
      "AlgorithmIdentifier is not an OID and its parameters",
    )
  }
  let params = if items.length() == 2 { Some(items[1].raw) } else { None }
  (items[0].oid(), params)
}

///|
fn read_spki(tlv : @asn1.Tlv) -> Spki raise @asn1.Refused {
  if tlv.tag != 0x30 {
    raise @asn1.Malformed("SubjectPublicKeyInfo is not a SEQUENCE")
  }
  let items = tlv.items()
  if items.length() != 2 {
    raise @asn1.Malformed("SubjectPublicKeyInfo is not an algorithm and a key")
  }
  let (alg, params) = read_alg(items[0])
  let domain = if alg == oid_dsa || alg == oid_dh || alg == oid_dh_pkcs3 {
    params.map(p => p.to_owned())
  } else {
    None
  }
  let params = match params {
    Some(p) if alg == oid_rsa_pss => Some(digest_oid(pss_params(Some(p))))
    Some(p) => {
      let t = @asn1.only(p)
      if t.tag == 0x06 {
        Some(t.oid())
      } else {
        None
      }
    }
    None => None
  }
  { alg, params, domain, key: items[1].bits(), }
}

///|
/// Dss-Parms (RFC 3279 §2.3.2): the prime p, the subgroup order q and the generator g.
fn dsa_domain(der : BytesView) -> @dsa.Domain raise @asn1.Refused {
  let seq = @asn1.only(der)
  let items = if seq.tag == 0x30 { seq.items() } else { [] }
  if items.length() != 3 {
    raise @asn1.Malformed("Dss-Parms is not a p, a q and a g")
  }
  @dsa.Domain::raw(items[0].int(), items[1].int(), items[2].int())
}

///|
/// The DSA public key a SubjectPublicKeyInfo carries: y, an INTEGER inside the key bits, on the
/// domain its parameters give. RFC 3279 lets a certificate leave the domain to its issuer; such a
/// key is refused here, as webpki and Go refuse it.
fn dsa_key(spki : Spki) -> @dsa.PublicKey raise @asn1.Refused {
  guard spki.domain is Some(der) else {
    raise @asn1.Malformed("DSA key without its domain")
  }
  let domain = dsa_domain(der[:])
  let y = @asn1.only(key_octets(spki)[:]).int()
  if y <= 1 || y >= domain.p() {
    raise @asn1.Malformed("DSA public value outside its group")
  }
  @dsa.PublicKey::new(y.to_octets(length=domain.modulus_size())[:], domain~) catch {
    _ => raise @asn1.Malformed("DSA public value wider than its prime")
  }
}

///|
/// The prime and generator of a Diffie-Hellman key's parameters: X9.42's DomainParameters, p, g
/// and q with optional extras (RFC 3279 §2.3.3), or PKCS #3's DHParameter, p and g with an
/// optional length.
fn dh_group(der : BytesView) -> (BigInt, BigInt) raise @asn1.Refused {
  let seq = @asn1.only(der)
  let items = if seq.tag == 0x30 { seq.items() } else { [] }
  if items.length() < 2 {
    raise @asn1.Malformed("Diffie-Hellman parameters are not a p and a g")
  }
  let p = items[0].int()
  let g = items[1].int()
  if p <= 3 || g <= 1 || g >= p - 1 {
    raise @asn1.Malformed("Diffie-Hellman group out of range")
  }
  (p, g)
}

///|
/// A static Diffie-Hellman public key: y, an INTEGER in the key bits, inside the group.
fn dh_key(spki : Spki) -> Key raise @asn1.Refused {
  guard spki.domain is Some(der) else {
    raise @asn1.Malformed("Diffie-Hellman key without its group")
  }
  let (p, g) = dh_group(der[:])
  let y = @asn1.only(key_octets(spki)[:]).int()
  if y <= 1 || y >= p - 1 {
    raise @asn1.Malformed("Diffie-Hellman public value outside its group")
  }
  Dh(prime=p.to_octets(), generator=g.to_octets(), public=y.to_octets())
}

///|
/// DHParameter (PKCS #3) for a prime and a generator.
fn dh_parameter(prime : Bytes, generator : Bytes) -> Bytes {
  @asn1.sequence([@asn1.integer(prime), @asn1.integer(generator)])
}

///|
/// Dss-Parms for a domain.
fn dss_parms(domain : @dsa.Domain) -> Bytes {
  @asn1.sequence([
    @asn1.integer(domain.p().to_octets()),
    @asn1.integer(domain.q().to_octets()),
    @asn1.integer(domain.g().to_octets()),
  ])
}

///|
/// Read a bare SubjectPublicKeyInfo.
///
/// A certificate carries one in `Cert::spki`; this is for the ones that travel on their own — a
/// `PUBLIC KEY` PEM file, or the key MySQL's `caching_sha2_password` hands a client mid-handshake.
pub fn Spki::read(der : BytesView) -> Spki raise @asn1.Refused {
  read_spki(@asn1.only(der))
}

///|
fn curve_of(oid : String?) -> @curve.Curve raise @asn1.Refused {
  match oid {
    Some(o) if o == oid_p256 => P256
    Some(o) if o == oid_p384 => P384
    Some(o) if o == oid_p521 => P521
    Some(o) if o == oid_secp256k1 => Secp256k1
    Some(o) if o == oid_brainpool_p256r1 => BrainpoolP256r1
    Some(o) if o == oid_brainpool_p384r1 => BrainpoolP384r1
    Some(o) if o == oid_brainpool_p512r1 => BrainpoolP512r1
    Some(o) => raise @asn1.Unsupported("elliptic curve " + o)
    None => raise @asn1.Malformed("EC key without a named curve")
  }
}

///|
fn key_octets(spki : Spki) -> Bytes raise @asn1.Refused {
  if spki.key.unused != 0 {
    raise @asn1.Malformed("public key BIT STRING has unused bits")
  }
  spki.key.bytes
}

///|
/// The EC public key a SubjectPublicKeyInfo carries, on any of the four curves. Refuses the
/// compressed and hybrid point forms (RFC 5480 §2.2 allows them; webpki and Go do not) and a
/// point that is not on the curve.
fn ec_key(spki : Spki) -> @ecdsa.PublicKey raise @asn1.Refused {
  if spki.alg != oid_ec_key {
    raise @asn1.Unsupported("public key algorithm " + spki.alg)
  }
  let curve = curve_of(spki.params)
  let pt = key_octets(spki)
  if pt.length() != 1 + 2 * curve.size() || pt[0] != b'\x04' {
    raise @asn1.Malformed("public key is not an uncompressed point")
  }
  // Whether the point is on the curve is the curve's question, not the certificate's.
  @ecdsa.PublicKey::new(pt[:], curve~) catch {
    _ => raise @asn1.Malformed("public key is not a point on its curve")
  }
}

///|
/// The P-256 public key a SubjectPublicKeyInfo carries. Refuses any other curve.
pub fn Spki::p256(self : Spki) -> @ecdsa.PublicKey raise @asn1.Refused {
  if self.alg == oid_ec_key && self.params != Some(oid_p256) {
    raise @asn1.Unsupported("elliptic curve other than prime256v1")
  }
  ec_key(self)
}

///|
/// The scheme an RSASSA-PSS key held to `digest` signs and verifies under (RFC 4055 §3.1): MGF1
/// over the same digest, a salt as long as the digest. A key held to no digest reads as SHA-256,
/// the pairing RFC 8446 §4.2.3 names first; a TLS 1.3 peer picks the digest of each signature.
fn pss_scheme(digest : @rsa.Digest) -> (@rsa.Digest, @rsa.Scheme) {
  (digest, Pss(salt=Exact(digest_size(digest))))
}

///|
/// The OID of a digest RSASSA-PSS parameters may name.
fn digest_oid(digest : @rsa.Digest) -> String {
  match digest {
    Sha384 => "2.16.840.1.101.3.4.2.2"
    Sha512 => "2.16.840.1.101.3.4.2.3"
    _ => "2.16.840.1.101.3.4.2.1"
  }
}

///|
/// The digest an OID from `digest_oid` names.
fn digest_named(oid : String) -> @rsa.Digest raise @asn1.Refused {
  match oid {
    "2.16.840.1.101.3.4.2.1" => Sha256
    "2.16.840.1.101.3.4.2.2" => Sha384
    "2.16.840.1.101.3.4.2.3" => Sha512
    o => raise @asn1.Unsupported("RSASSA-PSS digest " + o)
  }
}

///|
/// The RSA public key a SubjectPublicKeyInfo carries.
///
/// The key bits are an `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`
/// (RFC 8017 §A.1.1). Refuses any algorithm but rsaEncryption and RSASSA-PSS; an RSASSA-PSS key
/// keeps the digest and scheme its parameters hold it to, whatever `digest` and `scheme` say.
///
/// `digest` and `scheme` are the signature parameters the key is built with. They do not enter
/// encryption at all — `@rsa.PublicKey::encrypt` takes its own — so a caller that only encrypts
/// can leave them alone.
pub fn Spki::rsa(
  self : Spki,
  digest~ : @rsa.Digest = Sha256,
  scheme~ : @rsa.Scheme = Pkcs1,
) -> @rsa.PublicKey raise @asn1.Refused {
  let (digest, scheme) = if self.alg == oid_rsa {
    (digest, scheme)
  } else if self.alg == oid_rsa_pss {
    pss_scheme(
      match self.params {
        Some(oid) => digest_named(oid)
        None => Sha256
      },
    )
  } else {
    raise @asn1.Unsupported("public key algorithm " + self.alg)
  }
  let seq = @asn1.only(key_octets(self)[:])
  if seq.tag != 0x30 {
    raise @asn1.Malformed("RSAPublicKey is not a SEQUENCE")
  }
  let items = seq.items()
  if items.length() != 2 {
    raise @asn1.Malformed("RSAPublicKey is not a modulus and an exponent")
  }
  let n = items[0].int().to_octets()
  let e = items[1].int().to_octets()
  @rsa.PublicKey::new(n[:], e[:], digest~, scheme~) catch {
    _ => raise @asn1.Malformed("RSAPublicKey carries an unusable modulus")
  }
}

///|
/// The public key a SubjectPublicKeyInfo carries: RSA, under rsaEncryption or RSASSA-PSS; ECDSA on
/// P-256, P-384, P-521, secp256k1 or the three brainpool curves of RFC 5639; Ed25519; or ML-DSA at
/// any of its three parameter sets. Another algorithm raises `Unsupported`.
pub fn Spki::key(self : Spki) -> Key raise @asn1.Refused {
  match self.alg {
    a if a == oid_rsa || a == oid_rsa_pss => Rsa(self.rsa())
    a if a == oid_ec_key => Ec(ec_key(self))
    a if a == oid_ed25519 => {
      if self.params is Some(_) {
        raise @asn1.Malformed("Ed25519 key with parameters")
      }
      let k = key_octets(self)
      Ed25519(
        @ed25519.PublicKey::new(k[:]) catch {
          _ => raise @asn1.Malformed("Ed25519 key is not 32 octets")
        },
      )
    }
    a if ml_dsa_of(a) is Some(kind) => MlDsa(ml_dsa_key(self, kind))
    a if a == oid_dsa => Dsa(dsa_key(self))
    a if a == oid_dh || a == oid_dh_pkcs3 => dh_key(self)
    a => raise @asn1.Unsupported("public key algorithm " + a)
  }
}

///|
/// The ML-DSA public key a SubjectPublicKeyInfo carries (RFC 9881 §4): the key bits are the raw
/// `pk` of FIPS 204 §7.2, not an ASN.1 structure, and the identifier's parameter set decides how
/// long that is. A key of the wrong length is refused here rather than at the first signature:
/// a shorter one would be a different algorithm's key wearing this identifier.
fn ml_dsa_key(
  spki : Spki,
  kind : @mldsa.Kind,
) -> @mldsa.PublicKey raise @asn1.Refused {
  if spki.params is Some(_) {
    raise @asn1.Malformed("ML-DSA key with parameters")
  }
  let pk = key_octets(spki)
  if pk.length() != kind.public_key() {
    raise @asn1.Malformed(
      "an ML-DSA key of \{pk.length()} octets where \{kind.public_key()} are asked for",
    )
  }
  @mldsa.PublicKey::new(kind~, pk[:]) catch {
    _ => raise @asn1.Malformed("ML-DSA public key of the wrong length")
  }
}

///|
/// The DER of an OBJECT IDENTIFIER written in dotted-decimal form, for the writers here that
/// build one from a constant or from a caller's string.
fn oid_der(dotted : String) -> Bytes raise @asn1.Refused {
  let arcs : Array[Int32] = []
  let mut value = 0
  let mut digits = 0
  for c in dotted {
    match c {
      '0'..<='9' => {
        value = value * 10 + (c.to_int() - '0'.to_int())
        digits = digits + 1
        if value > 2_000_000_000 {
          raise @asn1.Malformed("OID arc over 32 bits")
        }
      }
      '.' => {
        if digits == 0 {
          raise @asn1.Malformed("OID has an empty arc")
        }
        arcs.push(value)
        value = 0
        digits = 0
      }
      _ =>
        raise @asn1.Malformed(
          "OID has a character that is not a digit or a dot",
        )
    }
  }
  if digits == 0 {
    raise @asn1.Malformed("OID has an empty arc")
  }
  arcs.push(value)
  if arcs.length() < 2 {
    raise @asn1.Malformed("OID has fewer than two arcs")
  }
  @asn1.oid(arcs)
}

///|
/// The object identifier arcs a curve is named by, for the writer: every curve the crypto package
/// holds, the same list the reader takes.
fn curve_arcs(curve : @curve.Curve) -> Array[Int32] {
  match curve {
    P256 => [1, 2, 840, 10045, 3, 1, 7]
    P384 => [1, 3, 132, 0, 34]
    P521 => [1, 3, 132, 0, 35]
    Secp256k1 => [1, 3, 132, 0, 10]
    BrainpoolP256r1 => [1, 3, 36, 3, 3, 2, 8, 1, 1, 7]
    BrainpoolP384r1 => [1, 3, 36, 3, 3, 2, 8, 1, 1, 11]
    BrainpoolP512r1 => [1, 3, 36, 3, 3, 2, 8, 1, 1, 13]
  }
}

///|
/// The SubjectPublicKeyInfo for a public key: the algorithm, the parameters that algorithm
/// takes — NULL for RSA, the named curve for EC, none for Ed25519 and ML-DSA — and the key as a
/// BIT STRING. This is what a certificate, a request or a key file carries, built from a key in
/// hand.
pub fn Spki::encode(key : Key) -> Bytes {
  match key {
    Rsa(k) =>
      @asn1.sequence([
        @asn1.sequence([@asn1.oid([1, 2, 840, 113549, 1, 1, 1]), @asn1.null()]),
        @asn1.bit_string(
          @asn1.sequence([
            @asn1.integer(k.modulus()),
            @asn1.integer(k.exponent()),
          ]),
        ),
      ])
    Ec(k) =>
      @asn1.sequence([
        @asn1.sequence([
          @asn1.oid([1, 2, 840, 10045, 2, 1]),
          @asn1.oid(curve_arcs(k.curve())),
        ]),
        @asn1.bit_string(k.bytes()),
      ])
    Ed25519(k) =>
      @asn1.sequence([
        @asn1.sequence([@asn1.oid([1, 3, 101, 112])]),
        @asn1.bit_string(k.bytes()),
      ])
    // The key bits are the raw `pk` (RFC 9881 §4) and the identifier carries no parameters.
    MlDsa(k) =>
      @asn1.sequence([
        @asn1.sequence([@asn1.oid(ml_dsa_arcs(k.kind()))]),
        @asn1.bit_string(k.bytes()),
      ])
    Dsa(k) =>
      @asn1.sequence([
        @asn1.sequence([
          @asn1.oid([1, 2, 840, 10040, 4, 1]),
          dss_parms(k.domain()),
        ]),
        @asn1.bit_string(@asn1.integer(k.bytes())),
      ])
    Dh(prime~, generator~, public~) =>
      @asn1.sequence([
        @asn1.sequence([
          @asn1.oid([1, 2, 840, 113549, 1, 3, 1]),
          dh_parameter(prime, generator),
        ]),
        @asn1.bit_string(@asn1.integer(public)),
      ])
  }
}

///|
/// Whether this SubjectPublicKeyInfo carries `key`: the same algorithm and the same key material.
/// The digest or scheme a key was built with is not key material, an absent parameter and a NULL
/// one both read as no parameters, and a curve is compared as the identifier it is named by.
///
/// This is how a private key is matched to a certificate — `cert.spki.holds(key.public())` — the
/// question `PrivateKey::public` raises about, answered without building a key a second time.
pub fn Spki::holds(self : Spki, key : Key) -> Bool {
  let held = self.key() catch { _ => return false }
  held == key
}

///|
pub extend Spki with Debug::{to_repr}

///|
pub extend Spki with Eq::{not_equal, equal}
