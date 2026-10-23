// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
let oid_ec_key : String = "1.2.840.10045.2.1"

///|
/// rsaEncryption (RFC 8017 §A.1), the algorithm a SubjectPublicKeyInfo names when the key is RSA.
let oid_rsa : String = "1.2.840.113549.1.1.1"

///|
/// id-Ed25519 (RFC 8410 §3): the key algorithm and the signature algorithm are one OID.
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
/// A SubjectPublicKeyInfo: the algorithm OID, the parameter OID when the algorithm takes one (for
/// an EC key, the named curve), and the key bits. Absent and NULL parameters both read as `None`,
/// which is what every algorithm reachable from here means by either.
pub(all) struct Spki {
  alg : String
  params : String?
  key : @asn1.Bits
} derive(Eq, Debug)

///|
/// A public key as a signature can be checked against. An RSA or EC key is held with the digest
/// its own algorithm defaults to; a certificate's signature algorithm decides the digest it is
/// actually checked with, so the key is re-read for each signature rather than fixed here.
pub(all) enum Key {
  Rsa(@rsa.PublicKey)
  Ec(@ecdsa.PublicKey)
  Ed25519(@ed25519.PublicKey)
}

///|
/// An AlgorithmIdentifier (RFC 5280 §4.1.1.2) as its OID and the encoding of its parameters,
/// `None` when they are absent.
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
/// A SubjectPublicKeyInfo (RFC 5280 §4.1.2.7).
fn read_spki(tlv : @asn1.Tlv) -> Spki raise @asn1.Refused {
  if tlv.tag != 0x30 {
    raise @asn1.Malformed("SubjectPublicKeyInfo is not a SEQUENCE")
  }
  let items = tlv.items()
  if items.length() != 2 {
    raise @asn1.Malformed("SubjectPublicKeyInfo is not an algorithm and a key")
  }
  let (alg, params) = read_alg(items[0])
  let params = match params {
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
  { alg, params, key: items[1].bits(), }
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
/// The curve a named-curve OID stands for.
fn curve_of(oid : String?) -> @curve.Curve raise @asn1.Refused {
  match oid {
    Some(o) if o == oid_p256 => P256
    Some(o) if o == oid_p384 => P384
    Some(o) if o == oid_p521 => P521
    Some(o) if o == oid_secp256k1 => Secp256k1
    Some(o) => raise @asn1.Unsupported("elliptic curve " + o)
    None => raise @asn1.Malformed("EC key without a named curve")
  }
}

///|
/// The key bits as octets, refusing a BIT STRING with a partial last octet.
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
/// The RSA public key a SubjectPublicKeyInfo carries.
///
/// The key bits are an `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`
/// (RFC 8017 §A.1.1). Refuses any algorithm but rsaEncryption.
///
/// `digest` and `scheme` are the signature parameters the key is built with. They do not enter
/// encryption at all — `@rsa.PublicKey::encrypt` takes its own — so a caller that only encrypts
/// can leave them alone.
pub fn Spki::rsa(
  self : Spki,
  digest~ : @rsa.Digest = Sha256,
  scheme~ : @rsa.Scheme = Pkcs1,
) -> @rsa.PublicKey raise @asn1.Refused {
  if self.alg != oid_rsa {
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
/// The public key a SubjectPublicKeyInfo carries: RSA, ECDSA on P-256, P-384, P-521 or
/// secp256k1, or Ed25519. Another algorithm raises `Unsupported`.
pub fn Spki::key(self : Spki) -> Key raise @asn1.Refused {
  match self.alg {
    a if a == oid_rsa => Rsa(self.rsa())
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
    a => raise @asn1.Unsupported("public key algorithm " + a)
  }
}

///|
pub extend Spki with Debug::{to_repr}

///|
pub extend Spki with Eq::{not_equal, equal}
