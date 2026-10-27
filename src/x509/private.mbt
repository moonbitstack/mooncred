// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A private key as a server signs with: what a `PRIVATE KEY`, `EC PRIVATE KEY` or
/// `RSA PRIVATE KEY` file holds.
pub(all) enum PrivateKey {
  Rsa(@rsa.PrivateKey)
  Ec(@ecdsa.PrivateKey)
  Ed25519(@ed25519.PrivateKey)
}

///|
/// Read a private key from DER in any of the three forms in use: PKCS#8 (RFC 5958), SEC1's
/// ECPrivateKey (RFC 5915), or PKCS#1's RSAPrivateKey (RFC 8017 §A.1.2). The form is told by the
/// second element of the outer SEQUENCE, as OpenSSL tells it.
///
/// An RSA key whose primes do not multiply to its modulus, an EC key whose scalar is out of range
/// or whose embedded public key is not its own, and an Ed25519 seed of the wrong length are all
/// `Malformed`. An algorithm that does not sign (X25519) or a multi-prime RSA key is `Unsupported`.
pub fn PrivateKey::read(der : BytesView) -> PrivateKey raise @asn1.Refused {
  let seq = @asn1.only(der)
  if seq.tag != 0x30 {
    raise @asn1.Malformed("private key is not a SEQUENCE")
  }
  let items = seq.items()
  if items.length() < 2 || items[0].tag != 0x02 {
    raise @asn1.Malformed("private key does not open with a version")
  }
  match items[1].tag {
    0x30 => pkcs8(items)
    0x04 => sec1(items, None)
    0x02 => pkcs1(items)
    _ => raise @asn1.Malformed("private key is in no known form")
  }
}

///|
/// Read the first private key in a PEM file, under any of the labels `openssl` writes:
/// `PRIVATE KEY`, `EC PRIVATE KEY` (after which an `EC PARAMETERS` block is passed over) or
/// `RSA PRIVATE KEY`. An encrypted key, in either the PKCS#8 or the legacy `Proc-Type` form, is
/// `Unsupported`: decrypting it needs the passphrase and a cipher this package does not carry.
pub fn PrivateKey::pem(text : String) -> PrivateKey raise @asn1.Refused {
  if text.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") ||
    text.contains("Proc-Type: 4,ENCRYPTED") {
    raise @asn1.Unsupported("encrypted private key")
  }
  for label in ["PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY"] {
    if pems(text, label~) is [der, ..] {
      return PrivateKey::read(der[:])
    }
  }
  raise @asn1.Malformed("no private key in the PEM text")
}

///|
/// The public half: what the certificate for this key carries, so `key.public() == spki.key()`
/// tells whether a certificate and a key belong together.
pub fn PrivateKey::public(self : PrivateKey) -> Key {
  match self {
    Rsa(k) => Rsa(k.public())
    Ec(k) => Ec(k.public())
    Ed25519(k) => Ed25519(k.public())
  }
}

///|
/// Two public keys are equal when their key material is: modulus and exponent, curve and point,
/// or the Ed25519 octets. The digest an RSA or EC key was built with is not key material.
pub impl Eq for Key with fn equal(a, b) {
  match (a, b) {
    (Rsa(x), Rsa(y)) =>
      x.modulus() == y.modulus() && x.exponent() == y.exponent()
    (Ec(x), Ec(y)) => x.curve() == y.curve() && x.bytes() == y.bytes()
    (Ed25519(x), Ed25519(y)) => x.bytes() == y.bytes()
    _ => false
  }
}

///|
pub extend Key with Eq::{equal, not_equal}

///|
fn pkcs8(items : Array[@asn1.Tlv]) -> PrivateKey raise @asn1.Refused {
  if items.length() < 3 {
    raise @asn1.Malformed("PrivateKeyInfo is short of its key")
  }
  let version = items[0].int()
  if version != 0 && version != 1 {
    raise @asn1.Malformed("PrivateKeyInfo version is neither v1 nor v2")
  }
  let (alg, params) = read_alg(items[1])
  let inner = items[2].octets()
  match alg {
    a if a == oid_rsa => pkcs1(rsa_items(inner))
    a if a == oid_ec_key => {
      guard params is Some(p) else {
        raise @asn1.Malformed("EC key without a named curve")
      }
      let key = @asn1.only(inner)
      if key.tag != 0x30 {
        raise @asn1.Malformed("ECPrivateKey is not a SEQUENCE")
      }
      sec1(key.items(), Some(curve_of(Some(@asn1.only(p).oid()))))
    }
    a if a == oid_ed25519 => {
      if params is Some(_) {
        raise @asn1.Malformed("Ed25519 key with parameters")
      }
      let seed = @asn1.only(inner).octets()
      let key = @ed25519.PrivateKey::new(seed) catch {
        _ => raise @asn1.Malformed("Ed25519 seed is not 32 octets")
      }
      match public_bits(items[3:], 1) {
        Some(bits) if bits != key.public().bytes() =>
          raise @asn1.Malformed("Ed25519 public key is not the seed's own")
        _ => ()
      }
      Ed25519(key)
    }
    a => raise @asn1.Unsupported("private key algorithm " + a)
  }
}

///|
fn rsa_items(der : BytesView) -> Array[@asn1.Tlv] raise @asn1.Refused {
  let seq = @asn1.only(der)
  if seq.tag != 0x30 {
    raise @asn1.Malformed("RSAPrivateKey is not a SEQUENCE")
  }
  seq.items()
}

///|
/// RSAPrivateKey: version, n, e, d, p, q, d mod (p-1), d mod (q-1), q⁻¹ mod p.
fn pkcs1(items : Array[@asn1.Tlv]) -> PrivateKey raise @asn1.Refused {
  if items[0].int() != 0 {
    raise @asn1.Unsupported("multi-prime RSA key")
  }
  if items.length() != 9 {
    raise @asn1.Malformed("RSAPrivateKey is not nine INTEGERs")
  }
  let n = items[1].int()
  let p = items[4].int()
  let q = items[5].int()
  if p * q != n {
    raise @asn1.Malformed("RSA primes do not multiply to the modulus")
  }
  let key = @rsa.PrivateKey::new(
    n.to_octets()[:],
    items[2].int().to_octets()[:],
    items[3].int().to_octets()[:],
  ) catch {
    _ => raise @asn1.Malformed("RSAPrivateKey carries an unusable modulus")
  }
  Rsa(key)
}

///|
/// ECPrivateKey: version 1, the scalar, then `[0]` the curve and `[1]` the public point, both
/// optional. Inside PKCS#8 the curve comes from the outer AlgorithmIdentifier as `outer`; when the
/// key names one too, the two must agree.
fn sec1(
  items : Array[@asn1.Tlv],
  outer : @curve.Curve?,
) -> PrivateKey raise @asn1.Refused {
  if items.length() < 2 || items[0].int() != 1 {
    raise @asn1.Malformed("ECPrivateKey version is not 1")
  }
  let mut named = None
  for t in items[2:] {
    if @asn1.context(t.tag, 0) {
      named = Some(curve_of(Some(@asn1.only(t.value).oid())))
    }
  }
  let curve = match (outer, named) {
    (Some(a), Some(b)) if a != b =>
      raise @asn1.Malformed(
        "ECPrivateKey names another curve than its algorithm",
      )
    (Some(c), _) => c
    (None, Some(c)) => c
    (None, None) => raise @asn1.Malformed("EC key without a named curve")
  }
  let scalar = fixed(items[1].octets(), curve.size())
  let key = @ecdsa.PrivateKey::new(scalar[:], curve~) catch {
    _ => raise @asn1.Malformed("EC private key is out of range")
  }
  match public_bits(items[2:], 1) {
    Some(bits) if bits != key.public().bytes() =>
      raise @asn1.Malformed("EC public key is not the private key's own")
    _ => ()
  }
  Ec(key)
}

///|
/// The scalar at the curve's width. RFC 5915 fixes the width, but OpenSSL once dropped leading
/// zero octets and some encoders add them, so both are read.
fn fixed(scalar : BytesView, size : Int32) -> Bytes raise @asn1.Refused {
  let mut s = scalar
  while s.length() > size && s[0] == b'\x00' {
    s = s[1:]
  }
  if s.length() > size {
    raise @asn1.Malformed("EC private key is wider than its curve")
  }
  let out = Buffer()
  for _ in s.length()..<size {
    out.write_byte(b'\x00')
  }
  out.write_bytesview(s)
  out.to_bytes()
}

///|
/// The public key a private key carries alongside itself under context tag `n`: explicit in SEC1,
/// implicit in PKCS#8 v2.
fn public_bits(
  items : ArrayView[@asn1.Tlv],
  n : Int32,
) -> Bytes? raise @asn1.Refused {
  for t in items {
    if @asn1.context(t.tag, n) {
      let v = if (t.tag & 0x20) != 0 {
        @asn1.only(t.value).value
      } else {
        t.value
      }
      if v.length() == 0 || v[0] != b'\x00' {
        raise @asn1.Malformed("public key BIT STRING has unused bits")
      }
      return Some(v[1:].to_owned())
    }
  }
  None
}
