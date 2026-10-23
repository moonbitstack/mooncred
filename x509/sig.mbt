// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// How a certificate's signature is checked: the scheme its algorithm names, with the digest.
priv enum Scheme {
  Pkcs1(@rsa.Digest)
  Pss(@rsa.Digest)
  Ecdsa(@sha2.Kind)
  Eddsa
}

///|
/// The digest an AlgorithmIdentifier inside RSASSA-PSS-params names (RFC 4055 §2.1). Only the
/// SHA-2 digests webpki and Go accept; the parameters must be NULL or absent.
fn pss_digest(t : @asn1.Tlv) -> @rsa.Digest raise @asn1.Refused {
  let (oid, params) = read_alg(t)
  if params is Some(p) && p.to_owned() != b"\x05\x00" {
    raise @asn1.Malformed("digest AlgorithmIdentifier has parameters")
  }
  match oid {
    "2.16.840.1.101.3.4.2.1" => Sha256
    "2.16.840.1.101.3.4.2.2" => Sha384
    "2.16.840.1.101.3.4.2.3" => Sha512
    o => raise @asn1.Unsupported("RSASSA-PSS digest " + o)
  }
}

///|
/// The octet length of a digest.
fn digest_size(d : @rsa.Digest) -> Int32 {
  match d {
    Sha1 => 20
    Sha224 => 28
    Sha256 => 32
    Sha384 => 48
    Sha512 => 64
  }
}

///|
/// RSASSA-PSS-params (RFC 4055 §3.1), held to the one shape anyone issues: SHA-256, SHA-384 or
/// SHA-512, MGF1 over the same digest, a salt as long as the digest, the trailer left at its
/// default. Go and webpki accept exactly this; a certificate signed otherwise is refused as an
/// unsupported algorithm rather than checked under parameters nobody else would honour.
fn pss_params(params : BytesView?) -> @rsa.Digest raise @asn1.Refused {
  let seq = match params {
    Some(p) => @asn1.only(p)
    None =>
      raise @asn1.Unsupported("RSASSA-PSS with default (SHA-1) parameters")
  }
  if seq.tag != 0x30 {
    raise @asn1.Malformed("RSASSA-PSS-params is not a SEQUENCE")
  }
  let mut digest : @rsa.Digest? = None
  let mut mgf : @rsa.Digest? = None
  let mut salt : Int32? = None
  for f in seq.items() {
    let inner = @asn1.only(f.value)
    match f.tag {
      0xa0 => digest = Some(pss_digest(inner))
      0xa1 => {
        let (oid, p) = read_alg(inner)
        if oid != "1.2.840.113549.1.1.8" {
          raise @asn1.Unsupported("RSASSA-PSS mask generation " + oid)
        }
        guard p is Some(p) else {
          raise @asn1.Malformed("MGF1 without a digest")
        }
        mgf = Some(pss_digest(@asn1.only(p)))
      }
      0xa2 => {
        let n = inner.int()
        if n < (0 : BigInt) || n > (1024 : BigInt) {
          raise @asn1.Malformed("RSASSA-PSS salt length out of range")
        }
        salt = Some(n.to_int())
      }
      0xa3 =>
        if inner.int() != (1 : BigInt) {
          raise @asn1.Malformed("RSASSA-PSS trailer field is not 1")
        }
      _ => raise @asn1.Malformed("unexpected field in RSASSA-PSS-params")
    }
  }
  guard digest is Some(d) else {
    raise @asn1.Unsupported("RSASSA-PSS with the default SHA-1 digest")
  }
  if mgf != Some(d) || salt != Some(digest_size(d)) {
    raise @asn1.Unsupported("RSASSA-PSS parameters other than the digest's own")
  }
  d
}

///|
/// The scheme a signature AlgorithmIdentifier names. SHA-1 and SHA-224 signatures are refused:
/// a trust anchor's own signature is never checked, so the only place SHA-1 survives in a
/// modern chain needs no support here.
fn scheme_of(oid : String, params : BytesView?) -> Scheme raise @asn1.Refused {
  let none = params is None
  let null = params is Some(p) && p.to_owned() == b"\x05\x00"
  match oid {
    "1.2.840.113549.1.1.11" if none || null => Pkcs1(Sha256)
    "1.2.840.113549.1.1.12" if none || null => Pkcs1(Sha384)
    "1.2.840.113549.1.1.13" if none || null => Pkcs1(Sha512)
    "1.2.840.113549.1.1.10" => Pss(pss_params(params))
    "1.2.840.10045.4.3.2" if none => Ecdsa(Sha256)
    "1.2.840.10045.4.3.3" if none => Ecdsa(Sha384)
    "1.2.840.10045.4.3.4" if none => Ecdsa(Sha512)
    "1.3.101.112" if none => Eddsa
    "1.2.840.113549.1.1.11"
    | "1.2.840.113549.1.1.12"
    | "1.2.840.113549.1.1.13"
    | "1.2.840.10045.4.3.2"
    | "1.2.840.10045.4.3.3"
    | "1.2.840.10045.4.3.4"
    | "1.3.101.112" =>
      raise @asn1.Malformed(
        "signature algorithm " + oid + " with wrong parameters",
      )
    o => raise @asn1.Unsupported("signature algorithm " + o)
  }
}

///|
/// An ECDSA-Sig-Value (RFC 5480 §2.2) as the fixed-width `r || s` the verifier takes, or `None`
/// when either integer does not fit the curve — such a signature cannot be valid.
fn ecdsa_raw(sig : BytesView, size : Int32) -> Bytes? raise @asn1.Refused {
  let seq = @asn1.only(sig)
  if seq.tag != 0x30 {
    raise @asn1.Malformed("ECDSA-Sig-Value is not a SEQUENCE")
  }
  let rs = seq.items()
  if rs.length() != 2 {
    raise @asn1.Malformed("ECDSA-Sig-Value is not an r and an s")
  }
  let r = rs[0].int()
  let s = rs[1].int()
  if r <= (0 : BigInt) || s <= (0 : BigInt) {
    return None
  }
  let ro = r.to_octets()
  let so = s.to_octets()
  if ro.length() > size || so.length() > size {
    return None
  }
  let buf = Buffer()
  buf.write_bytes(r.to_octets(length=size))
  buf.write_bytes(s.to_octets(length=size))
  Some(buf.to_bytes())
}

///|
/// Check the certificate's signature under `issuer` — its issuer's key, or its own if it is
/// self-signed. RSA PKCS#1 v1.5 and PSS with SHA-256, SHA-384 or SHA-512, ECDSA with the same
/// three digests on any of the four curves, and Ed25519. An algorithm outside that set raises
/// `Unsupported` rather than returning false, so a caller cannot read "not checked" as "checked
/// and bad". A key of the wrong kind for the algorithm returns false: no signature by that
/// algorithm verifies under it.
pub fn Cert::signed_by(self : Cert, issuer : Spki) -> Bool raise @asn1.Refused {
  let scheme = scheme_of(self.alg, self.params.map(p => p[:]))
  if self.sig.unused != 0 {
    raise @asn1.Malformed("signature BIT STRING has unused bits")
  }
  let sig = self.sig.bytes[:]
  match (scheme, issuer.key()) {
    (Pkcs1(d), Rsa(k)) => rsa_with(k, d, Pkcs1).verify(self.tbs, sig)
    (Pss(d), Rsa(k)) =>
      rsa_with(k, d, Pss(salt=digest_size(d))).verify(self.tbs, sig)
    (Ecdsa(kind), Ec(k)) => {
      let curve = k.curve()
      guard ecdsa_raw(sig, curve.size()) is Some(raw) else { return false }
      let key = @ecdsa.PublicKey::with_hash(
        k.bytes()[:],
        () => (@sha2.Hasher::new(kind~) : &@spec.Hash),
        curve~,
      ) catch {
        _ => return false
      }
      key.verify(self.tbs, raw[:])
    }
    (Eddsa, Ed25519(k)) => k.verify(self.tbs, sig)
    _ => false
  }
}

///|
/// `k` re-read with the digest and scheme a signature names.
fn rsa_with(
  k : @rsa.PublicKey,
  digest : @rsa.Digest,
  scheme : @rsa.Scheme,
) -> @rsa.PublicKey raise @asn1.Refused {
  @rsa.PublicKey::new(k.modulus()[:], k.exponent()[:], digest~, scheme~) catch {
    _ => raise @asn1.Malformed("RSAPublicKey carries an unusable modulus")
  }
}
