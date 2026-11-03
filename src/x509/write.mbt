// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Writing: the certificate a TLS server presents when it has nothing better — a commonName, a
// serial, the two instants, and a signature by the key it belongs to. The signature algorithm
// follows the key, so the same call writes a P-256 or an ML-DSA certificate.

///|
/// A Name with a single commonName attribute: RDNSequence → RelativeDistinguishedName (SET) →
/// AttributeTypeAndValue (SEQUENCE of the commonName OID 2.5.4.3 and the UTF8String value).
///
/// This is the subject a certificate request asks for and the one a self-signed certificate
/// carries; anything else — a country, an organization, several attributes per set — is the
/// caller's DER to build.
pub fn common_name(cn : String) -> Bytes {
  @asn1.sequence([
    @asn1.set_of([
      @asn1.sequence([@asn1.oid([2, 5, 4, 3]), @asn1.utf8_string(cn)]),
    ]),
  ])
}

///|
/// An AlgorithmIdentifier that takes no parameters: a SEQUENCE of just the OID, which is the shape
/// every ECDSA, Ed25519 and ML-DSA identifier has (RFC 5758 §3.2, RFC 8410 §3, RFC 9881 §2).
fn alg_der(arcs : Array[Int32]) -> Bytes {
  @asn1.sequence([@asn1.oid(arcs)])
}

///|
/// The signature algorithm the key signs with. ECDSA pairs its digest to the curve the way the
/// signer does — SHA-256 on P-256 and secp256k1, SHA-384 on P-384, SHA-512 on P-521 and the
/// brainpool curves of that size — RSA takes PKCS#1 v1.5 with SHA-256, and the ML-DSA identifiers
/// name the parameter set (RFC 9881 §3).
pub fn signature_algorithm(key : PrivateKey) -> Bytes {
  match key {
    Rsa(_) =>
      @asn1.sequence([@asn1.oid([1, 2, 840, 113549, 1, 1, 11]), @asn1.null()])
    Ec(k) =>
      alg_der(
        match k.curve() {
          P256 | Secp256k1 | BrainpoolP256r1 => [1, 2, 840, 10045, 4, 3, 2]
          P384 | BrainpoolP384r1 => [1, 2, 840, 10045, 4, 3, 3]
          P521 | BrainpoolP512r1 => [1, 2, 840, 10045, 4, 3, 4]
        },
      )
    Ed25519(_) => alg_der([1, 3, 101, 112])
    MlDsa(k) => alg_der(ml_dsa_arcs(k.kind()))
  }
}

///|
/// The signature value over `tbs`: the octets the key produced, except for ECDSA, whose raw
/// `r || s` is wrapped in the ECDSA-Sig-Value SEQUENCE RFC 5280 §4.1.1.3 asks for.
pub fn signature_value(
  key : PrivateKey,
  tbs : Bytes,
) -> Bytes raise @asn1.Refused {
  match key {
    Rsa(k) => k.sign(tbs)
    Ec(k) => {
      let raw = k.sign(tbs)
      let size = k.curve().size()
      if raw.length() != 2 * size {
        raise @asn1.Malformed("ECDSA signature is not an r and an s")
      }
      @asn1.sequence([
        @asn1.integer(raw[0:size].to_owned()),
        @asn1.integer(raw[size:2 * size].to_owned()),
      ])
    }
    Ed25519(k) => k.sign(tbs)
    MlDsa(k) => k.sign(tbs)
  }
}

///|
/// An instant as a Validity field holds it (RFC 5280 §4.1.2.5): UTCTime with the year given in two
/// digits through 2049, GeneralizedTime from 2050 on, both in UTC to the second. The cut is the
/// profile's, and a writer that ignores it makes 2060 read as 1960.
fn asn1_time(seconds : Int64) -> Bytes raise @asn1.Refused {
  let days = floor_div(seconds, 86400L)
  let rest = seconds - days * 86400L
  let date = @moondate.Date::of_days(days.to_int())
  let hour = (rest / 3600L).to_int()
  let minute = (rest % 3600L / 60L).to_int()
  let second = (rest % 60L).to_int()
  let tail = two(hour) + two(minute) + two(second) + "Z"
  if date.year >= 1950 && date.year <= 2049 {
    @asn1.utc_time(
      two(date.year % 100) + two(date.month) + two(date.day) + tail,
    )
  } else {
    @asn1.tlv(
      0x18,
      ascii_of(four(date.year) + two(date.month) + two(date.day) + tail),
    )
  }
}

///|
/// Division that rounds towards minus infinity, so an instant before 1970 lands on the day it is
/// in rather than on the one after it.
fn floor_div(a : Int64, b : Int64) -> Int64 {
  let q = a / b
  if a % b != 0L && (a < 0L) != (b < 0L) {
    q - 1L
  } else {
    q
  }
}

///|
/// A decimal number in two digits, zero-padded.
fn two(n : Int32) -> String {
  if n < 10 {
    "0" + n.to_string()
  } else {
    n.to_string()
  }
}

///|
/// A decimal number in four digits, zero-padded.
fn four(n : Int32) -> String {
  let digits = n.to_string()
  let out = StringBuilder()
  for _ in digits.length()..<4 {
    out.write_string("0")
  }
  out.write_string(digits)
  out.to_string()
}

///|
/// A Validity: notBefore and notAfter, each at the form its year asks for.
fn validity_of(
  not_before : Int64,
  not_after : Int64,
) -> Bytes raise @asn1.Refused {
  @asn1.sequence([asn1_time(not_before), asn1_time(not_after)])
}

///|
/// A self-signed X.509 v3 certificate: `key`'s public half in the SubjectPublicKeyInfo, the same
/// `cn` as subject and issuer, the serial number, the two instants in seconds since the Unix
/// epoch, and, when `exts` is given, the extensions the certificate claims.
///
/// The signature is made by `key` over the DER of the TBSCertificate, under the algorithm
/// `signature_algorithm` names for its kind, so one call writes the P-256 certificate a test
/// server needs and the ML-DSA-65 one a post-quantum deployment does.
///
/// A certificate without `exts` names no host: subjectAltName is what a client compares, and a
/// certificate that carries none is an identity for nothing (RFC 6125). A server's certificate
/// wants at least `Exts::empty()` with a `san` and a `key_usage` filled in.
pub fn self_signed(
  key~ : PrivateKey,
  cn~ : String,
  serial~ : Bytes,
  not_before~ : Int64,
  not_after~ : Int64,
  exts? : Exts,
) -> Bytes raise @asn1.Refused {
  let alg = signature_algorithm(key)
  let fields : Array[Bytes] = [
    // version v3, `[0] EXPLICIT INTEGER 2`
    @asn1.explicit(0, @asn1.integer(b"\x02")),
    @asn1.integer(serial),
    alg,
    common_name(cn),
    validity_of(not_before, not_after),
    common_name(cn),
    Spki::encode(key.public()),
  ]
  match exts {
    Some(e) => fields.push(@asn1.explicit(3, e.encode()))
    None => ()
  }
  let tbs = @asn1.sequence(fields)
  @asn1.sequence([tbs, alg, @asn1.bit_string(signature_value(key, tbs))])
}
