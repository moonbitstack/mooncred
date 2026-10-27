// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Writing: the certificate a TLS server presents when it has nothing better — a P-256 key, an
// ecdsa-with-SHA256 signature over its own TBSCertificate, a commonName.

///|
/// The ecdsa-with-SHA256 AlgorithmIdentifier (RFC 5758): a SEQUENCE of just the OID, ECDSA
/// taking no parameters.
pub fn alg_ecdsa_sha256() -> Bytes {
  @asn1.sequence([@asn1.oid([1, 2, 840, 10045, 4, 3, 2])])
}

///|
/// The id-ecPublicKey with the prime256v1 (P-256) curve AlgorithmIdentifier (RFC 5480).
pub fn alg_ec_key() -> Bytes {
  @asn1.sequence([
    @asn1.oid([1, 2, 840, 10045, 2, 1]),
    @asn1.oid([1, 2, 840, 10045, 3, 1, 7]),
  ])
}

///|
/// A Name with a single commonName attribute: RDNSequence → RelativeDistinguishedName (SET) →
/// AttributeTypeAndValue (SEQUENCE of the commonName OID 2.5.4.3 and the UTF8String value).
pub fn common_name(cn : String) -> Bytes {
  @asn1.sequence([
    @asn1.set_of([
      @asn1.sequence([@asn1.oid([2, 5, 4, 3]), @asn1.utf8_string(cn)]),
    ]),
  ])
}

///|
/// A Validity: notBefore and notAfter as UTCTime `YYMMDDHHMMSSZ`.
pub fn validity_of(not_before : String, not_after : String) -> Bytes {
  @asn1.sequence([@asn1.utc_time(not_before), @asn1.utc_time(not_after)])
}

///|
/// A SubjectPublicKeyInfo for a P-256 key: the ecPublicKey/prime256v1 algorithm and the
/// uncompressed point as a BIT STRING.
pub fn spki_of(pub_key : @ecdsa.PublicKey) -> Bytes {
  @asn1.sequence([alg_ec_key(), @asn1.bit_string(pub_key.bytes())])
}

///|
/// The TBSCertificate (RFC 5280 §4.1.2): version v3 `[0] EXPLICIT INTEGER 2`, the serial number,
/// the signature algorithm, the issuer, the validity, the subject, and the SubjectPublicKeyInfo.
/// Self-signed, so issuer and subject are the same commonName. Extensions are omitted (a valid,
/// minimal profile).
pub fn tbs_of(
  serial : Bytes,
  cn : String,
  not_before : String,
  not_after : String,
  pub_key : @ecdsa.PublicKey,
) -> Bytes {
  @asn1.sequence([
    @asn1.explicit(0, @asn1.integer(b"\x02")),
    @asn1.integer(serial),
    alg_ecdsa_sha256(),
    common_name(cn),
    validity_of(not_before, not_after),
    common_name(cn),
    spki_of(pub_key),
  ])
}

///|
/// A self-signed X.509 certificate: build the TBSCertificate for `key`'s public key, sign its
/// DER with ES256, DER-encode the `r`/`s` signature (RFC 5280 requires the ECDSA-Sig-Value
/// SEQUENCE, not the raw concatenation), and wrap TBS + algorithm + signature in the outer
/// Certificate SEQUENCE.
pub fn self_signed(
  key : @ecdsa.PrivateKey,
  serial : Bytes,
  cn : String,
  not_before : String,
  not_after : String,
) -> Bytes {
  let pub_key = key.public()
  let tbs = tbs_of(serial, cn, not_before, not_after, pub_key)
  let raw = key.sign(tbs[:])
  let sig = @asn1.sequence([
    @asn1.integer(raw[0:32].to_owned()),
    @asn1.integer(raw[32:64].to_owned()),
  ])
  @asn1.sequence([tbs, alg_ecdsa_sha256(), @asn1.bit_string(sig)])
}
