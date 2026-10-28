// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// An OCSP response is a revocation list for one serial: the responder signs a CertificateStatus
// that names the issuer, the serial and an answer. What makes it about *this* certificate is the
// CertID — a hash of the issuer's name, a hash of the issuer's key and the serial — so a response
// is matched to a certificate rather than trusted to be about it.

///|
/// How the responder names itself (RFC 6960 §4.2.2.3): by its distinguished name, or by a hash of
/// its public key.
pub(all) enum Responder {
  ByName(@x509.Name)
  ByKey(Bytes)
} derive(Eq, Debug)

///|
/// One answer inside a response: which certificate it is about, what the answer is, and the window
/// it is good for.
pub(all) struct Single {
  hash : String
  issuer_name_hash : Bytes
  issuer_key_hash : Bytes
  serial : BigInt
  status : Status
  this_update : Int64
  next_update : Int64?
}

///|
/// The signed part of a response (RFC 6960 §4.2.1): who answered, when, and what it said.
pub(all) struct Basic {
  tbs : BytesView
  responder : Responder
  produced_at : Int64
  responses : Array[Single]
  alg : String
  params : Bytes?
  sig : @asn1.Bits
}

///|
/// A whole OCSPResponse (RFC 6960 §4.2.1): the transport-level status, and the signed answer when
/// that status is `successful`.
pub(all) struct Ocsp {
  raw : BytesView
  status : Int32
  basic : Basic?
}

///|
/// id-pkix-ocsp-basic, the only response type this package reads.
let oid_basic : String = "1.3.6.1.5.5.7.48.1.1"

///|
/// Parse a DER OCSPResponse.
///
/// A response whose status is not `successful` carries no answer and is read as such rather than
/// refused: `tryLater` and `unauthorized` are things a responder says, and a caller that treats
/// them as a parse failure cannot retry the one it should.
pub fn Ocsp::parse(der : BytesView) -> Ocsp raise @asn1.Refused {
  let top = @asn1.only(der)
  if top.tag != 0x30 {
    raise @asn1.Malformed("OCSPResponse is not a SEQUENCE")
  }
  let f = top.items()
  if f.length() == 0 || f.length() > 2 {
    raise @asn1.Malformed("OCSPResponse is not a status and a body")
  }
  if f[0].tag != 0x0a || f[0].value.length() != 1 {
    raise @asn1.Malformed("OCSPResponseStatus is not an ENUMERATED")
  }
  let status = f[0].value[0].to_int()
  if f.length() == 1 {
    return { raw: top.raw, status, basic: None, }
  }
  if status != 0 {
    raise @asn1.Malformed("a failed OCSPResponse carries a body")
  }
  if f[1].tag != 0xa0 {
    raise @asn1.Malformed("ResponseBytes is not [0]-tagged")
  }
  let bytes = @asn1.only(f[1].value).items()
  if bytes.length() != 2 || bytes[0].tag != 0x06 {
    raise @asn1.Malformed("ResponseBytes is not a type and a response")
  }
  if bytes[0].oid() != oid_basic {
    raise @asn1.Unsupported("OCSP response type " + bytes[0].oid())
  }
  { raw: top.raw, status, basic: Some(read_basic(bytes[1].octets())), }
}

///|
/// The BasicOCSPResponse inside the ResponseBytes.
fn read_basic(der : BytesView) -> Basic raise @asn1.Refused {
  let top = @asn1.only(der)
  if top.tag != 0x30 {
    raise @asn1.Malformed("BasicOCSPResponse is not a SEQUENCE")
  }
  let f = top.items()
  if f.length() < 3 {
    raise @asn1.Malformed("BasicOCSPResponse is short")
  }
  let data = f[0].items()
  let (alg, params) = @x509.algorithm(f[1].raw)
  let mut at = 0
  if data.length() > 0 && data[0].tag == 0xa0 {
    // `version [0] EXPLICIT` — v1 is the default and RFC 6960 defines no other.
    if @asn1.only(data[0].value).int() != 0 {
      raise @asn1.Unsupported("OCSP response version is not v1")
    }
    at = 1
  }
  if data.length() < at + 3 {
    raise @asn1.Malformed("ResponseData is short")
  }
  let responder = read_responder(data[at])
  let produced_at = data[at + 1].time()
  let responses : Array[Single] = []
  for s in data[at + 2].items() {
    responses.push(read_single(s))
  }
  {
    tbs: f[0].raw,
    responder,
    produced_at,
    responses,
    alg,
    params,
    sig: f[2].bits(),
  }
}

///|
fn read_responder(t : @asn1.Tlv) -> Responder raise @asn1.Refused {
  if t.tag == 0xa1 {
    return ByName(@x509.name(t.value))
  }
  if t.tag == 0x82 {
    return ByKey(t.value.to_owned())
  }
  raise @asn1.Malformed("ResponderID is neither a name nor a key hash")
}

///|
/// One SingleResponse (RFC 6960 §4.2.1): the CertID, the status, and the window.
fn read_single(t : @asn1.Tlv) -> Single raise @asn1.Refused {
  if t.tag != 0x30 {
    raise @asn1.Malformed("SingleResponse is not a SEQUENCE")
  }
  let f = t.items()
  if f.length() < 3 {
    raise @asn1.Malformed("SingleResponse is short")
  }
  let id = f[0].items()
  if id.length() != 4 {
    raise @asn1.Malformed("CertID is not a hash, two hashes and a serial")
  }
  let hash = match id[0].items() {
    [oid, ..] => oid.oid()
    _ => raise @asn1.Malformed("CertID hash algorithm is empty")
  }
  let status = read_cert_status(f[1])
  let this_update = f[2].time()
  let mut next_update : Int64? = None
  for extra in f[3:] {
    if extra.tag == 0xa0 {
      next_update = Some(@asn1.only(extra.value).time())
    }
  }
  {
    hash,
    issuer_name_hash: id[1].octets().to_owned(),
    issuer_key_hash: id[2].octets().to_owned(),
    serial: id[3].int(),
    status,
    this_update,
    next_update,
  }
}

///|
/// The CertStatus CHOICE: `good [0]`, `revoked [1]` with a time and a reason, or `unknown [2]`.
fn read_cert_status(t : @asn1.Tlv) -> Status raise @asn1.Refused {
  match t.tag {
    0x80 => Status::Good
    0xa1 => {
      let info = t.items()
      if info.length() < 1 {
        raise @asn1.Malformed("RevokedInfo is empty")
      }
      let at = info[0].time()
      let mut reason : Int32? = None
      for extra in info[1:] {
        if extra.tag == 0xa0 {
          let r = @asn1.only(extra.value)
          if r.tag != 0x0a || r.value.length() != 1 {
            raise @asn1.Malformed("revocationReason is not an ENUMERATED")
          }
          reason = Some(r.value[0].to_int())
        }
      }
      Status::Revoked({ at, reason, })
    }
    0x82 => Status::Unknown
    _ => raise @asn1.Malformed("CertStatus is none of good, revoked or unknown")
  }
}

///|
/// Whether the response was signed by `issuer`. A responder may sign with a key of its own — the
/// `certs` field exists for that — in which case the caller passes the responder's key instead.
pub fn Basic::signed_by(
  self : Basic,
  issuer : @x509.Spki,
) -> Bool raise @asn1.Refused {
  @x509.signature_ok(
    self.tbs,
    alg=self.alg,
    params=self.params,
    sig=self.sig,
    key=issuer,
  )
}

///|
/// Whether every answer in the response is current at `now`.
pub fn Basic::fresh(self : Basic, now : Int64) -> Bool {
  for s in self.responses {
    if now < s.this_update {
      return false
    }
    if s.next_update is Some(until) && now > until {
      return false
    }
  }
  true
}

///|
/// What the response says about this certificate, given the issuer that signed it.
///
/// The CertID is what makes the answer about this certificate: the hash of the issuer's name, the
/// hash of its public key and the serial all have to match, so a response about another
/// certificate under another CA is `Unknown` rather than an answer that was taken on faith.
pub fn Ocsp::status(
  self : Ocsp,
  cert : @x509.Cert,
  issuer : @x509.Cert,
) -> Status raise @asn1.Refused {
  guard self.basic is Some(basic) else { return Unknown }
  let key = issuer.spki.key.bytes
  let name_hash = issuer.subject.raw
  for s in basic.responses {
    if s.serial != cert.serial {
      continue
    }
    if !digest_matches(s.hash, name_hash, s.issuer_name_hash) {
      continue
    }
    if !digest_matches(s.hash, key, s.issuer_key_hash) {
      continue
    }
    return s.status
  }
  Unknown
}

///|
/// Whether `data` hashes to `want` under the algorithm the CertID names.
fn digest_matches(
  hash : String,
  data : Bytes,
  want : Bytes,
) -> Bool raise @asn1.Refused {
  let got = match hash {
    "1.3.14.3.2.26" => (@sha1.Hasher::new() : &@spec.Hash)
    "2.16.840.1.101.3.4.2.1" => (@sha2.Hasher::new(kind=Sha256) : &@spec.Hash)
    "2.16.840.1.101.3.4.2.2" => (@sha2.Hasher::new(kind=Sha384) : &@spec.Hash)
    "2.16.840.1.101.3.4.2.3" => (@sha2.Hasher::new(kind=Sha512) : &@spec.Hash)
    _ => raise @asn1.Unsupported("CertID hash " + hash)
  }
  got.write(data)
  got.finish() == want
}

///|
pub extend Responder with Eq::{not_equal, equal}

///|
pub extend Responder with Debug::{to_repr}

///|
pub extend Status with Eq::{not_equal, equal}

///|
pub extend Status with Debug::{to_repr}

///|
pub extend Revoked with Eq::{not_equal, equal}

///|
pub extend Revoked with Debug::{to_repr}
