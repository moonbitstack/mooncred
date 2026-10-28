// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A revocation list is a CA's standing statement about the certificates it has issued: the serials
// it has withdrawn, when each went, and why. It is signed and dated, so the two questions a reader
// has to answer are whether the issuer really made it and whether it is still current — and a
// reader that skips either is asking the list a question it cannot answer.

///|
/// What a revocation source says about a certificate.
pub(all) enum Status {
  /// Not withdrawn, as of the source's own timestamp.
  Good
  /// Withdrawn: when, and why under the reason codes of RFC 5280 §5.3.1.
  Revoked(Revoked)
  /// The source does not speak for this certificate — another issuer, another serial.
  Unknown
} derive(Eq, Debug)

///|
/// A withdrawal: the time it took effect and the reason the issuer gave.
pub(all) struct Revoked {
  at : Int64
  reason : Int32?
} derive(Eq, Debug)

///|
/// One line of a revocation list.
pub(all) struct Entry {
  serial : BigInt
  revoked : Revoked
}

///|
/// A parsed CertificateList (RFC 5280 §5.1). `tbs` is the exact TBSCertList the signature covers.
pub(all) struct Crl {
  raw : BytesView
  tbs : BytesView
  issuer : @x509.Name
  this_update : Int64
  next_update : Int64?
  entries : Array[Entry]
  alg : String
  params : Bytes?
  sig : @asn1.Bits
}

///|
/// cRLReason, the extension on a list entry that says why the certificate was withdrawn.
let oid_crl_reason : String = "2.5.29.21"

///|
/// Read a DER CertificateList.
///
/// The version is optional and the entry list is optional, so an empty list — a CA that has
/// withdrawn nothing — is a list with no entries rather than a malformed one. Anything that is not
/// exactly one well-formed list is `Malformed`.
pub fn Crl::parse(der : BytesView) -> Crl raise @asn1.Refused {
  let top = @asn1.only(der)
  if top.tag != 0x30 {
    raise @asn1.Malformed("CertificateList is not a SEQUENCE")
  }
  let outer = top.items()
  if outer.length() != 3 {
    raise @asn1.Malformed(
      "CertificateList is not a TBS list, an algorithm and a signature",
    )
  }
  let f = outer[0].items()
  // RFC 5280 §5.1.1.2: the inner signature algorithm is the one that is signed, so the outer copy
  // must say the same thing or a reader could be shown an algorithm nobody signed with.
  if f.length() < 2 || outer[1].raw != f[1].raw {
    raise @asn1.Malformed(
      "the signature algorithm differs from the one the list names",
    )
  }
  let mut i = 0
  if f.length() > 0 && f[0].tag == 0x02 {
    if f[0].int() != 1 {
      raise @asn1.Malformed("CRL version is neither v1 nor v2")
    }
    i = 1
  }
  if f.length() < i + 3 {
    raise @asn1.Malformed("TBSCertList is missing fields")
  }
  let (alg, params) = @x509.algorithm(f[i].raw)
  let issuer = @x509.name(f[i + 1].raw)
  let this_update = f[i + 2].time()
  let mut next_update : Int64? = None
  let mut at = i + 3
  if at < f.length() && (f[at].tag == 0x17 || f[at].tag == 0x18) {
    next_update = Some(f[at].time())
    at = at + 1
  }
  let entries : Array[Entry] = []
  if at < f.length() && f[at].tag == 0x30 {
    for e in f[at].items() {
      entries.push(read_entry(e))
    }
    at = at + 1
  }
  if at < f.length() && f[at].tag != 0xa0 {
    raise @asn1.Malformed("unexpected field in TBSCertList")
  }
  {
    raw: top.raw,
    tbs: outer[0].raw,
    issuer,
    this_update,
    next_update,
    entries,
    alg,
    params,
    sig: outer[2].bits(),
  }
}

///|
/// One `SEQUENCE { serial, date, extensions OPTIONAL }` of a list.
fn read_entry(t : @asn1.Tlv) -> Entry raise @asn1.Refused {
  if t.tag != 0x30 {
    raise @asn1.Malformed("revoked certificate entry is not a SEQUENCE")
  }
  let f = t.items()
  if f.length() < 2 {
    raise @asn1.Malformed("revoked certificate entry is short")
  }
  let mut reason : Int32? = None
  if f.length() > 2 {
    reason = read_reason(f[2])
  }
  { serial: f[0].int(), revoked: { at: f[1].time(), reason, }, }
}

///|
/// The cRLReason out of an entry's extensions: an ENUMERATED inside an OCTET STRING.
fn read_reason(t : @asn1.Tlv) -> Int32? raise @asn1.Refused {
  for e in t.items() {
    if e.tag != 0x30 {
      raise @asn1.Malformed("entry extension is not a SEQUENCE")
    }
    let parts = e.items()
    if parts.length() < 2 {
      raise @asn1.Malformed("entry extension is short")
    }
    if parts[0].oid() == oid_crl_reason {
      let inner = @asn1.only(parts[parts.length() - 1].octets())
      if inner.tag != 0x0a {
        raise @asn1.Malformed("cRLReason is not an ENUMERATED")
      }
      if inner.value.length() != 1 {
        raise @asn1.Malformed("cRLReason is not one octet")
      }
      return Some(inner.value[0].to_int())
    }
  }
  None
}

///|
/// Read the first revocation list in a PEM file, under the label `openssl ca -gencrl` writes.
pub fn Crl::pem(text : String) -> Crl raise @asn1.Refused {
  if @x509.pems(text, label="X509 CRL") is [der, ..] {
    return Crl::parse(der[:])
  }
  raise @asn1.Malformed("no revocation list in the PEM text")
}

///|
/// Whether the list was signed by `issuer` — the key of the CA whose certificates it speaks for.
/// Until this is true, nothing else the list says means anything.
pub fn Crl::signed_by(
  self : Crl,
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
/// Whether the list is current at `now`, in seconds since the Unix epoch: thisUpdate has passed
/// and nextUpdate has not. A list with no nextUpdate never expires by its own terms, which
/// RFC 5280 §5.1.2.5 allows and which a caller has to weigh for itself.
pub fn Crl::fresh(self : Crl, now : Int64) -> Bool {
  if now < self.this_update {
    return false
  }
  match self.next_update {
    Some(until) => now <= until
    None => true
  }
}

///|
/// What the list says about this certificate.
///
/// `Unknown` when the list belongs to another issuer: a list only speaks for the certificates its
/// issuer signed, and serials are the issuer's own numbering. Freshness and the signature are the
/// caller's to check — `signed_by` and `fresh` are why they can.
pub fn Crl::status(self : Crl, cert : @x509.Cert) -> Status {
  if cert.issuer.raw != self.issuer.raw {
    return Unknown
  }
  for e in self.entries {
    if e.serial == cert.serial {
      return Revoked(e.revoked)
    }
  }
  Good
}
