// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A certificate the peer chose, read into something the TLS side can act on. RFC 5280 §4 layers
// rules on top of X.690 that a generator never has to think about — a DEFAULT that must be left
// out, an extension that must not repeat, an inner signature algorithm that must equal the outer
// one, a critical extension that must not be skipped — and each of them exists because a
// certificate with two readings has two identities. They are enforced here, so a caller holding
// a `Cert` is holding one certificate rather than a choice of them.

///|
/// A validity window, in seconds since the Unix epoch.
pub(all) struct Validity {
  not_before : Int64
  not_after : Int64
} derive(Eq, Debug)

///|
/// A parsed certificate. `tbs` is the exact encoding the signature covers and `raw` the whole
/// certificate, both as views into the input: a signature is checked over the bytes that arrived,
/// never over a re-encoding of what they were understood to mean. `params` is the encoding of
/// the signature algorithm's parameters, which RSASSA-PSS needs.
pub(all) struct Cert {
  raw : BytesView
  tbs : BytesView
  version : Int32
  serial : BigInt
  alg : String
  params : Bytes?
  issuer : Name
  validity : Validity
  subject : Name
  spki : Spki
  exts : Exts
  sig : @asn1.Bits
}

///|
fn read_window(tlv : @asn1.Tlv) -> Validity raise @asn1.Refused {
  if tlv.tag != 0x30 {
    raise @asn1.Malformed("Validity is not a SEQUENCE")
  }
  let items = tlv.items()
  if items.length() != 2 {
    raise @asn1.Malformed("Validity is not a notBefore and a notAfter")
  }
  { not_before: items[0].time(), not_after: items[1].time(), }
}

///|
/// Parse a DER certificate (RFC 5280 §4.1). Raises on anything that is not exactly one
/// well-formed certificate: a truncated or over-long field, a payload glued to the end, a version
/// that does not admit the fields present, or an outer signature algorithm that disagrees with
/// the one the signature actually covers.
pub fn parse(der : BytesView) -> Cert raise @asn1.Refused {
  let cert = @asn1.only(der)
  if cert.tag != 0x30 {
    raise @asn1.Malformed("Certificate is not a SEQUENCE")
  }
  let top = cert.items()
  if top.length() != 3 {
    raise @asn1.Malformed(
      "Certificate is not a TBSCertificate, an algorithm and a signature",
    )
  }
  let tbs = top[0]
  if tbs.tag != 0x30 {
    raise @asn1.Malformed("TBSCertificate is not a SEQUENCE")
  }
  let f = tbs.items()
  let mut version = 1
  let mut i = 0
  if f.length() > 0 && f[0].tag == 0xa0 {
    let v = @asn1.only(f[0].value).int()
    if v < (0 : BigInt) || v > (2 : BigInt) {
      raise @asn1.Malformed("unknown certificate version")
    }
    version = v.to_int() + 1
    i = 1
  }
  if f.length() < i + 6 {
    raise @asn1.Malformed("TBSCertificate is missing fields")
  }
  let serial = f[i].int()
  let (alg, params) = read_alg(f[i + 1])
  // RFC 5280 §4.1.1.2: the two algorithm identifiers are the same field written twice, and only
  // the inner one is signed. A peer that can make them differ chooses the algorithm a verifier
  // reads without touching what the issuer signed.
  if top[1].raw != f[i + 1].raw {
    raise @asn1.Malformed(
      "the signature algorithm differs from the one the TBSCertificate names",
    )
  }
  let issuer = read_name(f[i + 2])
  let validity = read_window(f[i + 3])
  let subject = read_name(f[i + 4])
  let spki = read_spki(f[i + 5])
  let mut exts = no_exts
  let mut prev = 0
  for j = i + 6; j < f.length(); j = j + 1 {
    let t = f[j]
    if (t.tag & 0xc0) != 0x80 {
      raise @asn1.Malformed("unexpected field in TBSCertificate")
    }
    let n = t.tag & 0x1f
    if n < 1 || n > 3 || n <= prev {
      raise @asn1.Malformed("unexpected field in TBSCertificate")
    }
    prev = n
    if n == 3 {
      if t.tag != 0xa3 {
        raise @asn1.Malformed("extensions are not EXPLICIT-tagged")
      }
      if version != 3 {
        raise @asn1.Malformed("extensions in a certificate below v3")
      }
      exts = read_exts(t)
    } else if version == 1 {
      raise @asn1.Malformed("unique identifier in a v1 certificate")
    }
  }
  {
    raw: cert.raw,
    tbs: tbs.raw,
    version,
    serial,
    alg,
    params: params.map(p => p.to_owned()),
    issuer,
    validity,
    subject,
    spki,
    exts,
    sig: top[2].bits(),
  }
}

///|
/// Whether `now`, in seconds since the Unix epoch, falls inside the certificate's validity
/// window. Both ends are inclusive: RFC 5280 §4.1.2.5 gives them as the first and last instant
/// the certificate is valid, not as an open interval.
pub fn Cert::valid_at(self : Cert, now : Int64) -> Bool {
  now >= self.validity.not_before && now <= self.validity.not_after
}

///|
/// Whether `s` is a well-formed DNS identifier (RFC 1034 §3.5, RFC 5280 §4.2.1.6): at most 253
/// octets, labels of letters, digits, hyphens and underscores, none empty, none longer than 63,
/// none starting or ending with a hyphen, the last not all digits. `wildcard` admits a first
/// label of exactly `*`, followed by at least two more labels, as NSS and webpki require;
/// `constraint` admits a leading dot and the empty string. The rules are webpki's.
fn dns_id(s : String, wildcard~ : Bool, constraint~ : Bool) -> Bool {
  if s.length() > 253 {
    return false
  }
  if constraint && s.length() == 0 {
    return true
  }
  let body = match s.strip_prefix("*.") {
    Some(rest) if wildcard => rest.to_owned()
    _ =>
      match s.strip_prefix(".") {
        Some(rest) if constraint => rest.to_owned()
        _ => s
      }
  }
  let labels = body.split(".").to_array()
  if wildcard && s.has_prefix("*.") && labels.length() < 2 {
    return false
  }
  for i, label in labels {
    if label.length() == 0 || label.length() > 63 {
      return false
    }
    if label.has_prefix("-") || label.has_suffix("-") {
      return false
    }
    let mut digits = true
    for c in label {
      match c {
        '0'..<='9' => ()
        'a'..<='z' | 'A'..<='Z' | '_' | '-' => digits = false
        _ => return false
      }
    }
    if digits && i == labels.length() - 1 {
      return false
    }
  }
  true
}

///|
/// Whether the dNSName `pattern` names `host` (RFC 6125 §6.4.3): label by label, ASCII case
/// insensitive. A first label of exactly `*` stands for one whole label and needs two more after
/// it, so `*.a.example` covers `b.a.example` and neither `a.example` nor `c.b.a.example`, and
/// `*.com` covers nothing. A `*` anywhere else, or fused to the rest of its label as in
/// `b*.a.example`, matches nothing — a partial wildcard is a claim on a name the issuer never
/// checked. A pattern or host that is not a well-formed DNS name matches nothing.
pub fn dns_match(pattern : String, host : String) -> Bool {
  if !dns_id(pattern, wildcard=true, constraint=false) ||
    !dns_id(host, wildcard=false, constraint=false) {
    return false
  }
  let p = pattern.split(".").to_array()
  let h = host.split(".").to_array()
  if p.length() != h.length() {
    return false
  }
  for i in 0..<p.length() {
    if i == 0 && p[0] == "*" {
      continue
    }
    if !p[i].equal_ignore_ascii_case(h[i]) {
      return false
    }
  }
  true
}

///|
/// Whether `host` is one of the certificate's identities: a DNS name against the subjectAltName
/// dNSName entries, an IPv4 or IPv6 literal against the iPAddress entries. The two never cross —
/// reading an address as a name is how a certificate for a name comes to be trusted for an
/// address. A certificate with no subjectAltName matches nothing: the commonName stopped being an
/// identity with RFC 6125, and Go and webpki no longer fall back to it.
pub fn Cert::matches(self : Cert, host : String) -> Bool {
  match ip_literal(host) {
    Some(addr) => self.exts.san.iter().any(n => n is Ip(a) && a == addr)
    None => {
      let h = match host.strip_suffix(".") {
        Some(v) => v.to_owned()
        None => host
      }
      self.exts.san.iter().any(n => n is Dns(p) && dns_match(p, h))
    }
  }
}

///|
pub extend Validity with Debug::{to_repr}

///|
pub extend Validity with Eq::{not_equal, equal}
