// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A minimal X.509 v3 certificate (RFC 5280) for a P-256 / ECDSA-with-SHA256 server, built on
// the ASN.1 DER primitives. A TLS 1.3 server sends this in its Certificate message so a client
// can bind the handshake to a public key; mooncat signs it with the same ES256 primitive the
// CertificateVerify uses. This produces a real, self-signed DER certificate — the identity curl
// parses — replacing the opaque placeholder the handshake carried.

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

// The other direction: a certificate the peer chose, read into something the TLS side can act
// on. RFC 5280 §4 layers rules on top of X.690 that a generator never has to think about — a
// DEFAULT that must be left out, an extension that must not repeat, an inner signature algorithm
// that must equal the outer one, a critical extension that must not be skipped — and each of
// them exists because a certificate with two readings has two identities. They are enforced
// here, so a caller holding a `Cert` is holding one certificate rather than a choice of them.

///|
/// commonName (X.520 §6.2.2), the attribute a name is usually read from.
pub let oid_cn : String = "2.5.4.3"

///|
/// id-kp-serverAuth: the purpose a TLS server certificate needs (RFC 5280 §4.2.1.12).
pub let eku_server_auth : String = "1.3.6.1.5.5.7.3.1"

///|
/// id-kp-clientAuth.
pub let eku_client_auth : String = "1.3.6.1.5.5.7.3.2"

///|
let oid_ec_key : String = "1.2.840.10045.2.1"

///|
let oid_p256 : String = "1.2.840.10045.3.1.7"

///|
let oid_ecdsa_sha256 : String = "1.2.840.10045.4.3.2"

///|
/// One AttributeTypeAndValue: the attribute's OID in dotted-decimal form, and its value as text.
pub(all) struct Attr {
  oid : String
  value : String
} derive(Eq, Debug)

///|
/// A distinguished name as it is encoded — a sequence of relative distinguished names, each a set
/// of attributes. Nearly every certificate puts one attribute in each RDN, but name comparison is
/// defined over the nesting, so the nesting is what is kept.
pub(all) struct Name {
  rdns : Array[Array[Attr]]
} derive(Eq, Debug)

///|
/// The value of the first attribute with this OID, in encoding order.
pub fn Name::get(self : Name, oid : String) -> String? {
  for rdn in self.rdns {
    for a in rdn {
      if a.oid == oid {
        return Some(a.value)
      }
    }
  }
  None
}

///|
/// The name's commonName, if it has one.
pub fn Name::cn(self : Name) -> String? {
  self.get(oid_cn)
}

///|
/// A subjectAltName entry (RFC 5280 §4.2.1.6). The forms that name a TLS peer are decoded; the
/// rest keep their field number and contents, so a caller can see what was there instead of
/// being told the extension was empty.
pub(all) enum GeneralName {
  Dns(String)
  Email(String)
  Uri(String)
  Ip(Bytes)
  Named(Int, Bytes)
} derive(Eq, Debug)

///|
/// A validity window, in seconds since the Unix epoch.
pub(all) struct Validity {
  not_before : Int64
  not_after : Int64
} derive(Eq, Debug)

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
/// The extensions a peer's certificate is judged on (RFC 5280 §4.2). `key_usage` bits are
/// numbered from the top of the first octet — 0 digitalSignature, 5 keyCertSign. `eku` is `None`
/// when the extension is absent, which means any purpose, as against a listed set that does not
/// include the one being asked for. `unknown_critical` names the critical extensions this parser
/// does not understand: §4.2 makes such a certificate unusable, and a caller can only obey that
/// rule if it is told rather than left to assume the skip was safe.
pub(all) struct Exts {
  san : Array[GeneralName]
  ca : Bool
  path_len : Int?
  key_usage : @asn1.Bits?
  eku : Array[String]?
  unknown_critical : Array[String]
} derive(Eq, Debug)

///|
/// A parsed certificate. `tbs` is the exact encoding the signature covers and `raw` the whole
/// certificate, both as views into the input: a signature is checked over the bytes that arrived,
/// never over a re-encoding of what they were understood to mean.
pub(all) struct Cert {
  raw : BytesView
  tbs : BytesView
  version : Int
  serial : BigInt
  alg : String
  issuer : Name
  validity : Validity
  subject : Name
  spki : Spki
  exts : Exts
  sig : @asn1.Bits
}

///|
/// An AlgorithmIdentifier (RFC 5280 §4.1.1.2) as its OID and its parameters, the latter kept only
/// when they are an OID.
fn read_alg(tlv : @asn1.Tlv) -> (String, String?) raise @asn1.Refused {
  if tlv.tag != 0x30 {
    raise @asn1.Malformed("AlgorithmIdentifier is not a SEQUENCE")
  }
  let items = tlv.items()
  if items.length() == 0 || items.length() > 2 {
    raise @asn1.Malformed(
      "AlgorithmIdentifier is not an OID and its parameters",
    )
  }
  let oid = items[0].oid()
  let params = if items.length() == 2 && items[1].tag == 0x06 {
    Some(items[1].oid())
  } else {
    None
  }
  (oid, params)
}

///|
/// An RDNSequence (RFC 5280 §4.1.2.4).
fn read_name(tlv : @asn1.Tlv) -> Name raise @asn1.Refused {
  if tlv.tag != 0x30 {
    raise @asn1.Malformed("Name is not a SEQUENCE")
  }
  let rdns : Array[Array[Attr]] = []
  for rdn in tlv.items() {
    if rdn.tag != 0x31 {
      raise @asn1.Malformed("RelativeDistinguishedName is not a SET")
    }
    let attrs : Array[Attr] = []
    for a in rdn.items() {
      if a.tag != 0x30 {
        raise @asn1.Malformed("AttributeTypeAndValue is not a SEQUENCE")
      }
      let parts = a.items()
      if parts.length() != 2 {
        raise @asn1.Malformed("AttributeTypeAndValue is not a type and a value")
      }
      attrs.push({ oid: parts[0].oid(), value: parts[1].text(), })
    }
    if attrs.length() == 0 {
      raise @asn1.Malformed("empty RelativeDistinguishedName")
    }
    rdns.push(attrs)
  }
  { rdns, }
}

///|
/// A Validity (RFC 5280 §4.1.2.5).
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
  { alg, params, key: items[1].bits(), }
}

///|
/// A GeneralNames (RFC 5280 §4.2.1.6). The entries are IMPLICIT-tagged, so the field number is
/// the only thing that says what the octets are; there is no string tag left to read.
fn x509_san(v : BytesView) -> Array[GeneralName] raise @asn1.Refused {
  let seq = @asn1.only(v)
  if seq.tag != 0x30 {
    raise @asn1.Malformed("subjectAltName is not a SEQUENCE")
  }
  let out : Array[GeneralName] = []
  for g in seq.items() {
    if (g.tag & 0xc0) != 0x80 {
      raise @asn1.Malformed("subjectAltName entry is not context-tagged")
    }
    match g.tag & 0x1f {
      1 => out.push(Email(@asn1.ascii(g.value)))
      2 => out.push(Dns(@asn1.ascii(g.value)))
      6 => out.push(Uri(@asn1.ascii(g.value)))
      7 => {
        if g.value.length() != 4 && g.value.length() != 16 {
          raise @asn1.Malformed("iPAddress is neither four nor sixteen octets")
        }
        out.push(Ip(g.value.to_owned()))
      }
      n => out.push(Named(n, g.value.to_owned()))
    }
  }
  if out.length() == 0 {
    raise @asn1.Malformed("empty subjectAltName")
  }
  out
}

///|
/// A BasicConstraints (RFC 5280 §4.2.1.9) as `(cA, pathLenConstraint)`.
fn x509_basic(v : BytesView) -> (Bool, Int?) raise @asn1.Refused {
  let seq = @asn1.only(v)
  if seq.tag != 0x30 {
    raise @asn1.Malformed("basicConstraints is not a SEQUENCE")
  }
  let items = seq.items()
  let mut i = 0
  let mut ca = false
  if i < items.length() && items[i].tag == 0x01 {
    ca = items[i].bool()
    if !ca {
      raise @asn1.Malformed("basicConstraints spells out the default cA")
    }
    i = i + 1
  }
  let mut path : Int? = None
  if i < items.length() && items[i].tag == 0x02 {
    if !ca {
      raise @asn1.Malformed("pathLenConstraint without cA")
    }
    let n = items[i].int()
    if n < (0 : BigInt) {
      raise @asn1.Malformed("negative pathLenConstraint")
    }
    if n > (255 : BigInt) {
      raise @asn1.Unsupported("pathLenConstraint over 255")
    }
    path = Some(n.to_int())
    i = i + 1
  }
  if i != items.length() {
    raise @asn1.Malformed("unexpected field in basicConstraints")
  }
  (ca, path)
}

///|
/// An ExtKeyUsageSyntax (RFC 5280 §4.2.1.12): the key purposes, of which there is at least one.
fn x509_eku(v : BytesView) -> Array[String] raise @asn1.Refused {
  let seq = @asn1.only(v)
  if seq.tag != 0x30 {
    raise @asn1.Malformed("extKeyUsage is not a SEQUENCE")
  }
  let out : Array[String] = []
  for o in seq.items() {
    out.push(o.oid())
  }
  if out.length() == 0 {
    raise @asn1.Malformed("empty extKeyUsage")
  }
  out
}

///|
/// The `[3] EXPLICIT Extensions` of a v3 certificate (RFC 5280 §4.1.2.9).
fn x509_exts(t : @asn1.Tlv) -> Exts raise @asn1.Refused {
  let seq = @asn1.only(t.value)
  if seq.tag != 0x30 {
    raise @asn1.Malformed("extensions are not a SEQUENCE")
  }
  let items = seq.items()
  if items.length() == 0 {
    raise @asn1.Malformed("empty extensions")
  }
  let seen : Array[String] = []
  let mut san : Array[GeneralName] = []
  let mut ca = false
  let mut path_len : Int? = None
  let mut key_usage : @asn1.Bits? = None
  let mut eku : Array[String]? = None
  let unknown_critical : Array[String] = []
  for e in items {
    if e.tag != 0x30 {
      raise @asn1.Malformed("extension is not a SEQUENCE")
    }
    let parts = e.items()
    if parts.length() < 2 || parts.length() > 3 {
      raise @asn1.Malformed("extension is not an id, a criticality and a value")
    }
    let oid = parts[0].oid()
    if seen.contains(oid) {
      raise @asn1.Malformed("extension " + oid + " appears twice")
    }
    seen.push(oid)
    let critical = if parts.length() == 3 {
      if !parts[1].bool() {
        raise @asn1.Malformed("extension spells out the default criticality")
      }
      true
    } else {
      false
    }
    let v = parts[parts.length() - 1].octets()
    match oid {
      "2.5.29.17" => san = x509_san(v)
      "2.5.29.19" => {
        let (c, p) = x509_basic(v)
        ca = c
        path_len = p
      }
      "2.5.29.15" => key_usage = Some(@asn1.only(v).bits())
      "2.5.29.37" => eku = Some(x509_eku(v))
      _ => if critical { unknown_critical.push(oid) }
    }
  }
  { san, ca, path_len, key_usage, eku, unknown_critical, }
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
  let (alg, _) = read_alg(f[i + 1])
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
  let mut exts : Exts = {
    san: [],
    ca: false,
    path_len: None,
    key_usage: None,
    eku: None,
    unknown_critical: [],
  }
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
      exts = x509_exts(t)
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
    issuer,
    validity,
    subject,
    spki,
    exts,
    sig: top[2].bits(),
  }
}

///|
/// The P-256 public key a SubjectPublicKeyInfo carries. Refuses any algorithm but id-ecPublicKey
/// on prime256v1, refuses the compressed and hybrid point forms, and refuses a point that is not
/// on the curve.
pub fn Spki::p256(self : Spki) -> @ecdsa.PublicKey raise @asn1.Refused {
  if self.alg != oid_ec_key {
    raise @asn1.Unsupported("public key algorithm " + self.alg)
  }
  if self.params != Some(oid_p256) {
    raise @asn1.Unsupported("elliptic curve other than prime256v1")
  }
  if self.key.unused != 0 {
    raise @asn1.Malformed("public key BIT STRING has unused bits")
  }
  let pt = self.key.bytes
  if pt.length() != 65 || pt[0] != b'\x04' {
    raise @asn1.Malformed("public key is not an uncompressed P-256 point")
  }
  // Whether the point is on the curve is the curve's question, not the
  // certificate's; `mooncrypt` answers it and refuses one that is not.
  @ecdsa.PublicKey::new(pt[:], curve=P256) catch {
    _ => raise @asn1.Malformed("public key is not a point on P-256")
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
/// Whether the dNSName `pattern` names `host` (RFC 6125 §6.4.3): label by label, ASCII case
/// insensitive. A first label of exactly `*` stands for one whole label, so `*.a.example` covers
/// `b.a.example` and neither `a.example` nor `c.b.a.example`. A `*` anywhere else, or fused to
/// the rest of its label as in `b*.a.example`, matches nothing — a partial wildcard is a claim on
/// a name the issuer never checked.
pub fn dns_match(pattern : String, host : String) -> Bool {
  let p = pattern.split(".").to_array()
  let h = host.split(".").to_array()
  if p.length() != h.length() || p.length() == 0 {
    return false
  }
  // A lone `*` would otherwise name every single-label host. How much of the tail a wildcard may
  // cover past that is a question about public suffixes, which needs a list this package has no
  // business carrying; that rule belongs to the caller.
  if p[0] == "*" && p.length() < 2 {
    return false
  }
  for i in 0..<p.length() {
    if p[i].length() == 0 || h[i].length() == 0 {
      return false
    }
    if i == 0 && p[0] == "*" {
      continue
    }
    for c in p[i] {
      if c == '*' {
        return false
      }
    }
    if !p[i].equal_ignore_ascii_case(h[i]) {
      return false
    }
  }
  true
}

///|
/// Whether `host` is one of the certificate's subjectAltName dNSName identities. iPAddress
/// entries are not consulted — an address is not a hostname, and reading one as the other is how
/// a certificate for a name comes to be trusted for an address. A certificate with no
/// subjectAltName matches nothing: the commonName stopped being an identity with RFC 6125.
pub fn Cert::matches(self : Cert, host : String) -> Bool {
  for n in self.exts.san {
    match n {
      Dns(p) => if dns_match(p, host) { return true }
      _ => ()
    }
  }
  false
}

///|
/// Check the certificate's signature under `key` — its issuer's public key, or its own if it is
/// self-signed. Only ecdsa-with-SHA256 is checked; another algorithm raises `Unsupported` rather
/// than returning false, so a caller cannot read "not checked" as "checked and bad".
pub fn Cert::signed_by(
  self : Cert,
  key : @ecdsa.PublicKey,
) -> Bool raise @asn1.Refused {
  if self.alg != oid_ecdsa_sha256 {
    raise @asn1.Unsupported("signature algorithm " + self.alg)
  }
  if self.sig.unused != 0 {
    raise @asn1.Malformed("signature BIT STRING has unused bits")
  }
  let sig = @asn1.only(self.sig.bytes[:])
  if sig.tag != 0x30 {
    raise @asn1.Malformed("ECDSA-Sig-Value is not a SEQUENCE")
  }
  let rs = sig.items()
  if rs.length() != 2 {
    raise @asn1.Malformed("ECDSA-Sig-Value is not an r and an s")
  }
  // X.509 carries `r` and `s` as two INTEGERs; the verifier takes them as the
  // fixed-width pair, and checks their range against the curve order itself.
  let r = rs[0].int()
  let s = rs[1].int()
  let sig = Buffer()
  sig.write_bytes(r.to_octets(length=32))
  sig.write_bytes(s.to_octets(length=32))
  key.verify(self.tbs, sig.to_bytes()[:])
}

///|
pub extend Attr with Debug::{to_repr}

///|
pub extend Attr with Eq::{not_equal, equal}

///|
pub extend Exts with Debug::{to_repr}

///|
pub extend Exts with Eq::{not_equal, equal}

///|
pub extend GeneralName with Debug::{to_repr}

///|
pub extend GeneralName with Eq::{not_equal, equal}

///|
pub extend Name with Debug::{to_repr}

///|
pub extend Name with Eq::{not_equal, equal}

///|
pub extend Spki with Debug::{to_repr}

///|
pub extend Spki with Eq::{not_equal, equal}

///|
pub extend Validity with Debug::{to_repr}

///|
pub extend Validity with Eq::{not_equal, equal}
