// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// id-kp-serverAuth: the purpose a TLS server certificate needs (RFC 5280 §4.2.1.12).
pub let eku_server_auth : String = "1.3.6.1.5.5.7.3.1"

///|
/// id-kp-clientAuth.
pub let eku_client_auth : String = "1.3.6.1.5.5.7.3.2"

///|
/// anyExtendedKeyUsage (RFC 5280 §4.2.1.12).
pub let eku_any : String = "2.5.29.37.0"

///|
/// A GeneralName (RFC 5280 §4.2.1.6). The forms that name a peer are decoded; the rest keep
/// their field number and contents, so a caller can see what was there instead of being told the
/// extension was empty. In a name constraint an `Ip` is an address followed by its mask, eight or
/// thirty-two octets; in a subjectAltName it is the bare address.
pub(all) enum GeneralName {
  Dns(String)
  Email(String)
  Uri(String)
  Ip(Bytes)
  Dir(Name)
  Named(Int32, Bytes)
} derive(Eq, Debug)

///|
/// A NameConstraints (RFC 5280 §4.2.1.10): the subtrees every name below the CA must fall in,
/// and the ones none may.
pub(all) struct Constraints {
  permitted : Array[GeneralName]
  excluded : Array[GeneralName]
} derive(Eq, Debug)

///|
/// The extensions a certificate is judged on (RFC 5280 §4.2). `key_usage` bits are numbered from
/// the top of the first octet — 0 digitalSignature, 5 keyCertSign. `eku` is `None` when the
/// extension is absent, which means any purpose, as against a listed set that does not include
/// the one being asked for. `ski` and `aki` are the key identifiers path building uses to try the
/// likeliest issuer first. `unknown_critical` names the critical extensions this parser does not
/// understand: §4.2 makes such a certificate unusable, and a caller can only obey that rule if it
/// is told rather than left to assume the skip was safe.
pub(all) struct Exts {
  san : Array[GeneralName]
  ca : Bool
  path_len : Int32?
  key_usage : @asn1.Bits?
  eku : Array[String]?
  ski : Bytes?
  aki : Bytes?
  constraints : Constraints?
  unknown_critical : Array[String]
} derive(Eq, Debug)

///|
let no_exts : Exts = {
  san: [],
  ca: false,
  path_len: None,
  key_usage: None,
  eku: None,
  ski: None,
  aki: None,
  constraints: None,
  unknown_critical: [],
}

///|
fn read_general(
  g : @asn1.Tlv,
  constraint~ : Bool,
) -> GeneralName raise @asn1.Refused {
  if (g.tag & 0xc0) != 0x80 {
    raise @asn1.Malformed("GeneralName is not context-tagged")
  }
  match g.tag & 0x1f {
    1 => Email(@asn1.ascii(g.value))
    2 => Dns(@asn1.ascii(g.value))
    4 => {
      if g.tag != 0xa4 {
        raise @asn1.Malformed("directoryName is not EXPLICIT-tagged")
      }
      Dir(read_name(@asn1.only(g.value)))
    }
    6 => Uri(@asn1.ascii(g.value))
    7 => {
      let ok = if constraint {
        g.value.length() == 8 || g.value.length() == 32
      } else {
        g.value.length() == 4 || g.value.length() == 16
      }
      if !ok {
        raise @asn1.Malformed("iPAddress has the wrong length")
      }
      Ip(g.value.to_owned())
    }
    n => Named(n, g.value.to_owned())
  }
}

///|
/// A GeneralNames (RFC 5280 §4.2.1.6). The entries are IMPLICIT-tagged, so the field number is
/// the only thing that says what the octets are; there is no string tag left to read.
fn read_san(v : BytesView) -> Array[GeneralName] raise @asn1.Refused {
  let seq = @asn1.only(v)
  if seq.tag != 0x30 {
    raise @asn1.Malformed("subjectAltName is not a SEQUENCE")
  }
  let out = seq.items().map(g => read_general(g, constraint=false))
  if out.length() == 0 {
    raise @asn1.Malformed("empty subjectAltName")
  }
  out
}

///|
fn read_basic(v : BytesView) -> (Bool, Int32?) raise @asn1.Refused {
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
  let mut path : Int32? = None
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
fn read_eku(v : BytesView) -> Array[String] raise @asn1.Refused {
  let seq = @asn1.only(v)
  if seq.tag != 0x30 {
    raise @asn1.Malformed("extKeyUsage is not a SEQUENCE")
  }
  let out = seq.items().map(o => o.oid())
  if out.length() == 0 {
    raise @asn1.Malformed("empty extKeyUsage")
  }
  out
}

///|
/// An AuthorityKeyIdentifier's keyIdentifier (RFC 5280 §4.2.1.1), when it has one; the issuer
/// name and serial form is read past.
fn read_aki(v : BytesView) -> Bytes? raise @asn1.Refused {
  let seq = @asn1.only(v)
  if seq.tag != 0x30 {
    raise @asn1.Malformed("authorityKeyIdentifier is not a SEQUENCE")
  }
  for f in seq.items() {
    if f.tag == 0x80 {
      return Some(f.value.to_owned())
    }
  }
  None
}

///|
/// A GeneralSubtrees (RFC 5280 §4.2.1.10). `minimum` and `maximum` are fixed by the profile — the
/// first must be left at zero and the second out — so a subtree that sets either is refused
/// rather than read with a meaning nobody implements.
fn read_subtrees(t : @asn1.Tlv) -> Array[GeneralName] raise @asn1.Refused {
  let out : Array[GeneralName] = []
  for s in t.items() {
    if s.tag != 0x30 {
      raise @asn1.Malformed("GeneralSubtree is not a SEQUENCE")
    }
    let parts = s.items()
    if parts.length() != 1 {
      raise @asn1.Malformed("GeneralSubtree sets minimum or maximum")
    }
    out.push(read_general(parts[0], constraint=true))
  }
  if out.length() == 0 {
    raise @asn1.Malformed("empty GeneralSubtrees")
  }
  out
}

///|
fn read_constraints(v : BytesView) -> Constraints raise @asn1.Refused {
  let seq = @asn1.only(v)
  if seq.tag != 0x30 {
    raise @asn1.Malformed("nameConstraints is not a SEQUENCE")
  }
  let mut permitted = []
  let mut excluded = []
  let items = seq.items()
  if items.length() == 0 {
    raise @asn1.Malformed("empty nameConstraints")
  }
  let mut prev = -1
  for f in items {
    let n = f.tag & 0x1f
    if (f.tag & 0xe0) != 0xa0 || n > 1 || n <= prev {
      raise @asn1.Malformed("unexpected field in nameConstraints")
    }
    prev = n
    if n == 0 {
      permitted = read_subtrees(f)
    } else {
      excluded = read_subtrees(f)
    }
  }
  { permitted, excluded, }
}

///|
fn read_exts(t : @asn1.Tlv) -> Exts raise @asn1.Refused {
  read_exts_body(@asn1.only(t.value))
}

///|
/// The extensions a certificate carries, from the `Extensions` SEQUENCE on its own — the same
/// encoding arrives in a certificate request's `extensionRequest` attribute and in a revocation
/// list, so it is read here rather than at each of the three callers.
pub fn exts(der : BytesView) -> Exts raise @asn1.Refused {
  read_exts_body(@asn1.only(der))
}

///|
/// The extensions, from an `Extensions` SEQUENCE that has already been read.
fn read_exts_body(seq : @asn1.Tlv) -> Exts raise @asn1.Refused {
  if seq.tag != 0x30 {
    raise @asn1.Malformed("extensions are not a SEQUENCE")
  }
  let items = seq.items()
  if items.length() == 0 {
    raise @asn1.Malformed("empty extensions")
  }
  let seen : Array[String] = []
  let mut exts = no_exts
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
      "2.5.29.17" => exts = { ..exts, san: read_san(v), }
      "2.5.29.19" => {
        let (ca, path_len) = read_basic(v)
        exts = { ..exts, ca, path_len, }
      }
      "2.5.29.15" => exts = { ..exts, key_usage: Some(@asn1.only(v).bits()), }
      "2.5.29.37" => exts = { ..exts, eku: Some(read_eku(v)), }
      "2.5.29.14" =>
        exts = { ..exts, ski: Some(@asn1.only(v).octets().to_owned()), }
      "2.5.29.35" => exts = { ..exts, aki: read_aki(v), }
      "2.5.29.30" => exts = { ..exts, constraints: Some(read_constraints(v)), }
      _ => if critical { unknown_critical.push(oid) }
    }
  }
  { ..exts, unknown_critical, }
}

///|
/// An `Exts` with nothing in it — the starting point for a caller assembling the extensions a
/// certificate or a request should ask for.
pub fn Exts::empty() -> Exts {
  no_exts
}

///|
/// Whether the extension is one whose value this package can write.
fn Exts::written(self : Exts) -> Unit raise @asn1.Refused {
  if self.constraints is Some(_) {
    raise @asn1.Unsupported("nameConstraints are read but not written")
  }
  if self.unknown_critical.get(0) is Some(oid) {
    raise @asn1.Unsupported("extension " + oid + " is read but not written")
  }
}

///|
/// The `Extensions` SEQUENCE for these extensions (RFC 5280 §4.2), in the order this package
/// writes them. An extension it reads but does not write — a name constraint, or an unknown
/// critical one whose value was dropped on the way in — is `Unsupported` rather than silently
/// left out, because leaving it out changes what the certificate means.
pub fn Exts::encode(self : Exts) -> Bytes raise @asn1.Refused {
  self.written()
  let out : Array[Bytes] = []
  if self.ca || self.path_len is Some(_) {
    let body : Array[Bytes] = []
    if self.ca {
      body.push(@asn1.tlv(0x01, b"\xff"))
    }
    match self.path_len {
      Some(n) => {
        if n < 0 || n > 255 {
          raise @asn1.Malformed("pathLenConstraint out of range")
        }
        body.push(@asn1.integer(magnitude(n)))
      }
      None => ()
    }
    out.push(extension("2.5.29.19", true, @asn1.sequence(body)))
  }
  match self.key_usage {
    Some(bits) => {
      let body : Array[Byte] = [bits.unused.to_byte()]
      let mut last = bits.bytes.length()
      while last > 1 && bits.bytes[last - 1] == b'\x00' && bits.unused == 0 {
        last = last - 1
      }
      for i in 0..<last {
        body.push(bits.bytes[i])
      }
      out.push(
        extension("2.5.29.15", true, @asn1.tlv(0x03, Bytes::from_array(body))),
      )
    }
    None => ()
  }
  match self.eku {
    Some(list) => {
      if list.length() == 0 {
        raise @asn1.Malformed("an empty extKeyUsage is not encodable")
      }
      let body : Array[Bytes] = []
      for oid in list {
        body.push(oid_der(oid))
      }
      out.push(extension("2.5.29.37", false, @asn1.sequence(body)))
    }
    None => ()
  }
  if self.san.length() > 0 {
    let body : Array[Bytes] = []
    for g in self.san {
      body.push(name_der(g))
    }
    out.push(extension("2.5.29.17", false, @asn1.sequence(body)))
  }
  match self.ski {
    Some(k) => out.push(extension("2.5.29.14", false, @asn1.octet_string(k)))
    None => ()
  }
  match self.aki {
    Some(k) =>
      out.push(
        extension("2.5.29.35", false, @asn1.sequence([@asn1.tlv(0x80, k)])),
      )
    None => ()
  }
  if out.length() == 0 {
    raise @asn1.Malformed("an empty Extensions is not encodable")
  }
  @asn1.sequence(out)
}

///|
/// One `Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET
/// STRING }`. A `FALSE` criticality is the default and is left out, which DER requires.
fn extension(oid : String, critical : Bool, value : Bytes) -> Bytes {
  let parts : Array[Bytes] = [oid_der(oid) catch { _ => @asn1.null() }]
  if critical {
    parts.push(@asn1.tlv(0x01, b"\xff"))
  }
  parts.push(@asn1.octet_string(value))
  @asn1.sequence(parts)
}

///|
/// A GeneralName as the wire writes it: the field number in the tag, because RFC 5280 makes
/// every form IMPLICIT-tagged except `directoryName`.
fn name_der(g : GeneralName) -> Bytes raise @asn1.Refused {
  match g {
    Dns(s) => @asn1.tlv(0x82, ascii_of(s))
    Email(s) => @asn1.tlv(0x81, ascii_of(s))
    Uri(s) => @asn1.tlv(0x86, ascii_of(s))
    Ip(a) => @asn1.tlv(0x87, a)
    Dir(n) => @asn1.tlv(0xa4, n.raw)
    Named(k, v) => @asn1.tlv(0x80 | k, v)
  }
}

///|
fn ascii_of(s : String) -> Bytes raise @asn1.Refused {
  let out = Buffer()
  for c in s {
    let n = c.to_int()
    if n >= 0x80 {
      raise @asn1.Malformed("a non-ASCII character in an IA5String")
    }
    out.write_byte(n.to_byte())
  }
  out.to_bytes()
}

///|
/// A non-negative integer as the big-endian magnitude an INTEGER is built from.
fn magnitude(n : Int32) -> Bytes {
  let out = Buffer()
  let mut m = n
  let digits : Array[Byte] = []
  if m == 0 {
    digits.push(b'\x00')
  }
  while m > 0 {
    digits.push((m % 256).to_byte())
    m = m / 256
  }
  for i in 0..<digits.length() {
    out.write_byte(digits[digits.length() - 1 - i])
  }
  out.to_bytes()
}

///|
pub extend Exts with Debug::{to_repr}

///|
pub extend Exts with Eq::{not_equal, equal}

///|
pub extend GeneralName with Debug::{to_repr}

///|
pub extend GeneralName with Eq::{not_equal, equal}

///|
pub extend Constraints with Debug::{to_repr}

///|
pub extend Constraints with Eq::{not_equal, equal}
