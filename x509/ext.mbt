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
  let seq = @asn1.only(t.value)
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
