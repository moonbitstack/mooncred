// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// commonName (X.520 §6.2.2), the attribute a name is usually read from.
pub let oid_cn : String = "2.5.4.3"

///|
/// One AttributeTypeAndValue: the attribute's OID in dotted-decimal form, and its value as text.
pub(all) struct Attr {
  oid : String
  value : String
} derive(Eq, Debug)

///|
/// A distinguished name as it is encoded — a sequence of relative distinguished names, each a set
/// of attributes — together with the encoding itself. Path building matches an issuer to its
/// subject by those octets, as webpki and Go do: two readings of one name must not decide whether
/// a certificate chains.
pub(all) struct Name {
  rdns : Array[Array[Attr]]
  raw : Bytes
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
/// A name from the DER of its `Name` SEQUENCE, for the callers outside a certificate: a
/// certificate request's subject, a revocation list's issuer, a responder's name.
pub fn name(der : BytesView) -> Name raise @asn1.Refused {
  read_name(@asn1.only(der))
}

///|
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
      attrs.push({ oid: parts[0].oid(), value: attr_text(parts[1]), })
    }
    if attrs.length() == 0 {
      raise @asn1.Malformed("empty RelativeDistinguishedName")
    }
    rdns.push(attrs)
  }
  { rdns, raw: tlv.raw.to_owned(), }
}

///|
/// An attribute value as text. Directory strings are decoded; a value of another type (a
/// domainComponent is an IA5String, but an attribute may be anything) keeps its encoding in hex,
/// so a name that carries one still reads instead of refusing the whole certificate.
fn attr_text(t : @asn1.Tlv) -> String raise @asn1.Refused {
  match t.tag {
    0x0c | 0x12 | 0x13 | 0x14 | 0x16 | 0x1a | 0x1e => t.text()
    _ => "#" + @base16.encode(t.raw)
  }
}

///|
fn rdn_raws(name : Name) -> Array[Bytes] raise @asn1.Refused {
  @asn1.only(name.raw[:]).items().map(r => r.raw.to_owned())
}

///|
pub extend Attr with Debug::{to_repr}

///|
pub extend Attr with Eq::{not_equal, equal}

///|
pub extend Name with Debug::{to_repr}

///|
pub extend Name with Eq::{not_equal, equal}
