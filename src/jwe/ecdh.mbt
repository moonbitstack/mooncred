// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// ECDH-ES (RFC 7518 §4.6): the sender makes an ephemeral key pair, agrees a secret with the
// recipient's public key, and derives the content key — or the key that wraps it — from that
// secret and the names of the two parties. The ephemeral public key travels in the header as
// `epk`; the secret never does, which is what makes the message readable by one private key
// and by no one else.

///|
/// The curve a name stands for, among those RFC 7518 §6.2.1.1 registers for this use.
fn curve_of(name : StringView) -> @curve.Curve raise Refused {
  match name {
    "P-256" => P256
    "P-384" => P384
    "P-521" => P521
    _ => raise Unsupported("the curve " + name.to_owned())
  }
}

///|
/// The name a curve goes by in a JWK.
fn curve_name(curve : @curve.Curve) -> String raise Refused {
  match curve {
    P256 => "P-256"
    P384 => "P-384"
    P521 => "P-521"
    _ => raise Unsupported("a curve this library does not agree keys on")
  }
}

///|
/// The shared secret: the X coordinate of the product of the private scalar and the peer's
/// point.
fn agree(
  scalar : BytesView,
  point : BytesView,
  curve : @curve.Curve,
) -> Bytes raise Refused {
  @ecdh.shared(scalar, point, curve~) catch {
    _ => raise Key
  }
}

///|
/// The ephemeral public key as a JWK goes into the header.
fn epk_of(
  scalar : BytesView,
  curve : @curve.Curve,
) -> Map[String, Json] raise Refused {
  let point = @ecdh.public(scalar, curve~) catch { _ => raise Key }
  let (x, y) = @ecdsa.PublicKey::new(point, curve~).xy() catch {
    _ => raise Key
  }
  let out : Map[String, Json] = Map([])
  out["kty"] = Json::string("EC")
  out["crv"] = Json::string(curve_name(curve))
  out["x"] = Json::string(b64(x[:]))
  out["y"] = Json::string(b64(y[:]))
  out
}

///|
/// The public point an `epk` names, and the curve it says it lies on.
fn point_of_epk(epk : Map[String, Json]) -> (@curve.Curve, Bytes) raise Refused {
  let name = match epk.get("kty") {
    Some(String(kind)) =>
      if kind != "EC" {
        raise Unsupported("an ephemeral key of type " + kind)
      }
    _ => raise Malformed("epk names no key type")
  }
  ignore(name)
  let curve = match epk.get("crv") {
    Some(String(crv)) => curve_of(crv[:])
    _ => raise Malformed("epk names no curve")
  }
  let x = match epk.get("x") {
    Some(String(text)) => unwrap_b64(text)
    _ => raise Malformed("epk names no x")
  }
  let y = match epk.get("y") {
    Some(String(text)) => unwrap_b64(text)
    _ => raise Malformed("epk names no y")
  }
  let point = @ecdsa.PublicKey::of_xy(x[:], y[:], curve~) catch {
    _ => raise Malformed("epk is not a point on its curve")
  }
  (curve, point.bytes())
}

///|
/// The Concat KDF of NIST SP 800-56A §5.8.1, as RFC 7518 §4.6.2 spells it for JOSE.
///
/// The other information is the AlgorithmID, the two parties' key info and the length being
/// derived, each with a four-octet length in front; the length is in bits, and the counter the
/// KDF itself starts at one.
fn concat_key(
  z : BytesView,
  algid : StringView,
  apu : BytesView,
  apv : BytesView,
  bits : Int32,
) -> Bytes {
  let info = Buffer()
  length_prefixed(info, @utf8.encode(algid)[:])
  length_prefixed(info, apu)
  length_prefixed(info, apv)
  let size = Buffer()
  size.write_byte(((bits >> 24) & 0xFF).to_byte())
  size.write_byte(((bits >> 16) & 0xFF).to_byte())
  size.write_byte(((bits >> 8) & 0xFF).to_byte())
  size.write_byte((bits & 0xFF).to_byte())
  info.write_bytes(size.to_bytes()[:])
  @concat.key(
    z,
    fn() { @sha2.Hasher::new() },
    other_info=info.to_bytes()[:],
    len=bits / 8,
  )
}

///|
fn length_prefixed(out : Buffer, value : BytesView) -> Unit {
  let size = value.length()
  out.write_byte(((size >> 24) & 0xFF).to_byte())
  out.write_byte(((size >> 16) & 0xFF).to_byte())
  out.write_byte(((size >> 8) & 0xFF).to_byte())
  out.write_byte((size & 0xFF).to_byte())
  out.write_bytesview(value)
}

///|
/// `apu` and `apv`, the two parties' key info, from the header (both optional).
fn party_info(header : Map[String, Json], name : String) -> Bytes raise Refused {
  match header.get(name) {
    Some(String(text)) => unwrap_b64(text)
    _ => b""
  }
}

///|
fn unwrap_b64(text : String) -> Bytes raise Refused {
  @base64.decode(text[:], kind=Url) catch {
    _ => raise Malformed("a header parameter that is not base64url")
  }
}
