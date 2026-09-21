// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// The key material a JWK carries, by key type (RFC 7518 §6).
///
/// Bytes, not keys: turning these into something that can sign would mean
/// choosing an implementation for every algorithm, and then a program that
/// reads one JWK would link all of them. The two lines that build a key from
/// this material belong to the program, which knows which algorithms it wants.
pub(all) enum Material {
  /// A symmetric key — what HS256 is keyed with.
  Oct(key~ : Bytes)
  /// RSA: modulus, public exponent, and the private exponent when present.
  Rsa(modulus~ : Bytes, exponent~ : Bytes, secret~ : Bytes?)
  /// An elliptic curve point, and the scalar when present.
  Ec(curve~ : String, x~ : Bytes, y~ : Bytes, secret~ : Bytes?)
  /// An octet key pair — Ed25519 and the rest of RFC 8037.
  Okp(curve~ : String, x~ : Bytes, secret~ : Bytes?)
} derive(Eq, Debug)

///|
pub extend Material with Eq::{equal, not_equal}

///|
pub extend Material with Debug::{to_repr}

///|
/// Why a JWK could not be read.
pub(all) suberror Bad {
  /// The document is not a JSON object, or a set has no `keys` array.
  Shape(String)
  /// A field the key type requires is absent or not a string.
  Missing(field~ : String)
  /// A field that should be base64url is not.
  NotBase64(field~ : String)
  /// A `kty` this package does not know.
  Unknown(kty~ : String)
} derive(Eq, Debug)

///|
pub extend Bad with Eq::{equal, not_equal}

///|
pub extend Bad with Debug::{to_repr}

///|
/// One key, with the metadata a chooser needs.
struct Jwk {
  material : Material
  id : String?
  alg : String?
  usage : String?
  ops : Array[String]
}

///|
/// Read one key from a parsed document.
pub fn Jwk::read(value : Json) -> Jwk raise Bad {
  let members = match value {
    Object(members) => members
    _ => raise Shape("a JWK is a JSON object")
  }
  let kty = text(members, "kty")
  let material = match kty {
    "oct" => Material::Oct(key=raw(members, "k"))
    "RSA" =>
      Material::Rsa(
        modulus=raw(members, "n"),
        exponent=raw(members, "e"),
        secret=optional(members, "d"),
      )
    "EC" =>
      Material::Ec(
        curve=text(members, "crv"),
        x=raw(members, "x"),
        y=raw(members, "y"),
        secret=optional(members, "d"),
      )
    "OKP" =>
      Material::Okp(
        curve=text(members, "crv"),
        x=raw(members, "x"),
        secret=optional(members, "d"),
      )
    other => raise Unknown(kty=other)
  }
  let ops : Array[String] = []
  if members.get("key_ops") is Some(Array(items)) {
    for item in items {
      if item is String(name) {
        ops.push(name)
      }
    }
  }
  {
    material,
    id: maybe(members, "kid"),
    alg: maybe(members, "alg"),
    usage: maybe(members, "use"),
    ops,
  }
}

///|
/// Read one key from its JSON text.
pub fn Jwk::parse(text : StringView) -> Jwk raise Bad {
  Jwk::read(document(text))
}

///|
/// The key material itself.
pub fn Jwk::material(self : Jwk) -> Material {
  self.material
}

///|
/// `kid`, the name a verifier picks this key out of a set by.
pub fn Jwk::id(self : Jwk) -> String? {
  self.id
}

///|
/// `alg`, the one algorithm this key is for, when it says.
pub fn Jwk::alg(self : Jwk) -> String? {
  self.alg
}

///|
/// `use`: `"sig"` or `"enc"`.
pub fn Jwk::usage(self : Jwk) -> String? {
  self.usage
}

///|
/// `key_ops`, empty when the key does not say.
pub fn Jwk::ops(self : Jwk) -> Array[String] {
  self.ops
}

///|
/// Whether the key carries a private part.
///
/// A key set published at a well-known URL must answer `false` for every key in
/// it, which is worth asserting in a test rather than discovering in a log.
pub fn Jwk::is_private(self : Jwk) -> Bool {
  match self.material {
    Oct(..) => true
    Rsa(secret~, ..) => secret is Some(_)
    Ec(secret~, ..) => secret is Some(_)
    Okp(secret~, ..) => secret is Some(_)
  }
}

///|
/// Write the key back out.
///
/// The private part is left out unless `secret` says otherwise, because the
/// common reason to write a JWK is to publish it and the common accident is to
/// publish the whole thing.
pub fn Jwk::json(self : Jwk, secret? : Bool = false) -> Json {
  let out : Map[String, Json] = Map([])
  match self.material {
    Oct(key~) => {
      out["kty"] = Json::string("oct")
      out["k"] = Json::string(wrap(key))
    }
    Rsa(modulus~, exponent~, secret=hidden) => {
      out["kty"] = Json::string("RSA")
      out["n"] = Json::string(wrap(modulus))
      out["e"] = Json::string(wrap(exponent))
      if secret {
        match hidden {
          Some(d) => out["d"] = Json::string(wrap(d))
          None => ()
        }
      }
    }
    Ec(curve~, x~, y~, secret=hidden) => {
      out["kty"] = Json::string("EC")
      out["crv"] = Json::string(curve)
      out["x"] = Json::string(wrap(x))
      out["y"] = Json::string(wrap(y))
      if secret {
        match hidden {
          Some(d) => out["d"] = Json::string(wrap(d))
          None => ()
        }
      }
    }
    Okp(curve~, x~, secret=hidden) => {
      out["kty"] = Json::string("OKP")
      out["crv"] = Json::string(curve)
      out["x"] = Json::string(wrap(x))
      if secret {
        match hidden {
          Some(d) => out["d"] = Json::string(wrap(d))
          None => ()
        }
      }
    }
  }
  match self.usage {
    Some(v) => out["use"] = Json::string(v)
    None => ()
  }
  if self.ops.length() > 0 {
    out["key_ops"] = Json::array(self.ops.map(Json::string))
  }
  match self.alg {
    Some(v) => out["alg"] = Json::string(v)
    None => ()
  }
  match self.id {
    Some(v) => out["kid"] = Json::string(v)
    None => ()
  }
  Json::object(out)
}

///|
/// A JWK Set (RFC 7517 §5) — what a `jwks_uri` serves.
struct Set {
  keys : Array[Jwk]
}

///|
/// Read a set from a parsed document.
///
/// A key the reader does not understand is skipped rather than fatal: RFC 7517
/// §5.1 says so, and a set that grows a post-quantum key must not stop every
/// verifier that has not heard of it. `skip` turns that off for a caller who
/// would rather hear about it.
pub fn Set::read(value : Json, skip? : Bool = true) -> Set raise Bad {
  let members = match value {
    Object(members) => members
    _ => raise Shape("a JWK set is a JSON object")
  }
  let listed = match members.get("keys") {
    Some(Array(items)) => items
    _ => raise Shape("a JWK set has a `keys` array")
  }
  let keys : Array[Jwk] = []
  for item in listed {
    if skip {
      keys.push(Jwk::read(item)) catch {
        _ => ()
      }
    } else {
      keys.push(Jwk::read(item))
    }
  }
  { keys, }
}

///|
/// Read a set from its JSON text.
pub fn Set::parse(text : StringView, skip? : Bool = true) -> Set raise Bad {
  Set::read(document(text), skip~)
}

///|
/// Every key that was understood.
pub fn Set::keys(self : Set) -> Array[Jwk] {
  self.keys
}

///|
/// The key with this `kid`.
pub fn Set::by_id(self : Set, id : StringView) -> Jwk? {
  for key in self.keys {
    if key.id is Some(name) && name[:] == id {
      return Some(key)
    }
  }
  None
}

///|
/// The key to verify a token with: the one named by `kid` if the token names
/// one, otherwise the only candidate for this algorithm.
///
/// A key that says nothing about its algorithm is a candidate for any; one that
/// names a different algorithm, or is marked for encryption, is not. When
/// several remain, none is returned — picking one arbitrarily is how a rotated
/// key silently keeps verifying — and `first` is how a caller asks for the
/// other behaviour.
///
/// `usage` is the `use` a candidate must carry when it carries one; `"sig"` is
/// the default because this is a signature library. `None` accepts any.
pub fn Set::pick(
  self : Set,
  alg~ : String,
  id? : String? = None,
  usage? : String? = Some("sig"),
  first? : Bool = false,
) -> Jwk? {
  match id {
    Some(name) =>
      match self.by_id(name[:]) {
        Some(key) => if suits(key, alg, usage) { Some(key) } else { None }
        None => None
      }
    None => {
      let mut found : Jwk? = None
      for key in self.keys {
        if suits(key, alg, usage) {
          if found is Some(_) && !first {
            return None
          }
          if found is None {
            found = Some(key)
          }
        }
      }
      found
    }
  }
}

///|
fn suits(key : Jwk, alg : String, want : String?) -> Bool {
  if want is Some(kind) && key.usage is Some(usage) && usage != kind {
    return false
  }
  if key.ops.length() > 0 &&
    !key.ops.contains("verify") &&
    !key.ops.contains("sign") {
    return false
  }
  match key.alg {
    Some(named) => named == alg
    None => true
  }
}

// ----------------------------------------------------------------- the pieces

///|
fn document(text : StringView) -> Json raise Bad {
  @json.parse(text) catch {
    _ => raise Shape("not valid JSON")
  }
}

///|
fn text(members : Map[String, Json], field : String) -> String raise Bad {
  match members.get(field) {
    Some(String(value)) => value
    _ => raise Missing(field~)
  }
}

///|
fn raw(members : Map[String, Json], field : String) -> Bytes raise Bad {
  let encoded = text(members, field)
  @base64.decode(encoded[:], kind=Url) catch {
    _ => raise NotBase64(field~)
  }
}

///|
fn optional(members : Map[String, Json], field : String) -> Bytes? raise Bad {
  if members.get(field) is Some(String(_)) {
    Some(raw(members, field))
  } else {
    None
  }
}

///|
fn maybe(members : Map[String, Json], field : String) -> String? {
  match members.get(field) {
    Some(String(value)) => Some(value)
    _ => None
  }
}

///|
fn wrap(value : Bytes) -> String {
  @base64.encode(value[:], kind=Url, padding=false)
}
