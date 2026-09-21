// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A JOSE signature algorithm (RFC 7518 §3.1), and the one RFC 8037 adds.
///
/// `none` is not here and never will be. It is the algorithm that made
/// "verified" mean "not verified" in a dozen libraries, and a type that cannot
/// express it cannot be talked into accepting it.
pub(all) enum Alg {
  HS256
  HS384
  HS512
  RS256
  RS384
  RS512
  PS256
  PS384
  PS512
  ES256
  ES384
  ES512
  EdDSA
} derive(Eq, Debug)

///|
pub extend Alg with Eq::{equal, not_equal}

///|
pub extend Alg with Debug::{to_repr}

///|
/// The name this algorithm goes by in a header.
pub fn Alg::name(self : Alg) -> String {
  match self {
    HS256 => "HS256"
    HS384 => "HS384"
    HS512 => "HS512"
    RS256 => "RS256"
    RS384 => "RS384"
    RS512 => "RS512"
    PS256 => "PS256"
    PS384 => "PS384"
    PS512 => "PS512"
    ES256 => "ES256"
    ES384 => "ES384"
    ES512 => "ES512"
    EdDSA => "EdDSA"
  }
}

///|
/// Read an algorithm by name.
pub fn Alg::of(name : StringView) -> Alg raise Rejected {
  match name {
    "HS256" => HS256
    "HS384" => HS384
    "HS512" => HS512
    "RS256" => RS256
    "RS384" => RS384
    "RS512" => RS512
    "PS256" => PS256
    "PS384" => PS384
    "PS512" => PS512
    "ES256" => ES256
    "ES384" => ES384
    "ES512" => ES512
    "EdDSA" => EdDSA
    _ => raise Algorithm(want="a registered algorithm", got=name.to_owned())
  }
}

///|
/// Why a token was not accepted.
///
/// Each reason is separate so a caller can map it to the right answer — an
/// expired token deserves a different response from a forged one — and so a log
/// says which check failed rather than that one did.
pub(all) suberror Rejected {
  /// Not three segments, a segment that is not base64url, or a header or
  /// payload that is not a JSON object.
  Shape(String)
  /// The header names an algorithm other than the one the caller will accept.
  Algorithm(want~ : String, got~ : String)
  /// The signature does not match.
  Signature
  /// `exp` has passed.
  Expired(at~ : Double)
  /// `nbf` has not arrived.
  TooEarly(at~ : Double)
  /// `iss` is not the expected one.
  Issuer(want~ : String, got~ : String)
  /// `aud` does not include the expected one.
  Audience(want~ : String)
} derive(Eq, Debug)

///|
pub extend Rejected with Eq::{equal, not_equal}

///|
pub extend Rejected with Debug::{to_repr}

///|
/// Sign a claims set as a compact JWT.
///
/// `extra` goes into the header beside `alg` and `typ` — `kid` is what it is
/// usually for, so a verifier can pick the right key out of a set before it
/// verifies anything.
///
/// The key is whatever can sign; this package never chooses an algorithm's
/// implementation, so a program that issues only HS256 tokens links only HMAC.
pub fn sign(
  claims : Map[String, Json],
  alg : Alg,
  key : &@spec.Signer,
  extra? : Map[String, Json] = Map([]),
) -> String {
  let head : Map[String, Json] = Map([])
  head["alg"] = Json::string(alg.name())
  head["typ"] = Json::string("JWT")
  for name, value in extra {
    head[name] = value
  }
  let input = segment(head) + "." + segment(claims)
  input + "." + wrap(key.sign(@utf8.encode(input[:])[:]))
}

///|
/// Verify a compact JWT and return its claims.
///
/// **The algorithm is the caller's, not the token's.** A verifier that reads
/// `alg` out of the header and then trusts it is how an RS256 public key gets
/// used as an HS256 shared secret, and how `none` gets accepted; here the header
/// must match what the caller already decided, or the token is refused.
///
/// The checks run in this order: three segments; the header's algorithm; the
/// signature; `exp`; `nbf`; then `iss` and `aud` if the caller named them.
/// Signature before claims, so a forged token is never read for its contents.
///
/// `now` is a Unix timestamp in seconds — the JWT `NumericDate`. `leeway`
/// widens both time checks by that many seconds, for clocks that disagree.
pub fn verify(
  token : StringView,
  alg : Alg,
  key : &@spec.Verifier,
  now~ : Int64,
  leeway? : Int64 = 0,
  issuer? : String? = None,
  audience? : String? = None,
) -> Map[String, Json] raise Rejected {
  let (first, second) = split(token)
  let head = object(token[0:first], "header")
  match head.get("alg") {
    Some(String(name)) =>
      if name != alg.name() {
        raise Algorithm(want=alg.name(), got=name)
      }
    _ => raise Algorithm(want=alg.name(), got="none given")
  }
  let input = token[0:second]
  let given = unwrap(token[second + 1:], "signature")
  if !key.verify(@utf8.encode(input)[:], given[:]) {
    raise Signature
  }
  let claims = object(token[first + 1:second], "payload")
  let at = now.to_double()
  let slack = leeway.to_double()
  match seconds(claims, "exp") {
    Some(exp) => if at - slack >= exp { raise Expired(at=exp) }
    None => ()
  }
  match seconds(claims, "nbf") {
    Some(nbf) => if at + slack < nbf { raise TooEarly(at=nbf) }
    None => ()
  }
  match issuer {
    Some(want) =>
      match claims.get("iss") {
        Some(String(got)) => if got != want { raise Issuer(want~, got~) }
        _ => raise Issuer(want~, got="none given")
      }
    None => ()
  }
  match audience {
    Some(want) => if !accepts(claims, want) { raise Audience(want~) }
    None => ()
  }
  claims
}

///|
/// The header of a token that has not been verified.
///
/// This is for one thing: reading `kid` to choose which key to verify with.
/// Nothing else in here has been checked by anybody.
pub fn header(token : StringView) -> Map[String, Json] raise Rejected {
  object(token[0:split(token).0], "header")
}

///|
/// The claims of a token that has not been verified.
///
/// Whoever sent the token wrote these. Reading them before `verify` has
/// returned is reading an attacker's input; it is here because a gateway
/// sometimes must route on `iss` before it knows which key to fetch, and for no
/// other reason.
pub fn claims_unverified(
  token : StringView,
) -> Map[String, Json] raise Rejected {
  let (first, second) = split(token)
  object(token[first + 1:second], "payload")
}

// -------------------------------------------------------------- MAC as a key

///|
/// A keyed MAC, standing in as both signer and verifier.
///
/// HMAC is symmetric: the same key that signs verifies. What it is not is a
/// signature — anyone who can check an HS256 token can mint one — so a token
/// verified this way says only that someone holding the shared secret issued it.
struct Keyed {
  make : () -> &@spec.Mac
}

///|
/// Take a way of making a keyed MAC and use it as a JWT key.
///
/// It takes a factory rather than a MAC because one state cannot authenticate
/// two messages, and a key outlives the token it was used on.
pub fn mac(make : () -> &@spec.Mac) -> Keyed {
  { make, }
}

///|
pub extend Keyed with @spec.Signer::{sign}

///|
pub impl @spec.Signer for Keyed with fn sign(self : Keyed, msg : BytesView) -> Bytes {
  let m = (self.make)()
  m.write(msg)
  m.finish()
}

///|
pub extend Keyed with @spec.Verifier::{verify}

///|
/// Compared in constant time: the alternative leaks the right tag one byte at a
/// time to anyone who can measure how long the answer took.
pub impl @spec.Verifier for Keyed with fn verify(
  self : Keyed,
  msg : BytesView,
  tag : BytesView,
) -> Bool {
  let m = (self.make)()
  m.write(msg)
  @spec.eq(m.finish()[:], tag)
}

// ----------------------------------------------------------------- the pieces

///|
/// Where the two dots are, which is all a caller needs to cut the three
/// segments and the signing input out of one view.
fn split(token : StringView) -> (Int, Int) raise Rejected {
  let mut first = -1
  let mut second = -1
  let mut count = 0
  for i in 0..<token.length() {
    if token.at(i).to_int() == 0x2E {
      count += 1
      if first < 0 {
        first = i
      } else if second < 0 {
        second = i
      }
    }
  }
  if count != 2 ||
    first == 0 ||
    second == first + 1 ||
    second == token.length() - 1 {
    raise Shape("a compact JWT is three dot-separated segments")
  }
  (first, second)
}

///|
fn segment(value : Map[String, Json]) -> String {
  wrap(@utf8.encode(@json.write(Json::object(value))[:]))
}

///|
fn wrap(raw : Bytes) -> String {
  @base64.encode(raw[:], kind=Url, padding=false)
}

///|
fn unwrap(seg : StringView, what : String) -> Bytes raise Rejected {
  @base64.decode(seg, kind=Url) catch {
    _ => raise Shape("the \{what} is not base64url")
  }
}

///|
fn object(seg : StringView, what : String) -> Map[String, Json] raise Rejected {
  let raw = unwrap(seg, what)
  let text = @utf8.decode(raw[:]) catch {
    _ => raise Shape("the \{what} is not UTF-8")
  }
  let value = @json.parse(text[:]) catch {
    _ => raise Shape("the \{what} is not JSON")
  }
  match value {
    Object(members) => members
    _ => raise Shape("the \{what} is not a JSON object")
  }
}

///|
/// A `NumericDate` claim (RFC 7519 §2): seconds since the epoch, as a number.
/// A claim of the wrong shape is treated as absent rather than as a failure,
/// which is what the specification's "MUST be a number" leaves an implementation
/// to decide and what every other library does.
fn seconds(claims : Map[String, Json], name : String) -> Double? {
  match claims.get(name) {
    Some(Number(value, ..)) => Some(value)
    _ => None
  }
}

///|
/// `aud` is one string or an array of them (RFC 7519 §4.1.3).
fn accepts(claims : Map[String, Json], want : String) -> Bool {
  match claims.get("aud") {
    Some(String(one)) => one == want
    Some(Array(many)) => {
      for item in many {
        if item is String(one) && one == want {
          return true
        }
      }
      false
    }
    _ => false
  }
}
