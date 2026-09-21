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
/// When the time claims are measured against.
///
/// A library has no clock — reading one is a side effect and there is no reason
/// for a token verifier to have that power — so the instant comes in from the
/// caller. `Ignored` is the way to read a token without asking whether it has
/// expired: a debugging tool, an audit of tokens already collected, a migration
/// that has to read what was issued last year. It is spelled out at the call
/// site because the alternative is a verifier that quietly stopped checking.
pub(all) enum Clock {
  /// Check `exp` and `nbf` against this instant, in Unix seconds.
  At(Int64)
  /// Do not look at the time claims at all.
  Ignored
} derive(Eq, Debug)

///|
pub extend Clock with Eq::{equal, not_equal}

///|
pub extend Clock with Debug::{to_repr}

///|
/// Which side wins when a setting is given twice.
///
/// Every function here that takes both a base and something layered over it
/// says which one wins, and lets a caller say otherwise. The defaults differ by
/// function and each one says why: `verify` lets the override win, because a
/// per-call argument is more specific than a policy assembled once; `sign` lets
/// the base win, because the header it computes describes the signature it is
/// about to make.
pub(all) enum Wins {
  /// What the function starts from — the policy record, or the header the
  /// signer computes.
  Base
  /// What is layered over it — the per-call arguments, or the caller's `extra`.
  Extra
} derive(Eq, Debug)

///|
pub extend Wins with Eq::{equal, not_equal}

///|
pub extend Wins with Debug::{to_repr}

///|
/// What to do when a setting is given twice.
///
/// `Handle` receives the base and the merged result and returns whichever it
/// wants, so a caller can audit, refuse, or merge some other way entirely.
///
/// There is no `Warn`: a library has nowhere to warn to. It arrives when
/// `moonlog` does.
pub(all) enum OnClash[T] {
  /// Merge as `wins` says and say nothing. What every library does today.
  Ignore
  /// Abort. For the cases where being given two answers is a mistake in the
  /// program rather than a choice about configuration.
  Panic
  /// Hand the base and the merged result to a function and take what it returns.
  Handle((T, T) -> T)
}

///|
/// What a token has to satisfy beyond its signature.
///
/// Every field is a check that is either off or told what to expect, and every
/// default is what the mainstream libraries do: `exp` and `nbf` are checked,
/// `iat` is not, and `iss`, `aud`, `sub` and the header's `typ` are looked at
/// only when the caller says what to expect. Nothing is enforced implicitly and
/// nothing is skipped implicitly.
///
/// One of these is assembled once for a deployment and passed to every
/// verification, which is what `jsonwebtoken`'s `Validation`, .NET's
/// `TokenValidationParameters` and `jose`'s options object are for.
pub(all) struct Policy {
  /// Seconds of slack on the time checks, for clocks that disagree.
  leeway : Int64
  /// Whether to refuse a token whose `exp` has passed.
  expiry : Bool
  /// Whether to refuse a token whose `nbf` has not arrived.
  not_before : Bool
  /// Whether to refuse a token whose `iat` is in the future. Off by default: a
  /// token issued a second early by a fast clock is not an attack, and no
  /// mainstream library refuses it.
  issued_at : Bool
  /// What `iss` must say. `None` does not look at it.
  issuer : String?
  /// What `aud` must include; any one of them will do, because one deployment
  /// behind several names is ordinary. Empty does not look at it.
  audience : Array[String]
  /// What `sub` must say. `None` does not look at it.
  subject : String?
  /// What the header's `typ` must say. `None` does not look at it.
  typ : String?
  /// Claims that must be present whatever their value. RFC 7519 makes none of
  /// them mandatory, so this starts empty.
  required : Array[String]
} derive(Eq, Debug)

///|
pub extend Policy with Eq::{equal, not_equal}

///|
pub extend Policy with Debug::{to_repr}

///|
/// The policy a verification uses when the caller does not say otherwise.
pub let policy : Policy = {
  leeway: 0,
  expiry: true,
  not_before: true,
  issued_at: false,
  issuer: None,
  audience: [],
  subject: None,
  typ: None,
  required: [],
}

///|
/// Build a policy by naming the parts that differ from the default.
///
/// The same thing can be written `{ ..@jwt.policy, expiry: false }`; this form
/// exists because a named argument reads better when several parts differ.
/// `issuer`, `subject` and `typ` can be set here but not cleared: the preset
/// leaves all three unset, so there is nothing to clear. Starting from a base of
/// one's own, `{ ..mine, issuer: None }` is how a check is dropped.
pub fn Policy::new(
  leeway? : Int64 = policy.leeway,
  expiry? : Bool = policy.expiry,
  not_before? : Bool = policy.not_before,
  issued_at? : Bool = policy.issued_at,
  issuer? : String,
  audience? : Array[String] = policy.audience,
  subject? : String,
  typ? : String,
  required? : Array[String] = policy.required,
) -> Policy {
  {
    leeway,
    expiry,
    not_before,
    issued_at,
    issuer,
    audience,
    subject,
    typ,
    required,
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
  /// `aud` does not include any of the expected ones.
  Audience(want~ : Array[String])
  /// `sub` is not the expected one.
  Subject(want~ : String, got~ : String)
  /// `iat` is in the future, when the caller asked for that to be checked.
  IssuedAt(at~ : Double)
  /// The header's `typ` is not the expected one, when the caller named it.
  Type(want~ : String, got~ : String)
  /// A claim the caller required is absent.
  Missing(claim~ : String)
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
/// `typ` is `"JWT"`, which is what every library writes and what RFC 7519 §5.1
/// recommends. `None` leaves it out; another string puts that in — RFC 9068's
/// access tokens want `"at+jwt"`.
///
/// **`extra` cannot quietly rewrite `alg` or `typ`.** The header describes the
/// signature this function is about to make; a token whose header says `none`
/// while the bytes say HS256 is not a configuration choice, it is a mistake, so
/// `wins` starts at `Base` and `clash` at `Panic`. A caller who means it can
/// say `wins=Extra, clash=Ignore`.
///
/// The key is whatever can sign; this package never chooses an algorithm's
/// implementation, so a program that issues only HS256 tokens links only HMAC.
pub fn sign(
  claims : Map[String, Json],
  alg : Alg,
  key : &@spec.Signer,
  typ? : String? = Some("JWT"),
  extra? : Map[String, Json] = Map([]),
  wins? : Wins = Base,
  clash? : OnClash[Map[String, Json]] = Panic,
) -> String {
  let head : Map[String, Json] = Map([])
  head["alg"] = Json::string(alg.name())
  match typ {
    Some(kind) => head["typ"] = Json::string(kind)
    None => ()
  }
  let over : Map[String, Json] = Map([])
  for name, value in head {
    over[name] = value
  }
  let taken : Array[String] = []
  for name, value in extra {
    if head.get(name) is Some(_) {
      taken.push(name)
    }
    over[name] = value
  }
  let merged = if taken.length() == 0 {
    over
  } else {
    let chosen = match wins {
      Extra => over
      Base => {
        let kept : Map[String, Json] = Map([])
        for name, value in over {
          kept[name] = value
        }
        for name, value in head {
          kept[name] = value
        }
        kept
      }
    }
    match clash {
      Ignore => chosen
      Panic =>
        abort(
          "jwt: \{taken.join(", ")} in `extra` would rewrite the header this signature is made under",
        )
      Handle(arbitrate) => arbitrate(head, chosen)
    }
  }
  let input = segment(merged) + "." + segment(claims)
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
/// The signature is checked before any claim is read, so a forged token is
/// never inspected for its contents.
///
/// Configuration has three layers, each overriding the one before:
/// `@jwt.policy` < the `policy` given here < the named arguments given here.
/// `wins` turns the last two around; `clash` decides whether being given a
/// setting twice is silent, fatal, or yours to arbitrate.
///
/// `now` is not configuration but data: the instant the time claims are
/// measured against, or `Ignored` to read a token without asking whether it has
/// expired — a debugging tool, an audit of tokens already collected, a
/// migration that has to read what was issued last year.
pub fn verify(
  token : StringView,
  alg : Alg,
  key : &@spec.Verifier,
  now~ : Clock,
  policy? : Policy = policy,
  wins? : Wins = Extra,
  clash? : OnClash[Policy] = Ignore,
  leeway? : Int64,
  expiry? : Bool,
  issuer? : String,
  audience? : Array[String],
) -> Map[String, Json] raise Rejected {
  let rules = settle(policy, wins, clash, leeway, expiry, issuer, audience)
  let (first, second) = split(token)
  let head = object(token[0:first], "header")
  match head.get("alg") {
    Some(String(name)) =>
      if name != alg.name() {
        raise Algorithm(want=alg.name(), got=name)
      }
    _ => raise Algorithm(want=alg.name(), got="none given")
  }
  match rules.typ {
    Some(want) =>
      match head.get("typ") {
        Some(String(got)) =>
          if !got.equal_ignore_ascii_case(want) {
            raise Type(want~, got~)
          }
        _ => raise Type(want~, got="none given")
      }
    None => ()
  }
  let input = token[0:second]
  let given = unwrap(token[second + 1:], "signature")
  if !key.verify(@utf8.encode(input)[:], given[:]) {
    raise Signature
  }
  let claims = object(token[first + 1:second], "payload")
  match now {
    At(reading) => {
      let at = reading.to_double()
      let slack = rules.leeway.to_double()
      if rules.expiry {
        match seconds(claims, "exp") {
          Some(exp) => if at - slack >= exp { raise Expired(at=exp) }
          None => ()
        }
      }
      if rules.not_before {
        match seconds(claims, "nbf") {
          Some(nbf) => if at + slack < nbf { raise TooEarly(at=nbf) }
          None => ()
        }
      }
      if rules.issued_at {
        match seconds(claims, "iat") {
          Some(iat) => if at + slack < iat { raise IssuedAt(at=iat) }
          None => ()
        }
      }
    }
    Ignored => ()
  }
  match rules.issuer {
    Some(want) =>
      match claims.get("iss") {
        Some(String(got)) => if got != want { raise Issuer(want~, got~) }
        _ => raise Issuer(want~, got="none given")
      }
    None => ()
  }
  if rules.audience.length() > 0 && !accepts(claims, rules.audience) {
    raise Audience(want=rules.audience)
  }
  match rules.subject {
    Some(want) =>
      match claims.get("sub") {
        Some(String(got)) => if got != want { raise Subject(want~, got~) }
        _ => raise Subject(want~, got="none given")
      }
    None => ()
  }
  for claim in rules.required {
    if claims.get(claim) is None {
      raise Missing(claim~)
    }
  }
  claims
}

///|
/// Lay the per-call arguments over the policy, the way `wins` and `clash` say.
fn settle(
  base : Policy,
  wins : Wins,
  clash : OnClash[Policy],
  leeway : Int64?,
  expiry : Bool?,
  issuer : String?,
  audience : Array[String]?,
) -> Policy {
  let named : Array[String] = []
  let mut over = base
  match leeway {
    Some(value) => {
      named.push("leeway")
      over = { ..over, leeway: value, }
    }
    None => ()
  }
  match expiry {
    Some(value) => {
      named.push("expiry")
      over = { ..over, expiry: value, }
    }
    None => ()
  }
  match issuer {
    Some(value) => {
      named.push("issuer")
      over = { ..over, issuer: Some(value), }
    }
    None => ()
  }
  match audience {
    Some(value) => {
      named.push("audience")
      over = { ..over, audience: value, }
    }
    None => ()
  }
  if named.length() == 0 {
    return base
  }
  let merged = match wins {
    Extra => over
    Base => base
  }
  match clash {
    Ignore => merged
    Panic =>
      abort(
        "jwt: \{named.join(", ")} given both in the policy and as an argument",
      )
    Handle(arbitrate) => arbitrate(base, merged)
  }
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
  wrap(@utf8.encode(@json.dumps(Json::object(value))[:]))
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
  let value = @json.loads(text[:]) catch {
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
/// `aud` is one string or an array of them (RFC 7519 §4.1.3), and the caller
/// may accept several: one deployment behind several names is ordinary.
fn accepts(claims : Map[String, Json], want : Array[String]) -> Bool {
  match claims.get("aud") {
    Some(String(one)) => want.contains(one)
    Some(Array(many)) => {
      for item in many {
        if item is String(one) && want.contains(one) {
          return true
        }
      }
      false
    }
    _ => false
  }
}
