// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// CBOR Web Token (RFC 8392): a claim set, in CBOR, signed or MACed as a COSE message.
//
// The claims are the JWT ones under the short names CBOR gives them — 1 `iss`, 2 `sub`, 3 `aud`,
// 4 `exp`, 5 `nbf`, 6 `iat`, 7 `cti` — because a token that travels in a constrained network is
// meant to be small. The meanings are RFC 7519's, and so is the rule that a time claim is Seconds
// Since the Epoch in UTC.
//
// The claim set is a map that may hold anything; this type carries the seven registered claims and
// leaves the rest. A caller that needs a private claim reads it out of the decoded map itself.

///|
/// When the caller says it is.
///
/// The clock is an argument rather than something this library reads, for the reason none of these
/// packages calls the system: a verifier that consults its own clock cannot be tested at the
/// moment a token expires, and one that cannot be tested that way is one nobody checks.
pub(all) enum Clock {
  At(Int64)
  Ignored
} derive(Eq, Debug)

///|
/// The registered claims of RFC 8392 §3.1.
pub(all) struct Claims {
  /// 1: who issued the token.
  iss : String?
  /// 2: who it is about.
  sub : String?
  /// 3: who it is for. RFC 8392 allows a single audience or a list; a list is not carried here,
  /// so a token with one is refused rather than silently read as its first entry.
  aud : String?
  /// 4: when it stops being valid, in seconds since the epoch.
  exp : Int64?
  /// 5: when it starts being valid.
  nbf : Int64?
  /// 6: when it was issued.
  iat : Int64?
  /// 7: an identifier for this token, so one can be recognised as a replay.
  cti : Bytes?
} derive(Eq, Debug)

///|
/// A claim set from the claims given; the others stay absent, not empty.
pub fn Claims::new(
  iss? : String,
  sub? : String,
  aud? : String,
  exp? : Int64,
  nbf? : Int64,
  iat? : Int64,
  cti? : Bytes,
) -> Claims {
  { iss, sub, aud, exp, nbf, iat, cti, }
}

///|
/// The claim set as the CBOR map it is signed as: only the claims that are set, in the order the
/// numbers put them in, so that two encodings of the same claims are the same octets.
pub fn Claims::value(self : Claims) -> @cbor.Value {
  let pairs : Array[(@cbor.Value, @cbor.Value)] = []
  if self.iss is Some(v) {
    pairs.push((Int(1), Text(v)))
  }
  if self.sub is Some(v) {
    pairs.push((Int(2), Text(v)))
  }
  if self.aud is Some(v) {
    pairs.push((Int(3), Text(v)))
  }
  if self.exp is Some(v) {
    pairs.push((Int(4), Int(v)))
  }
  if self.nbf is Some(v) {
    pairs.push((Int(5), Int(v)))
  }
  if self.iat is Some(v) {
    pairs.push((Int(6), Int(v)))
  }
  if self.cti is Some(v) {
    pairs.push((Int(7), Bytes(v)))
  }
  Map(pairs)
}

///|
/// Read a claim set back, keeping the seven claims and dropping the rest.
pub fn Claims::of(value : @cbor.Value) -> Claims raise Refused {
  guard value is Map(pairs) else { raise Malformed("a claim set is a map") }
  let mut iss = None
  let mut sub = None
  let mut aud = None
  let mut exp = None
  let mut nbf = None
  let mut iat = None
  let mut cti = None
  for pair in pairs {
    match pair.0.int() {
      Some(1) => iss = text_of(pair.1, "iss")
      Some(2) => sub = text_of(pair.1, "sub")
      Some(3) => aud = text_of(pair.1, "aud")
      Some(4) => exp = time_of(pair.1, "exp")
      Some(5) => nbf = time_of(pair.1, "nbf")
      Some(6) => iat = time_of(pair.1, "iat")
      Some(7) =>
        cti = match pair.1.bytes() {
          Some(b) => Some(b)
          None => raise Malformed("cti is not a byte string")
        }
      _ => () // A private claim, which this type does not carry.
    }
  }
  { iss, sub, aud, exp, nbf, iat, cti, }
}

///|
fn text_of(value : @cbor.Value, name : String) -> String? raise Refused {
  match value {
    Text(s) => Some(s)
    // A claim that is absent and one that is present but the wrong type are different things: the
    // second is a message the writer got wrong, and reading it as absent would hide that.
    Null | Undefined => None
    _ => raise Malformed(name + " is not a text string")
  }
}

///|
fn time_of(value : @cbor.Value, name : String) -> Int64? raise Refused {
  match value.int() {
    Some(n) => Some(n)
    None =>
      match value {
        Null | Undefined => None
        _ => raise Malformed(name + " is not an integer")
      }
  }
}

///|
/// Whether the claim set is valid at `now`, which is the only judgement a verifier can make without
/// knowing what the token is for.
///
/// The leeway is the seconds of slack allowed either side, for the reason a signer's clock and a
/// verifier's rarely agree exactly: with a leeway of sixty, a token that expired half a minute ago
/// still passes.
pub fn Claims::check(
  self : Claims,
  now~ : Clock,
  leeway~ : Int64 = 60L,
) -> Unit raise Refused {
  guard now is At(seconds) else { return }
  if self.exp is Some(exp) {
    if seconds > exp + leeway {
      raise Expired(at=exp)
    }
  }
  if self.nbf is Some(nbf) {
    if seconds + leeway < nbf {
      raise TooEarly(at=nbf)
    }
  }
}

///|
/// Sign a claim set into a COSE_Sign1.
pub fn signed(
  claims : Claims,
  alg~ : Alg,
  signer : &@spec.Signer,
  kid~ : BytesView? = None,
  external~ : BytesView = b"",
) -> Bytes raise Refused {
  sign1(@cbor.encode(claims.value())[:], alg~, signer, kid~, external~)
}

///|
/// Verify a COSE_Sign1 that carries a claim set, and judge its times.
///
/// `now` has no default: `exp` and `nbf` are checked against it with `leeway`
/// seconds of slack either side, and `now=Ignored` skips the check, which a
/// caller has to write out. The sixty-second leeway is python-cwt's.
pub fn verified(
  octets : BytesView,
  alg~ : Alg,
  verifier : &@spec.Verifier,
  now~ : Clock,
  leeway~ : Int64 = 60L,
  external~ : BytesView = b"",
) -> Claims raise Refused {
  let payload = verify1(octets, alg~, verifier, external~)
  let value = @cbor.decode(payload[:]) catch {
    Malformed(m) => raise Malformed("the claim set: " + m)
    Unsupported(m) => raise Unsupported("the claim set: " + m)
  }
  let claims = Claims::of(value)
  claims.check(now~, leeway~)
  claims
}

///|
/// MAC a claim set into a COSE_Mac0, and verify one back.
pub fn macd(
  claims : Claims,
  alg~ : Alg,
  tagger : &@spec.Signer,
  kid~ : BytesView? = None,
  external~ : BytesView = b"",
) -> Bytes raise Refused {
  mac0(@cbor.encode(claims.value())[:], alg~, tagger, kid~, external~)
}

///|
/// Verify a COSE_Mac0 made by `macd` and read the claim set out of it, judging
/// its times as `verified` does.
pub fn uncovered(
  octets : BytesView,
  alg~ : Alg,
  verifier : &@spec.Verifier,
  now~ : Clock,
  leeway~ : Int64 = 60L,
  external~ : BytesView = b"",
) -> Claims raise Refused {
  let payload = verify_mac0(octets, alg~, verifier, external~)
  let value = @cbor.decode(payload[:]) catch {
    Malformed(m) => raise Malformed("the claim set: " + m)
    Unsupported(m) => raise Unsupported("the claim set: " + m)
  }
  let claims = Claims::of(value)
  claims.check(now~, leeway~)
  claims
}

///|
pub extend Clock with Eq::{equal, not_equal}

///|
pub extend Clock with Debug::{to_repr}

///|
pub extend Claims with Eq::{equal, not_equal}

///|
pub extend Claims with Debug::{to_repr}
