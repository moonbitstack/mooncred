// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A signed token is for the data a session carries that must come back unedited: a user id, a
// form's hidden fields, an unsubscribe link. It is not an envelope — the payload is readable by
// anyone holding the string — and it is not a JWT: there is no algorithm field to confuse, no
// header to forge, and one key does the one thing the caller asked for.

///|
/// Why a token was not accepted.
pub(all) suberror Refused {
  /// Not a token this format could have produced.
  Malformed(String)
  /// The tag does not match: the payload, the timestamp or the salt is not the one that was
  /// signed, or the key that signed it is not one of these. A verifier cannot tell those apart,
  /// and a forger must not be able to.
  Signature
  /// Older than the window the caller allows, or stamped in the future.
  Expired
} derive(Eq, Debug)

///|
/// The keys a token may be verified against: the one signing now, and the ones retired but still
/// honoured, newest first. Rotating is a push, and every token signed by the old key keeps
/// working until the call that drops it.
pub(all) struct Keys {
  current : Bytes
  previous : Array[Bytes]
}

///|
/// A key set with one key in it.
pub fn Keys::new(current : BytesView) -> Keys {
  { current: current.to_owned(), previous: [], }
}

///|
/// The same set with `current` retired and `next` signing from now on. A token signed a moment
/// before the call still verifies; one signed a moment after verifies under the new key.
pub fn Keys::rotate(self : Keys, next : BytesView) -> Keys {
  let previous = [self.current]
  for k in self.previous {
    previous.push(k)
  }
  { current: next.to_owned(), previous, }
}

///|
/// Sign `payload` and return the token: `payload.timestamp.tag`, each part base64url without
/// padding, so it survives a URL, a cookie and a header unchanged.
///
/// `salt` is what makes the signature specific to a purpose. It is not sent with the token; it is
/// hashed into the tag, so a token issued by the password-reset path cannot be presented to the
/// session path even when both use one key.
pub fn sign(
  payload : BytesView,
  keys~ : Keys,
  salt~ : String = "",
  at~ : Int64? = None,
) -> String {
  let body = @base64.encode(payload, kind=Url, padding=false)
  let stamp = match at {
    Some(t) => @base64.encode(of_int(t)[:], kind=Url, padding=false)
    None => ""
  }
  let tag = @base64.encode(
    tag_of(body, stamp, salt, keys.current)[:],
    kind=Url,
    padding=false,
  )
  body + "." + stamp + "." + tag
}

///|
/// The payload of a token, if the tag is one this key set could have made and the timestamp is
/// inside `max_age` seconds of `now`.
///
/// A token with no timestamp has no age, so `max_age` does not apply to it: the format allows one
/// and the caller that signs without `at` is saying the token does not expire. Pass `at` for
/// anything that should.
pub fn verify(
  text : StringView,
  keys~ : Keys,
  salt~ : String = "",
  max_age~ : Int64? = None,
  now~ : Int64,
) -> Bytes raise Refused {
  let parts = split(text)
  let (body, stamp, tag) = match parts {
    [b, s, t] => (b, s, t)
    _ => raise Malformed("a token is three dot-separated parts")
  }
  let raw_tag = @base64.decode(tag, kind=Url) catch {
    _ => raise Malformed("the tag is not base64url")
  }
  let signed = tag_of(body, stamp, salt, keys.current)
  if same(raw_tag[:], signed[:]) {
    return aged(body, stamp, max_age~, now~)
  }
  for k in keys.previous {
    let older = tag_of(body, stamp, salt, k)
    if same(raw_tag[:], older[:]) {
      return aged(body, stamp, max_age~, now~)
    }
  }
  raise Signature
}

///|
/// The payload, once its age has been checked. `Signature` is not reachable from here; the two
/// failures a caller can see after the tag matched are a bad payload and an expired stamp.
fn aged(
  body : StringView,
  stamp : StringView,
  max_age~ : Int64?,
  now~ : Int64,
) -> Bytes raise Refused {
  guard stamp.length() > 0 else {
    let plain = @base64.decode(body, kind=Url) catch {
      _ => raise Malformed("the payload is not base64url")
    }
    return plain
  }
  let when = int_of(stamp)
  if when > now + 60L {
    raise Expired
  }
  match max_age {
    Some(limit) => if now - when > limit { raise Expired } else { () }
    None => ()
  }
  @base64.decode(body, kind=Url) catch {
    _ => raise Malformed("the payload is not base64url")
  }
}

///|
/// The tag over a token's first two parts: everything the caller can see, under one key and one
/// salt. The octet separators are what keep `("ab", "c")` from signing the same message as
/// `("a", "bc")`.
fn tag_of(
  body : StringView,
  stamp : StringView,
  salt : StringView,
  key : Bytes,
) -> Bytes {
  let h = @hmac.Hmac::new(key[:], () => (@sha2.Hasher::new() : &@spec.Hash))
  h.write(@utf8.encode(salt))
  h.write(b"\x00")
  h.write(@utf8.encode(body))
  h.write(b"\x00")
  h.write(@utf8.encode(stamp))
  h.finish()
}

///|
/// A token split at its dots: three parts, the middle one possibly empty.
fn split(text : StringView) -> Array[String] {
  let out : Array[String] = []
  let part = StringBuilder()
  for c in text {
    if c == '.' {
      out.push(part.to_string())
      part.reset()
    } else {
      part.write_char(c)
    }
  }
  out.push(part.to_string())
  out
}

///|
/// An instant as eight big-endian octets, which is how the timestamp part travels.
fn of_int(t : Int64) -> Bytes {
  let out = Buffer()
  let mut i = 7
  while i >= 0 {
    out.write_byte(((t >> (i * 8)) & 0xff).to_byte())
    i = i - 1
  }
  out.to_bytes()
}

///|
/// The inverse, for a timestamp that must be eight octets — a token with any other length in that
/// part is not one this format wrote.
fn int_of(text : StringView) -> Int64 raise Refused {
  let raw = @base64.decode(text, kind=Url) catch {
    _ => raise Malformed("the timestamp is not base64url")
  }
  if raw.length() != 8 {
    raise Malformed("the timestamp is not eight octets")
  }
  let mut t = 0L
  for b in raw {
    t = (t << 8) | b.to_int().to_int64()
  }
  t
}

///|
/// Two octet strings are equal, read to the end either way: a tag check that stops at the first
/// wrong octet tells an attacker how much of a guess was right.
fn same(a : BytesView, b : BytesView) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut diff = 0
  for i in 0..<a.length() {
    diff = diff | (a[i].to_int() ^ b[i].to_int())
  }
  diff == 0
}

///|
pub extend Refused with Eq::{equal, not_equal}

///|
pub extend Refused with Debug::{to_repr}
