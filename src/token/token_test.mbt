// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
/// A token split at its dots, as owned strings so the parts can be read by index.
fn parts(text : String) -> Array[String] {
  let out : Array[String] = []
  for p in text.split(".") {
    out.push(p.to_owned())
  }
  out
}

///|
fn key(text : String) -> @token.Keys {
  @token.Keys::new(@utf8.encode(text)[:])
}

///|
/// What was signed comes back, and the token carries it as three base64url parts a URL can hold.
test "token: what it signs, it verifies" {
  let keys = key("a secret nobody else has")
  let payload = @utf8.encode("user=42&scope=read")[:]
  let text = @token.sign(
    payload,
    keys~,
    salt="session",
    at=Some(1_700_000_000L),
  )
  let back = @token.verify(
    text,
    keys~,
    salt="session",
    max_age=Some(3600L),
    now=1_700_000_100L,
  )
  assert_eq(back, payload.to_owned())
  for c in text {
    assert_true(
      (c >= 'a' && c <= 'z') ||
      (c >= 'A' && c <= 'Z') ||
      (c >= '0' && c <= '9') ||
      c == '.' ||
      c == '-' ||
      c == '_',
    )
  }
  assert_eq(parts(text).length(), 3)
}

///|
/// The salt is what keeps one key's signatures from being usable in another place: the same
/// payload under another salt is another token, and the first one does not verify.
test "token: a salt separates one use of a key from another" {
  let keys = key("one key, two purposes")
  let text = @token.sign(
    @utf8.encode("reset the password")[:],
    keys~,
    salt="password-reset",
    at=Some(1_700_000_000L),
  )
  let refused = try {
    @token.verify(text, keys~, salt="session", now=1_700_000_001L) |> ignore
    false
  } catch {
    Signature => true
    _ => false
  }
  assert_true(refused)
  assert_true(
    @token.verify(text, keys~, salt="password-reset", now=1_700_000_001L).length() >
    0,
  )
}

///|
/// An edited payload does not survive: the tag covers the base64 that travels, so changing one
/// character of it changes what the tag was computed over.
test "token: an edited payload does not verify" {
  let keys = key("a secret nobody else has")
  let text = @token.sign(
    @utf8.encode("amount=10")[:],
    keys~,
    at=Some(1_700_000_000L),
  )
  let f = parts(text)
  let forged = @utf8.encode("amount=99")
    |> @base64.encode(kind=Url, padding=false)
  let edited = forged + "." + f[1] + "." + f[2]
  let refused = try {
    @token.verify(edited, keys~, now=1_700_000_100L) |> ignore
    false
  } catch {
    Signature => true
    _ => false
  }
  assert_true(refused)
}

///|
/// Age is checked against the caller's clock and window, in both directions: an old token is
/// expired, and so is one stamped further in the future than a clock can honestly be.
test "token: a token ages out, and a future one is not trusted" {
  let keys = key("a secret nobody else has")
  let text = @token.sign(
    @utf8.encode("session")[:],
    keys~,
    at=Some(1_700_000_000L),
  )
  assert_eq(
    @token.verify(text, keys~, max_age=Some(600L), now=1_700_000_590L),
    @utf8.encode("session")[:].to_owned(),
  )
  let stale = try {
    @token.verify(text, keys~, max_age=Some(600L), now=1_700_000_601L) |> ignore
    false
  } catch {
    Expired => true
    _ => false
  }
  assert_true(stale)
  let future = try {
    @token.verify(text, keys~, now=1_699_990_000L) |> ignore
    false
  } catch {
    Expired => true
    _ => false
  }
  assert_true(future)
}

///|
/// A key that has been rotated out still verifies what it signed, and a key that has never been
/// in the set does not.
test "token: a rotated key still verifies what it signed" {
  let old = key("the key from last year")
  let text = @token.sign(
    @utf8.encode("stamped before the change")[:],
    keys=old,
    at=Some(1_700_000_000L),
  )
  let rotated = old.rotate(@utf8.encode("the key from this year")[:])
  assert_eq(
    @token.verify(text, keys=rotated, now=1_700_000_100L),
    @utf8.encode("stamped before the change")[:].to_owned(),
  )
  // The new key signs, and the set that has never seen it refuses.
  let fresh = @token.sign(
    @utf8.encode("after the change")[:],
    keys=rotated,
    at=Some(1_700_000_000L),
  )
  assert_true(
    @token.verify(fresh, keys=rotated, now=1_700_000_100L).length() > 0,
  )
  let refused = try {
    @token.verify(fresh, keys=old, now=1_700_000_100L) |> ignore
    false
  } catch {
    Signature => true
    _ => false
  }
  assert_true(refused)
}

///|
/// A token signed without a timestamp carries none, so there is no age to check: that is the
/// caller's choice at signing time, and the reader honours it rather than inventing one.
test "token: a token without a timestamp is not aged" {
  let keys = key("a secret nobody else has")
  let text = @token.sign(@utf8.encode("forever")[:], keys~)
  assert_eq(parts(text)[1], "")
  assert_eq(
    @token.verify(text, keys~, max_age=Some(1L), now=2_000_000_000L),
    @utf8.encode("forever")[:].to_owned(),
  )
}

///|
/// Anything that is not three base64url parts is malformed rather than merely unsigned, so a
/// caller can tell a truncated cookie from a forged one.
test "token: a string that is not a token is malformed" {
  let keys = key("a secret nobody else has")
  for text in ["", "one", "one.two", "one.two.three.four", "a.b.!!!"] {
    let refused = try {
      @token.verify(text, keys~, now=1_700_000_000L) |> ignore
      false
    } catch {
      Malformed(_) => true
      _ => false
    }
    assert_true(refused)
  }
}
