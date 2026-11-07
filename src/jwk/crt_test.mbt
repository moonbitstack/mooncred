// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The five numbers an RSA private key may carry beside `d` (RFC 7518 §6.3.2). A key that is
// read and written back out has to keep them: what comes out is what a key file contained, and
// a key that quietly lost its primes no longer opens the same files it came from.

///|
fn field(value : Json, name : String) -> String raise {
  guard value is Object(members) && members.get(name) is Some(String(text)) else {
    fail("no " + name)
  }
  text
}

///|
test "jwk: RFC 7520 §3.4 keeps the primes and the Chinese-remainder values" {
  let key = @jwk.Jwk::parse(rfc7520_3_4)
  let parts = match key.crt() {
    Some(parts) => parts
    None => fail("the key carries p, q, dp, dq and qi")
  }
  let published = @json.loads(rfc7520_3_4)
  assert_eq(parts.p, @base64.decode(field(published, "p"), kind=Url))
  assert_eq(parts.q, @base64.decode(field(published, "q"), kind=Url))
  assert_eq(parts.dp, @base64.decode(field(published, "dp"), kind=Url))
  assert_eq(parts.dq, @base64.decode(field(published, "dq"), kind=Url))
  assert_eq(parts.qi, @base64.decode(field(published, "qi"), kind=Url))
}

///|
/// Written back out, the key is the document it came from: every parameter, in the same octets.
test "jwk: a written private key is the one that was read" {
  let key = @jwk.Jwk::parse(rfc7520_3_4)
  let before = @json.loads(rfc7520_3_4)
  let after = key.json(secret=true)
  for name in ["kty", "n", "e", "d", "p", "q", "dp", "dq", "qi"] {
    assert_eq(field(after, name), field(before, name))
  }
}

///|
/// Publishing a key still leaves the private half out, and with it the primes.
test "jwk: a public copy carries no primes" {
  let key = @jwk.Jwk::parse(rfc7520_3_4)
  let published = key.json()
  assert_true(published is Object(members) && members.get("p") is None)
  assert_true(published is Object(members) && members.get("d") is None)
}

///|
/// Half a set is not a set: the primes are only meaningful together, so a document carrying
/// some of them is refused with the name of the first that is absent.
test "jwk: a partial set of primes is refused" {
  let whole = @json.loads(rfc7520_3_4)
  let members = match whole {
    Object(members) => members
    _ => fail("an object")
  }
  members.remove("qi")
  let refused = try {
    @jwk.Jwk::read(Json::object(members)) |> ignore
    false
  } catch {
    @jwk.Missing(field~) => field == "qi"
    _ => false
  }
  assert_true(refused)
}

///|
/// A key written without them is a complete key, and reading it back says so.
test "jwk: a key without primes is a key" {
  let key = @jwk.Jwk::parse(rfc7520_3_3)
  assert_eq(key.crt(), None)
  assert_eq(key.is_private(), false)
}
