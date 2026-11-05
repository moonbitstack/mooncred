// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The keys of RFC 7520 §3, from "Examples of Protecting Content Using JSON Object Signing and
// Encryption". Each is read and written back out: a key that does not come back as the JSON it
// went in as has lost a parameter on the way through.

///|
fn parameter(value : Json, name : String) -> String raise {
  guard value is Object(fields) && fields.get(name) is Some(String(text)) else {
    fail("the example has no " + name)
  }
  text
}

///|
fn rereads(jwk : String) -> Bool raise {
  let key = @jwk.Jwk::parse(jwk)
  let published = @json.dumps(@json.loads(jwk), sort=true)
  published == @json.dumps(key.json(secret=true), sort=true)
}

///|
test "RFC 7520 §3.1: the EC public key reads and writes back" {
  assert_true(rereads(rfc7520_3_1))
}

///|
test "RFC 7520 §3.2: the EC private key reads and writes back" {
  assert_true(rereads(rfc7520_3_2))
  assert_true(@jwk.Jwk::parse(rfc7520_3_2).is_private())
}

///|
test "RFC 7520 §3.3: the RSA public key reads and writes back" {
  assert_true(rereads(rfc7520_3_3))
}

///|
test "RFC 7520 §3.4: the RSA private key keeps its modulus, exponent and private exponent" {
  // RFC 7518 §6.3.2 lets a private key carry the primes and the Chinese-remainder values as
  // well; `Material::Rsa` models n, e and d, which is what a key is, and leaves the rest out.
  let key = @jwk.Jwk::parse(rfc7520_3_4)
  assert_true(key.is_private())
  let published = @json.loads(rfc7520_3_4)
  let written = key.json(secret=true)
  for name in ["kty", "n", "e", "d"] {
    assert_eq(parameter(written, name), parameter(published, name))
  }
}

///|
test "RFC 7520 §3.5: the MAC key reads and writes back" {
  assert_true(rereads(rfc7520_3_5))
  assert_eq(@jwk.Jwk::parse(rfc7520_3_5).alg(), Some("HS256"))
}

///|
test "RFC 7520 §3.6: the encryption key reads and writes back" {
  assert_true(rereads(rfc7520_3_6))
  assert_eq(@jwk.Jwk::parse(rfc7520_3_6).usage(), Some("enc"))
}
