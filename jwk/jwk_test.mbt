// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn hex(b : Bytes) -> String {
  @base16.encode(b[:])
}

///|
/// The public key set of RFC 7517 §A.1, printed as the RFC prints it.
let public_set : String =
  #|{"keys":
  #|  [
  #|    {"kty":"EC",
  #|     "crv":"P-256",
  #|     "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
  #|     "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
  #|     "use":"enc",
  #|     "kid":"1"},
  #|
  #|    {"kty":"RSA",
  #|     "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
  #|     "e":"AQAB",
  #|     "alg":"RS256",
  #|     "kid":"2011-04-29"}
  #|  ]
  #|}

///|
/// The symmetric key set of RFC 7517 §A.3.
let secret_set : String =
  #|{"keys":
  #|  [
  #|    {"kty":"oct",
  #|     "alg":"A128KW",
  #|     "k":"GawgguFyGrWKav7AX4VKUg"},
  #|
  #|    {"kty":"oct",
  #|     "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
  #|     "kid":"HMAC key used in JWS spec Appendix A.1 example"}
  #|  ]
  #|}

///|
/// The Ed25519 key of RFC 8037 §A.1, whose `x` is the public key of RFC 8032's
/// first test vector and whose `d` is that vector's seed.
let okp : String =
  #|{"kty":"OKP","crv":"Ed25519",
  #| "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
  #| "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}

///|
test "the RFC 7517 A.1 public set" {
  let set = @jwk.Set::parse(public_set[:])
  assert_eq(set.keys().length(), 2)
  let ec = set.by_id("1").unwrap()
  assert_eq(ec.usage(), Some("enc"))
  assert_eq(ec.alg(), None)
  assert_false(ec.is_private())
  match ec.material() {
    Ec(curve~, x~, y~, secret~) => {
      assert_eq(curve, "P-256")
      assert_eq(
        hex(x),
        "30a0424cd21c2944838a2d75c92b37e76ea20d9f00893a3b4eee8a3c0aafec3e",
      )
      assert_eq(
        hex(y),
        "e04b65e92456d9888b52b379bdfbd51ee869ef1f0fc65b6659695b6cce081723",
      )
      assert_eq(secret, None)
    }
    _ => fail("the EC key did not read as one")
  }
  let key = set.by_id("2011-04-29").unwrap()
  assert_eq(key.alg(), Some("RS256"))
  match key.material() {
    Rsa(modulus~, exponent~, secret~) => {
      assert_eq(modulus.length(), 256)
      assert_eq(hex(exponent), "010001")
      assert_eq(secret, None)
    }
    _ => fail("the RSA key did not read as one")
  }
}

///|
test "the RFC 7517 A.3 symmetric set" {
  let set = @jwk.Set::parse(secret_set[:])
  assert_eq(set.keys().length(), 2)
  match set.keys()[0].material() {
    Oct(key~) => assert_eq(hex(key), "19ac2082e1721ab58a6afec05f854a52")
    _ => fail("the first key did not read as octets")
  }
  // The second is the key RFC 7515 §A.1 signs its example token with.
  let signing = set
    .by_id("HMAC key used in JWS spec Appendix A.1 example")
    .unwrap()
  match signing.material() {
    Oct(key~) => assert_eq(key.length(), 64)
    _ => fail("the signing key did not read as octets")
  }
  // A symmetric key is always private; publishing this set would publish it.
  assert_true(signing.is_private())
}

///|
test "the RFC 8037 A.1 Ed25519 key" {
  let key = @jwk.Jwk::parse(okp[:])
  assert_true(key.is_private())
  match key.material() {
    Okp(curve~, x~, secret~) => {
      assert_eq(curve, "Ed25519")
      assert_eq(
        hex(x),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
      )
      assert_eq(
        hex(secret.unwrap()),
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
      )
    }
    _ => fail("the OKP key did not read as one")
  }
}

///|
/// The material is what the algorithm packages take, so a key read here signs
/// and verifies without anything in between.
test "a key read here drives the algorithm it names" {
  let key = @jwk.Jwk::parse(okp[:])
  match key.material() {
    Okp(x~, secret~, ..) => {
      let sk = @ed25519.PrivateKey::new(secret.unwrap()[:])
      let pk = @ed25519.PublicKey::new(x[:])
      assert_eq(sk.public().bytes(), pk.bytes())
      let sig = sk.sign(b"a message"[:])
      assert_true(pk.verify(b"a message"[:], sig[:]))
    }
    _ => fail("the OKP key did not read as one")
  }
}

///|
/// Writing a key back leaves the private part out unless asked, because the
/// usual reason to write one is to publish it.
test "writing a key does not publish the secret" {
  let key = @jwk.Jwk::parse(okp[:])
  let published = @json.write(key.json())
  assert_eq(
    published, "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}",
  )
  assert_false(@jwk.Jwk::read(key.json()).is_private())
  let whole = @json.write(key.json(secret=true))
  assert_true(@jwk.Jwk::read(@json.parse(whole[:])).is_private())
  // And the round trip is exact.
  assert_eq(@jwk.Jwk::read(@json.parse(whole[:])).material(), key.material())
}

///|
/// Choosing a key out of a set: by `kid` when the token names one, otherwise
/// only when there is no ambiguity.
test "picking a key from a set" {
  let set = @jwk.Set::parse(public_set[:])
  assert_true(set.pick(alg="RS256", id="2011-04-29") is Some(_))
  // `kid` "1" is marked for encryption, so it is not a signing candidate.
  assert_true(set.pick(alg="RS256", id="1") is None)
  assert_true(set.pick(alg="RS256", id="nobody") is None)
  // Without a `kid`: the EC key is out because of `use`, leaving one.
  assert_true(set.pick(alg="RS256") is Some(_))
  // A key that names another algorithm is not a candidate.
  assert_true(set.pick(alg="ES256") is None)
  // Two candidates and no `kid` is an ambiguity, not a coin toss.
  let two =
    #|{"keys":[{"kty":"oct","k":"AAAA","kid":"a"},{"kty":"oct","k":"BBBB","kid":"b"}]}
  let ambiguous = @jwk.Set::parse(two[:])
  assert_true(ambiguous.pick(alg="HS256") is None)
  assert_true(ambiguous.pick(alg="HS256", id="b") is Some(_))
}

///|
/// A set skips what it cannot read rather than failing, which is what RFC 7517
/// §5.1 says and what lets a set grow a key type an old verifier never heard of.
test "an unknown key type is skipped, not fatal" {
  let mixed =
    #|{"keys":[{"kty":"MLDSA","pub":"…"},{"kty":"oct","k":"AAAA","kid":"known"}]}
  let set = @jwk.Set::parse(mixed[:])
  assert_eq(set.keys().length(), 1)
  assert_eq(set.keys()[0].id(), Some("known"))
}

///|
/// What a single key must refuse.
test "a malformed key is refused" {
  try @jwk.Jwk::parse("[1]") |> ignore catch {
    e => assert_true(e is Shape(_))
  } noraise {
    _ => fail("an array was read as a key")
  }
  try @jwk.Jwk::parse("{\"kty\":\"RSA\",\"e\":\"AQAB\"}") |> ignore catch {
    e => assert_eq(e, Missing(field="n"))
  } noraise {
    _ => fail("an RSA key with no modulus was accepted")
  }
  try
    @jwk.Jwk::parse("{\"kty\":\"oct\",\"k\":\"not base64!!\"}") |> ignore
  catch {
    e => assert_eq(e, NotBase64(field="k"))
  } noraise {
    _ => fail("a key that is not base64url was accepted")
  }
  try @jwk.Jwk::parse("{\"kty\":\"SM2\"}") |> ignore catch {
    e => assert_eq(e, Unknown(kty="SM2"))
  } noraise {
    _ => fail("an unknown key type was accepted")
  }
  try @jwk.Set::parse("{}") |> ignore catch {
    e => assert_true(e is Shape(_))
  } noraise {
    _ => fail("a set with no keys array was accepted")
  }
}

///|
/// `key_ops`, which narrows a key the way `use` does.
test "key_ops narrows a key" {
  let set =
    #|{"keys":[{"kty":"oct","k":"AAAA","kid":"wrapping","key_ops":["wrapKey"]},
    #|         {"kty":"oct","k":"BBBB","kid":"signing","key_ops":["sign","verify"]}]}
  let keys = @jwk.Set::parse(set[:])
  assert_eq(keys.keys()[0].ops(), ["wrapKey"])
  assert_true(keys.pick(alg="HS256", id="wrapping") is None)
  assert_true(keys.pick(alg="HS256", id="signing") is Some(_))
  assert_true(keys.pick(alg="HS256") is Some(_))
}

///|
/// Reading a set skips what it cannot understand by default, which is what
/// RFC 7517 §5.1 says; `skip=false` is how a caller asks to hear about it.
test "skipping unknown keys is a knob" {
  let mixed =
    #|{"keys":[{"kty":"MLDSA","pub":"…"},{"kty":"oct","k":"AAAA","kid":"known"}]}
  assert_eq(@jwk.Set::parse(mixed[:]).keys().length(), 1)
  try @jwk.Set::parse(mixed[:], skip=false) |> ignore catch {
    e => assert_eq(e, Unknown(kty="MLDSA"))
  } noraise {
    _ => fail("an unreadable key passed with skip=false")
  }
}

///|
/// Which `use` a candidate must carry, and what to do when several match: both
/// are the caller's, and both default to the careful answer.
test "picking is a knob" {
  let set = @jwk.Set::parse(public_set[:])
  // `kid` "1" is marked for encryption, so it is out by default…
  assert_true(set.pick(alg="RS256", id="1") is None)
  // …and in when the caller is not filtering on `use`.
  assert_true(set.pick(alg="RS256", id="1", usage=None) is Some(_))
  assert_true(set.pick(alg="ES256", id="1", usage=Some("enc")) is Some(_))
  let two =
    #|{"keys":[{"kty":"oct","k":"AAAA","kid":"a"},{"kty":"oct","k":"BBBB","kid":"b"}]}
  let ambiguous = @jwk.Set::parse(two[:])
  // Two candidates and no `kid`: none by default, the first on request.
  assert_true(ambiguous.pick(alg="HS256") is None)
  assert_eq(ambiguous.pick(alg="HS256", first=true).unwrap().id(), Some("a"))
}
