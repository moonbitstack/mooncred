// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// RFC 7520 §4, "JWS Examples". Every example is replayed both ways: the published octets are
// verified with the key the example publishes, and the payload is signed again with that key.
// Where the example records itself as reproducible — its algorithm draws no random nonce —
// the octets this library writes are compared with the ones the RFC prints, byte for byte.
// RSASSA-PSS and ECDSA draw one, so for those two the comparison is that this library's
// signature verifies and the published one does too.

///|
fn field(value : Json, name : String) -> Json raise {
  guard value is Object(members) && members.get(name) is Some(found) else {
    fail("the example has no " + name)
  }
  found
}

///|
fn maybe_field(value : Json, name : String) -> Json? {
  guard value is Object(members) else { return None }
  members.get(name)
}

///|
fn text_of(value : Json, name : String) -> String raise {
  guard field(value, name) is String(text) else {
    fail(name + " is not a string")
  }
  text
}

///|
fn flag_of(value : Json, name : String) -> Bool {
  match maybe_field(value, name) {
    Some(True) => true
    _ => false
  }
}

///|
/// An object without the names the signer writes itself.
fn rest_of(value : Json?, drop : Array[String]) -> Map[String, Json] raise {
  let out : Map[String, Json] = Map([])
  match value {
    Some(Object(members)) =>
      for name, item in members {
        if !drop.contains(name) {
          out[name] = item
        }
      }
    Some(_) => fail("a header is an object")
    None => ()
  }
  out
}

///|
fn header_of(pairs : Array[(String, String)]) -> Map[String, Json] {
  let out : Map[String, Json] = Map([])
  for pair in pairs {
    out[pair.0] = Json::string(pair.1)
  }
  out
}

///|
fn curve_of(name : String) -> @curve.Curve raise {
  match name {
    "P-256" => P256
    "P-384" => P384
    "P-521" => P521
    _ => fail("a curve this example does not use: " + name)
  }
}

///|
fn octets_of(key : Json, name : String) -> Bytes raise {
  @base64.decode(text_of(key, name)[:], kind=Url)
}

///|
fn hash_of(alg : @jwt.Alg) -> () -> &@spec.Hash {
  match alg {
    HS384 | RS384 | PS384 | ES384 => fn() { @sha2.Hasher::new(kind=Sha384) }
    HS512 | RS512 | PS512 | ES512 => fn() { @sha2.Hasher::new(kind=Sha512) }
    _ => fn() { @sha2.Hasher::new() }
  }
}

///|
/// The signer an example's key stands for, under the algorithm it names.
fn signer_of(key : Json, alg : @jwt.Alg) -> &@spec.Signer raise {
  let kty = text_of(key, "kty")
  match kty {
    "oct" => {
      let secret = octets_of(key, "k")
      let hash = hash_of(alg)
      (@jwt.mac(fn() { @hmac.Hmac::new(secret[:], hash) }) : &@spec.Signer)
    }
    "RSA" => {
      let (digest, scheme) = match alg {
        RS256 => (@rsa.Sha256, @rsa.Pkcs1)
        RS384 => (@rsa.Sha384, @rsa.Pkcs1)
        RS512 => (@rsa.Sha512, @rsa.Pkcs1)
        PS256 => (@rsa.Sha256, @rsa.Pss(salt=32))
        PS384 => (@rsa.Sha384, @rsa.Pss(salt=48))
        PS512 => (@rsa.Sha512, @rsa.Pss(salt=64))
        _ => fail("an RSA key does not sign " + alg.name())
      }
      (
        @rsa.PrivateKey::new(
          octets_of(key, "n"),
          octets_of(key, "e"),
          octets_of(key, "d"),
          digest~,
          scheme~,
        ) : &@spec.Signer)
    }
    "EC" =>
      (
        @ecdsa.PrivateKey::with_hash(
          octets_of(key, "d"),
          hash_of(alg),
          curve=curve_of(text_of(key, "crv")),
        ) : &@spec.Signer)
    _ => fail("a key type this example does not use: " + kty)
  }
}

///|
/// The verifier for the same key, built from the public half only.
fn verifier_of(key : Json, alg : @jwt.Alg) -> &@spec.Verifier raise {
  let kty = text_of(key, "kty")
  match kty {
    "oct" => {
      let secret = octets_of(key, "k")
      let hash = hash_of(alg)
      (@jwt.mac(fn() { @hmac.Hmac::new(secret[:], hash) }) : &@spec.Verifier)
    }
    "RSA" => {
      let (digest, scheme) = match alg {
        RS256 => (@rsa.Sha256, @rsa.Pkcs1)
        RS384 => (@rsa.Sha384, @rsa.Pkcs1)
        RS512 => (@rsa.Sha512, @rsa.Pkcs1)
        PS256 => (@rsa.Sha256, @rsa.Pss(salt=32))
        PS384 => (@rsa.Sha384, @rsa.Pss(salt=48))
        PS512 => (@rsa.Sha512, @rsa.Pss(salt=64))
        _ => fail("an RSA key verifies " + alg.name())
      }
      (
        @rsa.PublicKey::new(
          octets_of(key, "n"),
          octets_of(key, "e"),
          digest~,
          scheme~,
        ) : &@spec.Verifier)
    }
    "EC" =>
      (
        @ecdsa.PublicKey::with_hash(
          point_of(key),
          hash_of(alg),
          curve=curve_of(text_of(key, "crv")),
        ) : &@spec.Verifier)
    _ => fail("a key type this example does not use: " + kty)
  }
}

///|
fn signature_at(document : Json, at : Int32) -> Json raise {
  guard field(document, "signatures") is Array(items) else {
    fail("a message has signatures")
  }
  items[at]
}

///|
fn point_of(key : Json) -> Bytes raise {
  @ecdsa.PublicKey::of_xy(
    octets_of(key, "x"),
    octets_of(key, "y"),
    curve=curve_of(text_of(key, "crv")),
  ).bytes()
}

///|
/// The two documents as canonical text, or a line saying where they differ: JSON objects have
/// no order, so comparing the text an example prints is not comparing the values.
fn compare(ours : Json, theirs : Json, number : String) -> String {
  let mine = @json.dumps(ours, sort=true)
  let published = @json.dumps(theirs, sort=true)
  if mine == published {
    ""
  } else {
    number + ": wrote " + mine + ", the example says " + published
  }
}

///|
/// Sign the example's payload the way its `signing` block says, compare what this library
/// writes with what the RFC prints when the example is reproducible, and verify the published
/// octets either way.
fn replay(text : String, number : String) -> Unit raise {
  let example = @json.loads(text)
  let input = field(example, "input")
  let signing = field(example, "signing")
  let output = field(example, "output")
  let payload = @utf8.encode(text_of(input, "payload"))
  let alg = @jwt.Alg::of(text_of(input, "alg")[:])
  let key = field(input, "key")
  let signed_head = maybe_field(signing, "protected")
  let signed = rest_of(signed_head, ["alg"])
  let loose = rest_of(maybe_field(signing, "unprotected"), ["alg"])
  let bare = signed_head is None
  let message = @jwt.Message::new(payload).sign(
    alg,
    signer_of(key, alg),
    signed~,
    header=loose,
    bare~,
  )
  let shape = maybe_field(output, "json")
  let detached = shape is Some(one) && maybe_field(one, "payload") is None
  let written = if detached { message.detached() } else { message }
  if flag_of(example, "reproducible") {
    assert_eq(compare(written.json(), field(output, "json"), number), "")
    if maybe_field(output, "json_flat") is Some(published) {
      assert_eq(compare(written.flattened(), published, number), "")
    }
    if maybe_field(output, "compact") is Some(String(published)) {
      let kid = match signed.get("kid") {
        Some(kid) => kid
        None => Json::null()
      }
      let extra : Map[String, Json] = Map([])
      if kid is Json::String(_) {
        extra["kid"] = kid
      }
      assert_eq(
        @jwt.sign_bytes(payload, alg, signer_of(key, alg), extra~, detached~),
        published,
      )
    }
  }
  // The published octets, read by this library rather than by the one that wrote them.
  if maybe_field(output, "compact") is Some(String(published)) {
    let got = if detached {
      @jwt.verify_bytes(published[:], alg, verifier_of(key, alg), payload~)
    } else {
      @jwt.verify_bytes(published[:], alg, verifier_of(key, alg))
    }
    assert_eq(got, payload)
  }
  for shape in ["json", "json_flat"] {
    if maybe_field(output, shape) is Some(published) {
      let text = @json.dumps(published)
      let check = @jwt.Check::new(alg, verifier_of(key, alg))
      let got = if detached {
        @jwt.verify_json(text[:], checks=[check], payload~)
      } else {
        @jwt.verify_json(text[:], checks=[check])
      }
      assert_eq(got.payload, payload)
    }
  }
}

///|
test "RFC 7520 §4.1: RS256, and the octets the RFC prints" {
  replay(rfc7520_4_1, "4.1")
}

///|
test "RFC 7520 §4.2: PS384" {
  replay(rfc7520_4_2, "4.2")
}

///|
test "RFC 7520 §4.3: ES512" {
  replay(rfc7520_4_3, "4.3")
}

///|
test "RFC 7520 §4.4: HS256, and the octets the RFC prints" {
  replay(rfc7520_4_4, "4.4")
}

///|
test "RFC 7520 §4.5: a payload that travels beside the signature" {
  replay(rfc7520_4_5, "4.5")
}

///|
test "RFC 7520 §4.6: a parameter moved out of the signed header" {
  replay(rfc7520_4_6, "4.6")
}

///|
test "RFC 7520 §4.7: nothing signed but the payload" {
  replay(rfc7520_4_7, "4.7")
}

///|
/// The three signatures of §4.8, each with its own algorithm, key and idea of where the header
/// goes: one with `kid` beside a signed `alg`, one with no signed header at all, one with
/// everything signed. The message is compared with the one the RFC publishes, then each
/// signature is verified on its own.
test "RFC 7520 §4.8: three signatures over one payload" {
  let example = @json.loads(rfc7520_4_8)
  let input = field(example, "input")
  let payload = @utf8.encode(text_of(input, "payload"))
  let keys = match field(input, "key") {
    Array(items) => items
    _ => fail("three keys")
  }
  let message = @jwt.Message::new(payload)
    .sign(
      RS256,
      signer_of(keys[0], RS256),
      header=header_of([("kid", text_of(keys[0], "kid"))]),
    )
    .sign(
      ES512,
      signer_of(keys[1], ES512),
      header=header_of([("alg", "ES512"), ("kid", text_of(keys[1], "kid"))]),
      bare=true,
    )
    .sign(
      HS256,
      signer_of(keys[2], HS256),
      signed=header_of([("kid", text_of(keys[2], "kid"))]),
    )
  let published = field(field(example, "output"), "json")
  // ECDSA draws a private nonce, so its signature differs every time; the two deterministic
  // ones are compared, and the third is checked by verifying it below.
  let ours = message.json()
  for at in [0, 2] {
    assert_eq(
      compare(signature_at(ours, at), signature_at(published, at), "4.8"),
      "",
    )
  }
  assert_eq(@jwt.message(@json.dumps(ours)[:]).signatures().length(), 3)
  let text = @json.dumps(published)
  let checks = [
    @jwt.Check::new(RS256, verifier_of(keys[0], RS256)),
    @jwt.Check::new(ES512, verifier_of(keys[1], ES512)),
    @jwt.Check::new(HS256, verifier_of(keys[2], HS256)),
  ]
  assert_eq(@jwt.verify_json(text[:], checks~).payload, payload)
  // One signature, one key: the index says which of the three the caller's key opened.
  assert_eq(
    @jwt.verify_json(text[:], checks=[
      @jwt.Check::new(RS256, verifier_of(keys[0], RS256)),
    ]).index,
    0,
  )
  assert_eq(
    @jwt.verify_json(text[:], checks=[
      @jwt.Check::new(HS256, verifier_of(keys[2], HS256)),
    ]).index,
    2,
  )
  // A key offered under the wrong algorithm opens nothing.
  let wrong = try {
    @jwt.verify_json(text[:], checks=[
      @jwt.Check::new(HS256, verifier_of(keys[0], RS256)),
    ])
    |> ignore
    false
  } catch {
    @jwt.Signature => true
    _ => false
  }
  assert_true(wrong)
}
