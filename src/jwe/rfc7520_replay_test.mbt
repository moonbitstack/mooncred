// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// RFC 7520 §5, "JWE Examples". Every one of the thirteen is opened: the octets the RFC prints,
// in each serialisation it prints them in, under the key it publishes. Where the example is
// reproducible — the encrypted key is a function of the content key and the parameters the
// example publishes — the message is message again and compared byte for byte with what the RFC
// prints. The others draw a nonce the RFC does not publish (RSA's padding, an OAEP seed, an
// ephemeral scalar, a DEFLATE stream), so what can be checked is that they open.

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
fn octets_of(key : Json, name : String) -> Bytes raise {
  @base64.decode(text_of(key, name)[:], kind=Url)
}

///|
/// The content key the example used, which is what makes a reproducible example reproducible.
fn content_key_of(example : Json, enc : @jwe.Enc) -> Bytes raise {
  let generated = field(example, "generated")
  ignore(enc)
  octets_of(generated, "cek")
}

///|
fn iv_of(example : Json) -> Bytes raise {
  octets_of(field(example, "generated"), "iv")
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
/// What a token is message to, from the key the example publishes.
fn seal_key_of(jwk : Json) -> @jwe.Key raise {
  match text_of(jwk, "kty") {
    "oct" => @jwe.Key::Shared(octets_of(jwk, "k"))
    "RSA" =>
      @jwe.Key::Rsa(
        @rsa.PublicKey::new(octets_of(jwk, "n"), octets_of(jwk, "e")) catch {
          _ => fail("the example's RSA key")
        },
      )
    "EC" =>
      @jwe.Key::Agreement(
        curve_of(text_of(jwk, "crv")),
        @ecdsa.PublicKey::of_xy(
          octets_of(jwk, "x"),
          octets_of(jwk, "y"),
          curve=curve_of(text_of(jwk, "crv")),
        ).bytes() catch {
          _ => fail("the example's EC key")
        },
      )
    other => fail("a key type this example does not use: " + other)
  }
}

///|
/// What a token is opened with.
fn identity_of(jwk : Json) -> @jwe.Identity raise {
  match text_of(jwk, "kty") {
    "oct" => @jwe.Identity::Shared(octets_of(jwk, "k"))
    "RSA" =>
      @jwe.Identity::Rsa(
        @rsa.PrivateKey::new(
          octets_of(jwk, "n"),
          octets_of(jwk, "e"),
          octets_of(jwk, "d"),
        ) catch {
          _ => fail("the example's RSA key")
        },
      )
    "EC" =>
      @jwe.Identity::Agreement(
        curve_of(text_of(jwk, "crv")),
        octets_of(jwk, "d"),
      )
    other => fail("a key type this example does not use: " + other)
  }
}

///|
/// The identity an example opens with: its key, or its password.
fn opener_of(input : Json) -> @jwe.Identity raise {
  match maybe_field(input, "key") {
    Some(jwk) => identity_of(jwk)
    None => @jwe.Identity::Password(@utf8.encode(text_of(input, "pwd")))
  }
}

///|
/// The key an example seals to.
fn sealer_of(input : Json) -> @jwe.Key raise {
  match maybe_field(input, "key") {
    Some(jwk) => seal_key_of(jwk)
    None => @jwe.Key::Password(@utf8.encode(text_of(input, "pwd")))
  }
}

///|
/// Open every serialisation the example publishes, and compare the plaintext.
fn replay_jwe(text : String, number : String) -> Unit raise {
  let example = @json.loads(text)
  let input = field(example, "input")
  let output = field(example, "output")
  let plain = @utf8.encode(text_of(input, "plaintext"))
  let enc = @jwe.Enc::of(text_of(input, "enc")[:])
  let alg = @jwe.Alg::of(text_of(input, "alg")[:])
  let identity = opener_of(input)
  // The two legacy key-management algorithms are in RFC 7520 and refused by default, so the
  // examples are opened under the policy that accepts them.
  if maybe_field(output, "compact") is Some(String(token)) {
    assert_eq(
      @jwe.decrypt(token[:], key=identity, alg~, enc~, policy=@jwe.legacy),
      plain,
    )
  }
  for shape in ["json", "json_flat"] {
    if maybe_field(output, shape) is Some(document) {
      let written = @json.dumps(document)
      let opened = @jwe.open(
        written[:],
        enc~,
        unseal=[@jwe.Unseal::new(alg, identity)],
        policy=@jwe.legacy,
      )
      assert_eq(opened.plain, plain)
      ignore(number)
    }
  }
}

///|
/// Seal a reproducible example again and compare the compact serialisation with the one the RFC
/// prints, part for part and octet for octet.
fn reseal_jwe(text : String, number : String) -> Unit raise {
  let example = @json.loads(text)
  let input = field(example, "input")
  let output = field(example, "output")
  let plain = @utf8.encode(text_of(input, "plaintext"))
  let enc = @jwe.Enc::of(text_of(input, "enc")[:])
  let alg = @jwe.Alg::of(text_of(input, "alg")[:])
  let published = match maybe_field(output, "compact") {
    Some(String(token)) => token
    _ => fail(number + " has no compact serialisation")
  }
  // The header the example publishes carries the parameters this seal needs back: the PBES2
  // salt and count, the nonce of an AES-GCM wrap, and the name of the recipient.
  let head = @base64.decode(token_head(published)[:], kind=Url) catch {
    _ => fail("the header")
  }
  let header = @json.loads(@utf8.decode(head)) catch { _ => fail("the header") }
  let fields = match header {
    Object(fields) => fields
    _ => fail("the header")
  }
  let recipient = @jwe.Recipient::new(alg, sealer_of(input))
  let mut one = { ..recipient, header: fields, cek: None, }
  if !(alg is @jwe.Alg::Dir) {
    one = { ..one, cek: Some(content_key_of(example, enc)), }
  }
  if fields.get("p2s") is Some(String(salt)) {
    one = {
      ..one,
      salt: Some(@base64.decode(salt[:], kind=Url) catch { _ => fail("p2s") }),
      count: Some(
        match fields.get("p2c") {
          Some(Number(value, ..)) => value.to_int()
          _ => fail("p2c")
        },
      ),
    }
  }
  if fields.get("iv") is Some(String(nonce)) {
    one = {
      ..one,
      iv: Some(@base64.decode(nonce[:], kind=Url) catch { _ => fail("iv") }),
    }
  }
  let written = @jwe.seal_compact(
    plain,
    enc~,
    recipient=one,
    iv=iv_of(example)[:],
    policy=@jwe.legacy,
  )
  assert_eq(written, published)
}

///|
/// Seal an example again into the JSON serialisation and compare the whole document with the
/// one the RFC prints. The three examples this is used for differ only in where the two
/// algorithm parameters are placed, which is what `layout` and `shared` say.
fn reseal_json(
  text : String,
  number : String,
  layout : @jwe.Layout,
  shared_fields : Array[(String, String)],
) -> Unit raise {
  let example = @json.loads(text)
  let input = field(example, "input")
  let output = field(example, "output")
  let plain = @utf8.encode(text_of(input, "plaintext"))
  let enc = @jwe.Enc::of(text_of(input, "enc")[:])
  let alg = @jwe.Alg::of(text_of(input, "alg")[:])
  let jwk = match maybe_field(input, "key") {
    Some(jwk) => jwk
    None => fail(number + " has no key")
  }
  let shared : Map[String, Json] = Map([])
  for pair in shared_fields {
    shared[pair.0] = Json::string(pair.1)
  }
  let aad = match maybe_field(input, "aad") {
    Some(String(text)) => @utf8.encode(text)
    Some(_) => fail("aad is a string")
    None => b""
  }
  let recipient = {
    ..@jwe.Recipient::new(alg, seal_key_of(jwk)),
    header: header_of([("kid", text_of(jwk, "kid"))]),
    cek: Some(content_key_of(example, enc)),
  }
  let message = @jwe.seal(
    plain,
    enc~,
    recipients=[recipient],
    iv=iv_of(example)[:],
    aad~,
    shared~,
    layout~,
    policy=@jwe.legacy,
  )
  let published = field(output, "json")
  assert_eq(@json.dumps(message, sort=true), @json.dumps(published, sort=true))
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
fn token_head(token : String) -> String {
  let out = StringBuilder()
  for c in token {
    if c == '.' {
      break
    }
    out.write_char(c)
  }
  out.to_string()
}

///|
test "RFC 7520 §5.1: RSA1_5 and AES-CBC-HMAC-SHA2" {
  replay_jwe(rfc7520_5_1, "5.1")
}

///|
test "RFC 7520 §5.2: RSA-OAEP and AES-GCM" {
  replay_jwe(rfc7520_5_2, "5.2")
}

///|
test "RFC 7520 §5.3: PBES2, message again octet for octet" {
  replay_jwe(rfc7520_5_3, "5.3")
  reseal_jwe(rfc7520_5_3, "5.3")
}

///|
test "RFC 7520 §5.4: ECDH-ES with key wrapping" {
  replay_jwe(rfc7520_5_4, "5.4")
}

///|
test "RFC 7520 §5.5: ECDH-ES with a derived content key" {
  replay_jwe(rfc7520_5_5, "5.5")
}

///|
test "RFC 7520 §5.6: direct encryption, message again octet for octet" {
  replay_jwe(rfc7520_5_6, "5.6")
  reseal_jwe(rfc7520_5_6, "5.6")
}

///|
test "RFC 7520 §5.7: AES-GCM key wrapping, message again octet for octet" {
  replay_jwe(rfc7520_5_7, "5.7")
  reseal_jwe(rfc7520_5_7, "5.7")
}

///|
test "RFC 7520 §5.8: AES key wrapping, message again octet for octet" {
  replay_jwe(rfc7520_5_8, "5.8")
  reseal_jwe(rfc7520_5_8, "5.8")
}

///|
test "RFC 7520 §5.9: compressed content" {
  replay_jwe(rfc7520_5_9, "5.9")
}

///|
test "RFC 7520 §5.10: additional authenticated data, message again" {
  replay_jwe(rfc7520_5_10, "5.10")
  reseal_json(rfc7520_5_10, "5.10", @jwe.Layout::Protected, [])
}

///|
test "RFC 7520 §5.11: header parameters moved out of the protected header, message again" {
  replay_jwe(rfc7520_5_11, "5.11")
  reseal_json(rfc7520_5_11, "5.11", @jwe.Layout::Recipient, [
    ("alg", "A128KW"),
    ("kid", "81b20965-8332-43d9-a468-82160ad91ac8"),
  ])
}

///|
test "RFC 7520 §5.12: nothing protected, message again" {
  replay_jwe(rfc7520_5_12, "5.12")
  reseal_json(rfc7520_5_12, "5.12", @jwe.Layout::Bare, [
    ("alg", "A128KW"),
    ("kid", "81b20965-8332-43d9-a468-82160ad91ac8"),
    ("enc", "A128GCM"),
  ])
}

///|
/// Three recipients, each with its own key-management algorithm and its own key. The content
/// encryption is read from the message rather than from the example's `enc`, which the
/// cookbook records with a name no RFC defines; the algorithms come from each recipient's
/// header, and each is opened with the key at the same position in the list.
test "RFC 7520 §5.13: three recipients, three key-management algorithms" {
  let example = @json.loads(rfc7520_5_13)
  let input = field(example, "input")
  let output = field(example, "output")
  let plain = @utf8.encode(text_of(input, "plaintext"))
  let document = field(output, "json")
  let head = @json.loads(
    @utf8.decode(@base64.decode(text_of(document, "protected")[:], kind=Url)),
  ) catch {
    _ => fail("the protected header")
  }
  let enc = @jwe.Enc::of(text_of(head, "enc")[:])
  let keys = match field(input, "key") {
    Array(items) => items
    _ => fail("three keys")
  }
  let entries = match field(document, "recipients") {
    Array(items) => items
    _ => fail("three recipients")
  }
  let unseal : Array[@jwe.Unseal] = []
  let mut at = 0
  for entry in entries {
    let header = field(entry, "header")
    unseal.push(
      @jwe.Unseal::new(
        @jwe.Alg::of(text_of(header, "alg")[:]),
        identity_of(keys[at]),
      ),
    )
    at += 1
  }
  let written = @json.dumps(document)
  // The first recipient is the one this caller holds, and it opens; the other two are offered
  // as well and do not.
  let opened = @jwe.open(written[:], enc~, unseal~, policy=@jwe.legacy)
  assert_eq(opened.plain, plain)
  assert_eq(opened.index, 0)
  // A message opened by its second recipient says so.
  let second = @jwe.open(
    written[:],
    enc~,
    unseal=[
      @jwe.Unseal::new(@jwe.Alg::of("ECDH-ES+A256KW"[:]), identity_of(keys[1])),
    ],
    policy=@jwe.legacy,
  )
  assert_eq(second.plain, plain)
  assert_eq(second.index, 1)
}
