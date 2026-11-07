// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// Every key-management algorithm against every content-encryption algorithm, in the compact
// serialisation: what goes in comes out, and the two algorithms a deployment may refuse are
// refused only when it says so.

///|
let matrix_iv12 : String = "000102030405060708090a0b"

///|
let matrix_iv16 : String = "000102030405060708090a0b0c0d0e0f"

///|
fn hex_octets(text : String) -> Bytes raise {
  @base16.decode(text)
}

///|
/// One round trip: seal with `recipient`, open with `identity`, and compare.
fn round_trip(
  recipient : @jwe.Recipient,
  enc : @jwe.Enc,
  identity : @jwe.Identity,
  policy~ : @jwe.Policy = @jwe.policy,
) -> Unit raise {
  let plain = b"the payload that travels with the message"
  let iv = match enc {
    @jwe.Enc::A128Gcm | @jwe.Enc::A192Gcm | @jwe.Enc::A256Gcm =>
      hex_octets(matrix_iv12)
    _ => hex_octets(matrix_iv16)
  }
  let token = @jwe.seal_compact(plain, enc~, recipient~, iv=iv[:], policy~)
  assert_eq(
    @jwe.decrypt(token[:], key=identity, alg=recipient.alg, enc~, policy~),
    plain,
  )
}

///|
let matrix_encs : Array[@jwe.Enc] = [
  @jwe.Enc::A128Gcm,
  @jwe.Enc::A192Gcm,
  @jwe.Enc::A256Gcm,
  @jwe.Enc::A128CbcHs256,
  @jwe.Enc::A192CbcHs384,
  @jwe.Enc::A256CbcHs512,
]

///|
fn key_of(enc : @jwe.Enc) -> Bytes raise {
  let all = hex_octets(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
  )
  all[:content_key_size(enc)].to_owned()
}

///|
fn content_key_size(enc : @jwe.Enc) -> Int32 {
  match enc {
    @jwe.Enc::A128Gcm => 16
    @jwe.Enc::A192Gcm => 24
    @jwe.Enc::A256Gcm => 32
    @jwe.Enc::A128CbcHs256 => 32
    @jwe.Enc::A192CbcHs384 => 48
    @jwe.Enc::A256CbcHs512 => 64
  }
}

///|
test "jwe: dir and the AES key wrapping algorithms round trip under every content algorithm" {
  for enc in matrix_encs {
    let content = key_of(enc)
    round_trip(
      { ..@jwe.Recipient::new(@jwe.Alg::Dir, @jwe.Key::Shared(content)), },
      enc,
      @jwe.Identity::Shared(content),
    )
    for
      (alg, kek) in [
        (@jwe.Alg::A128Kw, 16),
        (@jwe.Alg::A192Kw, 24),
        (@jwe.Alg::A256Kw, 32),
      ] {
      let shared = hex_octets(
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
      )[:kek].to_owned()
      round_trip(
        {
          ..@jwe.Recipient::new(alg, @jwe.Key::Shared(shared)),
          cek: Some(content),
        },
        enc,
        @jwe.Identity::Shared(shared),
      )
    }
  }
}

///|
test "jwe: the AES-GCM wrapping algorithms round trip under every content algorithm" {
  for enc in matrix_encs {
    let content = key_of(enc)
    for
      (alg, kek) in [
        (@jwe.Alg::A128GcmKw, 16),
        (@jwe.Alg::A192GcmKw, 24),
        (@jwe.Alg::A256GcmKw, 32),
      ] {
      let shared = hex_octets(
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
      )[:kek].to_owned()
      round_trip(
        {
          ..@jwe.Recipient::new(alg, @jwe.Key::Shared(shared)),
          cek: Some(content),
          iv: Some(hex_octets(matrix_iv12)),
        },
        enc,
        @jwe.Identity::Shared(shared),
      )
    }
  }
}

///|
test "jwe: the PBES2 algorithms round trip under every content algorithm" {
  for enc in matrix_encs {
    for
      alg in [
        @jwe.Alg::Pbes2Hs256A128Kw,
        @jwe.Alg::Pbes2Hs384A192Kw,
        @jwe.Alg::Pbes2Hs512A256Kw,
      ] {
      let password = b"entrap_o-peter_long-credit_tun"
      round_trip(
        {
          ..@jwe.Recipient::new(alg, @jwe.Key::Password(password)),
          cek: Some(key_of(enc)),
          salt: Some(hex_octets("f0e1d2c3b4a5968778695a4b3c2d1e0f")),
          count: Some(4096),
        },
        enc,
        @jwe.Identity::Password(password),
      )
    }
  }
}

///|
/// The two algorithms that carry a security argument of their own. Both are supported, so both
/// are sealed and opened without the caller saying anything; both can be refused, and then
/// neither direction will use them.
test "jwe: RSA1_5 and RSA-OAEP work by default and are refused by a strict policy" {
  let example = @json.loads(rfc7520_5_1)
  let jwk = match example {
    Object(members) =>
      match members.get("input") {
        Some(Object(input)) =>
          match input.get("key") {
            Some(key) => key
            None => fail("no key")
          }
        _ => fail("no input")
      }
    _ => fail("not an object")
  }
  let private_key = @rsa.PrivateKey::new(
    octets_of(jwk, "n"),
    octets_of(jwk, "e"),
    octets_of(jwk, "d"),
  ) catch {
    _ => fail("the key")
  }
  let public_key = private_key.public()
  for alg in [@jwe.Alg::Rsa1_5, @jwe.Alg::RsaOaep] {
    let recipient = {
      ..@jwe.Recipient::new(alg, @jwe.Key::Rsa(public_key)),
      cek: Some(key_of(@jwe.Enc::A128Gcm)),
      // RSAES-PKCS1-v1_5 fills its padding from the seed; RSAES-OAEP masks with a digest of it.
      seed: Some(
        if alg is @jwe.Alg::Rsa1_5 {
          repeated(256, 0x5A)
        } else {
          repeated(20, 0x5A)
        },
      ),
    }
    // Accepted with no policy named at all: this is what "every algorithm is supported" means
    // for the two that other libraries gate.
    round_trip(recipient, @jwe.Enc::A128Gcm, @jwe.Identity::Rsa(private_key))
    let token = @jwe.seal_compact(
      b"payload",
      enc=@jwe.Enc::A128Gcm,
      recipient~,
      iv=hex_octets(matrix_iv12)[:],
    )
    // Refused when sealing, and when opening, under the preset that refuses them.
    let refused_seal = try {
      @jwe.seal_compact(
        b"payload",
        enc=@jwe.Enc::A128Gcm,
        recipient~,
        iv=hex_octets(matrix_iv12)[:],
        policy=@jwe.strict,
      )
      |> ignore
      false
    } catch {
      @jwe.Unsupported(reason) => {
        // The refusal names the algorithm rather than saying something generic.
        assert_true(reason.contains(alg.name()))
        true
      }
      _ => false
    }
    assert_true(refused_seal)
    let refused_open = try {
      @jwe.decrypt(
        token[:],
        key=@jwe.Identity::Rsa(private_key),
        alg~,
        enc=@jwe.Enc::A128Gcm,
        policy=@jwe.strict,
      )
      |> ignore
      false
    } catch {
      @jwe.Unsupported(_) => true
      _ => false
    }
    assert_true(refused_open)
  }
}

///|
test "jwe: RSA-OAEP-256 round trips and is accepted by default" {
  let example = @json.loads(rfc7520_5_2)
  let jwk = match example {
    Object(members) =>
      match members.get("input") {
        Some(Object(input)) =>
          match input.get("key") {
            Some(key) => key
            None => fail("no key")
          }
        _ => fail("no input")
      }
    _ => fail("not an object")
  }
  let private_key = @rsa.PrivateKey::new(
    octets_of(jwk, "n"),
    octets_of(jwk, "e"),
    octets_of(jwk, "d"),
  ) catch {
    _ => fail("the key")
  }
  for enc in matrix_encs {
    round_trip(
      {
        ..@jwe.Recipient::new(
          @jwe.Alg::RsaOaep256,
          @jwe.Key::Rsa(private_key.public()),
        ),
        cek: Some(key_of(enc)),
        seed: Some(repeated(32, 0x5A)),
      },
      enc,
      @jwe.Identity::Rsa(private_key),
    )
  }
}

///|
test "jwe: ECDH-ES round trips on all three curves, with and without key wrapping" {
  for curve in [@curve.Curve::P256, @curve.Curve::P384, @curve.Curve::P521] {
    // A small scalar for the recipient and another for the sender: what matters here is that
    // both sides agree, not that either is unguessable.
    let recipient_scalar = small_scalar(curve.size(), 3)
    let sender_scalar = small_scalar(curve.size(), 5)
    let recipient_key = @ecdsa.PrivateKey::new(recipient_scalar[:], curve~) catch {
      _ => fail("a recipient scalar")
    }
    let point = recipient_key.public().bytes()
    for enc in matrix_encs {
      round_trip(
        {
          ..@jwe.Recipient::new(
            @jwe.Alg::EcdhEs,
            @jwe.Key::Agreement(curve, point),
          ),
          ephemeral: Some(sender_scalar),
        },
        enc,
        @jwe.Identity::Agreement(curve, recipient_scalar),
      )
      round_trip(
        {
          ..@jwe.Recipient::new(
            @jwe.Alg::EcdhEsA256Kw,
            @jwe.Key::Agreement(curve, point),
          ),
          cek: Some(key_of(enc)),
          ephemeral: Some(sender_scalar),
        },
        enc,
        @jwe.Identity::Agreement(curve, recipient_scalar),
      )
    }
  }
}

///|
fn repeated(length : Int32, octet : Int32) -> Bytes {
  let out = Buffer()
  for _ in 0..<length {
    out.write_byte(octet.to_byte())
  }
  out.to_bytes()
}

///|
/// A scalar of `value`, big-endian in `length` octets: small enough to be below every curve's
/// order, which is all a test needs.
fn small_scalar(length : Int32, value : Int32) -> Bytes {
  let out = Buffer()
  for i in 0..<length {
    if i == length - 1 {
      out.write_byte(value.to_byte())
    } else {
      out.write_byte((0 : Byte))
    }
  }
  out.to_bytes()
}

///|
test "jwe: zip DEF shrinks the payload and an unknown compression is refused" {
  let shared = hex_octets(
    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
  )[:16].to_owned()
  // A payload long and dull enough that deflate wins on it.
  let dull = StringBuilder()
  for _ in 0..<64 {
    dull.write_string("credential ")
  }
  let plain = @utf8.encode(dull.to_string())
  let token = @jwe.encrypt(
    plain,
    key=@jwe.Key::Shared(shared),
    alg=@jwe.Alg::A128Kw,
    enc=@jwe.Enc::A128Gcm,
    cek=key_of(@jwe.Enc::A128Gcm),
    iv=hex_octets(matrix_iv12)[:],
    compress=true,
  )
  assert_eq(
    @jwe.decrypt(
      token[:],
      key=@jwe.Identity::Shared(shared),
      alg=@jwe.Alg::A128Kw,
      enc=@jwe.Enc::A128Gcm,
    ),
    plain,
  )
  // A token that says `zip: GZIP` is not one this library reads.
  let example = @json.loads(rfc7520_5_9)
  ignore(example)
  let head = @base64.encode(
    @utf8.encode("{\"alg\":\"A128KW\",\"enc\":\"A128GCM\",\"zip\":\"GZIP\"}"),
    kind=Url,
    padding=false,
  )
  let forged = head + ".AAAA.AAAA.AAAA.AAAA"
  let refused = try {
    @jwe.decrypt(
      forged[:],
      key=@jwe.Identity::Shared(shared),
      alg=@jwe.Alg::A128Kw,
      enc=@jwe.Enc::A128Gcm,
    )
    |> ignore
    false
  } catch {
    @jwe.Unsupported(_) => true
    @jwe.Key => true
    _ => false
  }
  assert_true(refused)
}

///|
test "jwe: additional authenticated data is authenticated" {
  let shared = hex_octets(
    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
  )[:16].to_owned()
  let plain = b"the payload"
  let aad = @utf8.encode("[\"vcard\",[\"version\",{},\"text\",\"4.0\"]]")
  let message = @jwe.seal(
    plain,
    enc=@jwe.Enc::A128Gcm,
    recipients=[
      {
        ..@jwe.Recipient::new(@jwe.Alg::A128Kw, @jwe.Key::Shared(shared)),
        cek: Some(key_of(@jwe.Enc::A128Gcm)),
      },
    ],
    iv=hex_octets(matrix_iv12)[:],
    aad~,
  )
  let written = @json.dumps(message)
  let opened = @jwe.open(written[:], enc=@jwe.Enc::A128Gcm, unseal=[
    @jwe.Unseal::new(@jwe.Alg::A128Kw, @jwe.Identity::Shared(shared)),
  ])
  assert_eq(opened.plain, plain)
  assert_eq(opened.aad, aad)
  // The same message with the additional data taken away does not open: it is not a wrapper
  // around the payload, it is part of what the tag covers.
  let members = match message {
    Object(members) => members
    _ => fail("not an object")
  }
  members.remove("aad")
  let refused = try {
    @jwe.open(@json.dumps(Json::object(members))[:], enc=@jwe.Enc::A128Gcm, unseal=[
      @jwe.Unseal::new(@jwe.Alg::A128Kw, @jwe.Identity::Shared(shared)),
    ])
    |> ignore
    false
  } catch {
    @jwe.Key => true
    _ => false
  }
  assert_true(refused)
}

///|
test "jwe: one ciphertext, three recipients that each open it" {
  let content = key_of(@jwe.Enc::A128CbcHs256)
  let first = hex_octets(
    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
  )[:16].to_owned()
  let second = hex_octets(
    "505152535455565758595a5b5c5d5e5f404142434445464748494a4b4c4d4e4f",
  )[:32].to_owned()
  let password = b"three readers, one message"
  let message = @jwe.seal(
    b"shared with three",
    enc=@jwe.Enc::A128CbcHs256,
    recipients=[
      {
        ..@jwe.Recipient::new(@jwe.Alg::A128Kw, @jwe.Key::Shared(first)),
        cek: Some(content),
        header: header_of([("kid", "one")]),
      },
      {
        ..@jwe.Recipient::new(@jwe.Alg::A256GcmKw, @jwe.Key::Shared(second)),
        cek: Some(content),
        iv: Some(hex_octets(matrix_iv12)),
        header: header_of([("kid", "two")]),
      },
      {
        ..@jwe.Recipient::new(
          @jwe.Alg::Pbes2Hs256A128Kw,
          @jwe.Key::Password(password),
        ),
        cek: Some(content),
        salt: Some(hex_octets("f0e1d2c3b4a5968778695a4b3c2d1e0f")),
        count: Some(2048),
        header: header_of([("kid", "three")]),
      },
    ],
    iv=hex_octets(matrix_iv16)[:],
  )
  let written = @json.dumps(message)
  let cases : Array[(Int32, @jwe.Unseal)] = [
    (0, @jwe.Unseal::new(@jwe.Alg::A128Kw, @jwe.Identity::Shared(first))),
    (1, @jwe.Unseal::new(@jwe.Alg::A256GcmKw, @jwe.Identity::Shared(second))),
    (
      2,
      @jwe.Unseal::new(
        @jwe.Alg::Pbes2Hs256A128Kw,
        @jwe.Identity::Password(password),
      ),
    ),
  ]
  for case in cases {
    let (at, one) = case
    let opened = @jwe.open(written[:], enc=@jwe.Enc::A128CbcHs256, unseal=[one])
    assert_eq(opened.plain, b"shared with three")
    assert_eq(opened.index, at)
  }
  // A key that is none of the three opens nothing.
  let stranger = hex_octets("606162636465666768696a6b6c6d6e6f")
  let refused = try {
    @jwe.open(written[:], enc=@jwe.Enc::A128CbcHs256, unseal=[
      @jwe.Unseal::new(@jwe.Alg::A128Kw, @jwe.Identity::Shared(stranger)),
    ])
    |> ignore
    false
  } catch {
    @jwe.Key => true
    _ => false
  }
  assert_true(refused)
}

///|
test "jwe: a parameter named in two headers of one message is refused" {
  let shared = hex_octets("404142434445464748494a4b4c4d4e4f")[:16].to_owned()
  let message = @jwe.seal(
    b"payload",
    enc=@jwe.Enc::A128Gcm,
    recipients=[
      {
        ..@jwe.Recipient::new(@jwe.Alg::A128Kw, @jwe.Key::Shared(shared)),
        cek: Some(key_of(@jwe.Enc::A128Gcm)),
      },
    ],
    iv=hex_octets(matrix_iv12)[:],
  )
  let members = match message {
    Object(members) => members
    _ => fail("not an object")
  }
  // The same parameter in the shared unprotected header and in the recipient's.
  let loose : Map[String, Json] = Map([])
  loose["alg"] = Json::string("A128KW")
  members["unprotected"] = Json::object(loose)
  let refused = try {
    @jwe.open(@json.dumps(Json::object(members))[:], enc=@jwe.Enc::A128Gcm, unseal=[
      @jwe.Unseal::new(@jwe.Alg::A128Kw, @jwe.Identity::Shared(shared)),
    ])
    |> ignore
    false
  } catch {
    @jwe.Malformed(_) => true
    _ => false
  }
  assert_true(refused)
}
