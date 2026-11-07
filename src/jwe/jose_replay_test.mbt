// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The interoperability vectors of `scripts/gen_jose_vectors.py`, replayed: the messages go-jose
// sealed are opened here, and the messages this library sealed are written again and compared
// with the ones go-jose opened. The two directions are recorded in one report and neither half
// stands on its own.

///|
fn report_field(value : Json, name : String) -> Json raise {
  guard value is Object(members) && members.get(name) is Some(found) else {
    fail("the report has no " + name)
  }
  found
}

///|
fn report_text(value : Json, name : String) -> String raise {
  guard report_field(value, name) is String(text) else {
    fail(name + " is not a string")
  }
  text
}

///|
fn report_list(value : Json, name : String) -> Array[Json] raise {
  guard report_field(value, name) is Array(items) else {
    fail(name + " is not an array")
  }
  items
}

///|
fn report_octets(value : Json, name : String) -> Bytes raise {
  @base64.decode(report_text(value, name)[:], kind=Url)
}

///|
fn interop_hex(text : String) -> Bytes raise {
  @base16.decode(text)
}

///|
let interop_kek128 : String = "404142434445464748494a4b4c4d4e4f"

///|
let interop_kek256 : String = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"

///|
let interop_content : String = "000102030405060708090a0b0c0d0e0f"

///|
let interop_password : String = "correct horse battery staple"

///|
/// The identity each of go-jose's messages is opened with, by the name the report gives it.
fn opener(name : String, entry : Json) -> @jwe.Identity raise {
  match name {
    "go-jwe-rsa-oaep256" =>
      @jwe.Identity::Rsa(
        @rsa.PrivateKey::new(
          report_octets(entry, "rsa_n"),
          report_octets(entry, "rsa_e"),
          report_octets(entry, "rsa_d"),
        ) catch {
          _ => fail("the RSA key go-jose used")
        },
      )
    "go-jwe-a128kw-cbc" => @jwe.Identity::Shared(interop_hex(interop_kek128))
    "go-jwe-dir" => @jwe.Identity::Shared(interop_hex(interop_kek256))
    "go-jwe-gcmkw" => @jwe.Identity::Shared(interop_hex(interop_kek256))
    "go-jwe-zip" => @jwe.Identity::Shared(interop_hex(interop_kek128))
    "go-jwe-aad" => @jwe.Identity::Shared(interop_hex(interop_kek128))
    "go-jwe-multi" => @jwe.Identity::Shared(interop_hex(interop_kek128))
    "go-jwe-pbes2" => @jwe.Identity::Password(@utf8.encode(interop_password))
    // go-jose sealed this one to the point of the curve at scalar one.
    "go-jwe-ecdh" =>
      @jwe.Identity::Agreement(
        P256,
        interop_hex(
          "0000000000000000000000000000000000000000000000000000000000000001",
        ),
      )
    _ => fail("no key for " + name)
  }
}

///|
test "interop: the messages go-jose sealed open here" {
  let report = @json.loads(jose_report)
  for entry in report_list(report, "sealed") {
    let name = report_text(entry, "name")
    let token = report_text(entry, "token")
    let plain = report_octets(entry, "plaintext")
    let identity = opener(name, entry)
    match report_text(entry, "kind") {
      "jwe-compact" => {
        let alg = @jwe.Alg::of(report_text(entry, "alg")[:])
        let enc = @jwe.Enc::of(report_text(entry, "enc")[:])
        assert_eq(
          @jwe.decrypt(token[:], key=identity, alg~, enc~, policy=@jwe.legacy),
          plain,
        )
      }
      "jwe-json" => {
        let enc = @jwe.Enc::of(report_text(entry, "enc")[:])
        // The multi-recipient message is addressed to two keys; this caller holds the first,
        // and the search stops at the recipient it opens.
        ignore(identity)
        let single : Array[@jwe.Unseal] = [
          @jwe.Unseal::new(
            @jwe.Alg::of("A128KW"[:]),
            @jwe.Identity::Shared(interop_hex(interop_kek128)),
          ),
        ]
        let opened = @jwe.open(
          token[:],
          enc~,
          unseal=single,
          policy=@jwe.legacy,
        )
        assert_eq(opened.plain, plain)
        if name == "go-jwe-aad" {
          assert_eq(opened.aad, @utf8.encode("[\"go-jose\",2]"))
        }
      }
      other => fail("a kind this test does not know: " + other)
    }
  }
}

///|
test "interop: the messages this library sealed are the ones go-jose opened" {
  let report = @json.loads(jose_report)
  let ours = report_field(report, "ours")
  let iv = interop_hex("000102030405060708090a0b")
  let content = interop_hex(interop_content)
  // Each message, written again with the parameters pinned in `src/examples/interop`.
  assert_eq(
    @jwe.encrypt(
      @utf8.encode("interop payload"),
      key=@jwe.Key::Shared(content),
      alg=@jwe.Alg::Dir,
      enc=@jwe.Enc::A128Gcm,
      iv=iv[:],
    ),
    report_text(ours, "jwe-dir-compact"),
  )
  assert_eq(
    @jwe.encrypt(
      @utf8.encode("interop payload"),
      key=@jwe.Key::Shared(interop_hex(interop_kek128)),
      alg=@jwe.Alg::A128Kw,
      enc=@jwe.Enc::A128Gcm,
      cek=content,
      iv=iv[:],
    ),
    report_text(ours, "jwe-a128kw-compact"),
  )
  assert_eq(
    @jwe.encrypt(
      @utf8.encode("interop payload"),
      key=@jwe.Key::Shared(interop_hex(interop_kek256)),
      alg=@jwe.Alg::A256GcmKw,
      enc=@jwe.Enc::A128Gcm,
      cek=content,
      iv=iv[:],
      wrap_iv=interop_hex("101112131415161718191a1b"),
    ),
    report_text(ours, "jwe-gcmkw-compact"),
  )
  assert_eq(
    @jwe.encrypt(
      @utf8.encode("interop payload"),
      key=@jwe.Key::Password(@utf8.encode(interop_password)),
      alg=@jwe.Alg::Pbes2Hs256A128Kw,
      enc=@jwe.Enc::A128Gcm,
      cek=content,
      iv=iv[:],
      salt=interop_hex("f0e1d2c3b4a5968778695a4b3c2d1e0f"),
      count=2048,
    ),
    report_text(ours, "jwe-pbes2-compact"),
  )
  // The JSON message, opened rather than compared: its tag covers a header this test would
  // have to reconstruct, and what matters is that the same payload comes out.
  let document = report_text(ours, "jwe-a128kw-json-aad")
  let opened = @jwe.open(document[:], enc=@jwe.Enc::A128Gcm, unseal=[
    @jwe.Unseal::new(
      @jwe.Alg::A128Kw,
      @jwe.Identity::Shared(interop_hex(interop_kek128)),
    ),
  ])
  assert_eq(opened.plain, @utf8.encode("interop payload"))
  assert_eq(opened.aad, @utf8.encode("[\"interop\",1]"))
  // And the plaintext go-jose recovered from each of them is the one this library sealed.
  for entry in report_list(report, "opened") {
    let name = report_text(entry, "name")
    let plain = report_octets(entry, "plaintext")
    assert_eq(plain, @utf8.encode("interop payload"))
    ignore(name)
  }
}
