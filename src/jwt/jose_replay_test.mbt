// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// The JWS half of the interoperability vectors: the signatures go-jose made are verified here,
// and the ones this library made are written again and compared with the ones go-jose verified.

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
let interop_hmac : String = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

///|
let interop_scalar : String = "0000000000000000000000000000000000000000000000000000000000000001"

///|
fn hmac_key() -> &@spec.Verifier {
  let secret = interop_hex(interop_hmac) catch { _ => abort("hex") }
  (
    @jwt.mac(fn() { @hmac.Hmac::new(secret[:], fn() { @sha2.Hasher::new() }) }) :
    &@spec.Verifier)
}

///|
fn hmac_signer() -> &@spec.Signer {
  let secret = interop_hex(interop_hmac) catch { _ => abort("hex") }
  (
    @jwt.mac(fn() { @hmac.Hmac::new(secret[:], fn() { @sha2.Hasher::new() }) }) :
    &@spec.Signer)
}

///|
fn interop_ec() -> @ecdsa.PrivateKey {
  let scalar = interop_hex(interop_scalar) catch { _ => abort("hex") }
  @ecdsa.PrivateKey::with_hash(scalar[:], fn() { @sha2.Hasher::new() }) catch {
    _ => abort("a scalar")
  }
}

///|
test "interop: the signatures go-jose made verify here" {
  let report = @json.loads(jose_report)
  for entry in report_list(report, "sealed") {
    let token = report_text(entry, "token")
    let plain = report_octets(entry, "plaintext")
    let alg = @jwt.Alg::of(report_text(entry, "alg")[:])
    let verifier : &@spec.Verifier = match report_text(entry, "name") {
      "go-jws-rs256" =>
        (
          @rsa.PublicKey::new(
            report_octets(entry, "rsa_n"),
            report_octets(entry, "rsa_e"),
            digest=@rsa.Sha256,
            scheme=@rsa.Pkcs1,
          ) catch {
            _ => fail("the RSA key go-jose used")
          } : &@spec.Verifier)
      "go-jws-es256-json" => (interop_ec().public() : &@spec.Verifier)
      _ => hmac_key()
    }
    let name = report_text(entry, "name")
    if name == "go-jws-b64" {
      // go-jose writes the payload member base64url encoded even under `b64: false`, and
      // RFC 7797 §3 says the payload is then represented as itself. The signature covers the
      // octets, so a reader that follows the RFC and one that follows go-jose cannot both be
      // right; the divergence is recorded in README's conformance section.
      let refused = try {
        @jwt.verify_json(token[:], checks=[@jwt.Check::new(alg, verifier)])
        |> ignore
        false
      } catch {
        @jwt.Signature => true
        _ => false
      }
      assert_true(refused)
      continue
    }
    let got = match report_text(entry, "kind") {
      "jws-compact" =>
        @jwt.verify_bytes(token[:], alg, verifier) catch {
          _ => fail("did not verify " + name)
        }
      "jws-json" => {
        let opened = @jwt.verify_json(token[:], checks=[
          @jwt.Check::new(alg, verifier),
        ]) catch {
          _ => fail("did not verify " + name)
        }
        opened.payload
      }
      "jws-flat" => {
        let opened = @jwt.verify_json(token[:], checks=[
          @jwt.Check::new(alg, verifier),
        ]) catch {
          _ => fail("did not verify " + name)
        }
        opened.payload
      }
      other => fail("a kind this test does not know: " + other)
    }
    assert_eq(got, plain)
  }
}

///|
test "interop: the signatures this library made are the ones go-jose verified" {
  let report = @json.loads(jose_report)
  let ours = report_field(report, "ours")
  let payload = @utf8.encode("{\"iss\":\"moonbitstack\"}")
  assert_eq(
    @jwt.sign_bytes(payload, HS256, hmac_signer()),
    report_text(ours, "jws-hs256"),
  )
  assert_eq(
    @jwt.sign_bytes(b"$.02", HS256, hmac_signer(), b64=false, detached=true),
    report_text(ours, "jws-b64-false"),
  )
  assert_eq(
    @json.dumps(
      @jwt.Message::new(payload)
      .sign(ES256, (interop_ec() : &@spec.Signer))
      .flattened(),
    ),
    report_text(ours, "jws-es256-flat"),
  )
  // And the payload go-jose recovered from each is the one that went in.
  for entry in report_list(report, "opened") {
    let name = report_text(entry, "name")
    let expected = if name == "jws-b64-false" {
      @utf8.encode("$.02")
    } else {
      payload
    }
    assert_eq(report_octets(entry, "plaintext"), expected)
  }
}
