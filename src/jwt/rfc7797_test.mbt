// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// RFC 7797, "JSON Web Signature (JWS) Unencoded Payload Option". The worked example of §4 is
// the only official vector for a signature over octets that travel as themselves, and it is
// replayed both ways: the published signature is checked, and the same signature is written.

///|
let rfc7797_key : String = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"

///|
let rfc7797_protected : String = "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19"

///|
let rfc7797_signature : String = "A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY"

///|
fn rfc7797_mac() -> &@spec.Verifier {
  let secret = @base64.decode(rfc7797_key[:], kind=Url) catch {
    _ => abort("the example's key is base64url")
  }
  (
    @jwt.mac(fn() { @hmac.Hmac::new(secret[:], fn() { @sha2.Hasher::new() }) }) :
    &@spec.Verifier)
}

///|
/// The same key as a signer: HMAC does both jobs with one key.
fn rfc7797_signer() -> &@spec.Signer {
  let secret = @base64.decode(rfc7797_key[:], kind=Url) catch {
    _ => abort("the example's key is base64url")
  }
  (
    @jwt.mac(fn() { @hmac.Hmac::new(secret[:], fn() { @sha2.Hasher::new() }) }) :
    &@spec.Signer)
}

///|
test "RFC 7797 §4: the published signature verifies, over the payload as itself" {
  let payload = @utf8.encode("$.02")
  let token = rfc7797_protected + ".." + rfc7797_signature
  let got = @jwt.verify_bytes(
    token[:],
    HS256,
    rfc7797_mac(),
    b64=false,
    payload~,
  )
  assert_eq(got, payload)
}

///|
test "RFC 7797 §4: the same signature is written" {
  let payload = @utf8.encode("$.02")
  let token = @jwt.sign_bytes(
    payload,
    HS256,
    rfc7797_signer(),
    b64=false,
    detached=true,
  )
  assert_eq(token, rfc7797_protected + ".." + rfc7797_signature)
}

///|
/// The same signature, carried in the flattened serialisation with the payload as a string:
/// RFC 7797 §4.2 prints it, and the payload member is the payload itself.
test "RFC 7797 §4: the flattened serialisation carries the payload unencoded" {
  let payload = @utf8.encode("$.02")
  let message = @jwt.Message::new(payload).sign(
    HS256,
    rfc7797_signer(),
    b64=false,
  )
  let written = @json.dumps(message.flattened())
  assert_eq(
    written,
    "{\"payload\":\"$.02\",\"protected\":\"" +
    rfc7797_protected +
    "\",\"signature\":\"" +
    rfc7797_signature +
    "\"}",
  )
  let got = @jwt.verify_json(written[:], checks=[
    @jwt.Check::new(HS256, rfc7797_mac()),
  ])
  assert_eq(got.payload, payload)
}

///|
/// A payload with a dot in it cannot travel in the compact form unencoded — the form is cut at
/// its dots — so signing one is refused rather than producing a token nobody can parse.
test "jws: an unencoded payload with a dot is refused in the compact form" {
  let refused = try {
    @jwt.sign_bytes(b"a.b", HS256, rfc7797_signer(), b64=false) |> ignore
    false
  } catch {
    @jwt.Shape(_) => true
    _ => false
  }
  assert_true(refused)
}

///|
/// Non-ASCII octets are refused too: the compact form's other two fields are base64url text,
/// and a payload that is not ASCII cannot be told from them by a reader that splits on dots.
test "jws: an unencoded payload outside ASCII is refused in the compact form" {
  let refused = try {
    @jwt.sign_bytes(b"\xff\xfe", HS256, rfc7797_signer(), b64=false) |> ignore
    false
  } catch {
    @jwt.Shape(_) => true
    _ => false
  }
  assert_true(refused)
}

///|
/// A token that says the payload is unencoded, offered to a reader that expects an encoded one,
/// is refused instead of being read as the other. Both readings verify different octets, so the
/// choice cannot be reconciled after the fact.
test "jws: b64 is part of what the caller and the token have to agree on" {
  let payload = @utf8.encode("arbitrary octets")
  let token = @jwt.sign_bytes(payload, HS256, rfc7797_signer(), b64=false)
  let refused = try {
    @jwt.verify_bytes(token[:], HS256, rfc7797_mac()) |> ignore
    false
  } catch {
    @jwt.Encoding(want~, got~) => want && !got
    _ => false
  }
  assert_true(refused)
  assert_eq(
    @jwt.verify_bytes(token[:], HS256, rfc7797_mac(), b64=false),
    payload,
  )
}

///|
/// RFC 7515 §4.1.11: a critical parameter this reader does not implement means the signature
/// must not be accepted, not that it should be ignored.
test "jws: an unknown critical parameter is refused" {
  let head = @base64.encode(
    @utf8.encode("{\"alg\":\"HS256\",\"crit\":[\"exp\"],\"exp\":1}"),
    kind=Url,
    padding=false,
  )
  let token = head +
    "." +
    @base64.encode(b"payload", kind=Url, padding=false) +
    ".AAAA"
  let refused = try {
    @jwt.verify_bytes(token[:], HS256, rfc7797_mac()) |> ignore
    false
  } catch {
    @jwt.Critical(name~) => name == "exp"
    _ => false
  }
  assert_true(refused)
}
