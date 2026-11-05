// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// RFC 7520 §5.6 and §5.8, the two worked examples of the compact serialisation that this
// library writes: the ciphertext each publishes is decrypted with the key it publishes, and the
// plaintext compared with the one it publishes.

///|
fn octets(text : String) -> Bytes raise {
  @base64.decode(text, kind=Url, padding=false)
}

///|
test "RFC 7520 §5.6: direct encryption with AES-GCM" {
  let plain = @jwe.decrypt(
    rfc7520_5_6_token[:],
    key=Shared(octets(rfc7520_5_6_k)),
    alg=Dir,
    enc=A128Gcm,
  )
  assert_eq(@utf8.decode(plain), rfc7520_5_6_plaintext)
}

///|
test "RFC 7520 §5.8: AES key wrap with AES-GCM" {
  let plain = @jwe.decrypt(
    rfc7520_5_8_token[:],
    key=Shared(octets(rfc7520_5_8_k)),
    alg=A128Kw,
    enc=A128Gcm,
  )
  assert_eq(@utf8.decode(plain), rfc7520_5_8_plaintext)
}
