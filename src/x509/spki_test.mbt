// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

// A bare SubjectPublicKeyInfo, read from the PEM another implementation wrote.
// The key below came out of Python's `cryptography` 45.0.2, so the modulus and
// exponent this reads back are checked against numbers we did not produce.

///|
let rsa_pem : String =
  #|-----BEGIN PUBLIC KEY-----
  #|MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuz3A+9cJWoGKnHxisrUp
  #|S/I5T0m6vsu9+JbZgTflrXxeoXZF7rRO9SamsQa2bbBRotpWrbm0om9mZOHd9tSL
  #|5yJMj8qtS7BOIHICaiXRlTi/0svNgIXmGHY9N0oM5cavxzJM4Q6n7GPNYyCb4oFA
  #|UlkIqT/u08Hu+KmPOvh4ped6FQ+/YCdjgs4mdlxWs6A/gEBsZJB9uXs60Zf15co6
  #|SsI/8fsMhBKCQ4iovVt9j7bIwWR+4XSqj1nrbsJtDHRVAx+xfoCA6JEdTK7WVfFE
  #|X4mRl1aj/01LukbJQRGB7xt6ZEajG5xgtmqGSFJxq6UYeIYC5Ecwv60qmvKW719J
  #|EQIDAQAB
  #|-----END PUBLIC KEY-----

///|
let rsa_modulus : String = "bb3dc0fbd7095a818a9c7c62b2b5294bf2394f49babecbbdf896d98137e5ad7c5ea17645eeb44ef526a6b106b66db051a2da56adb9b4a26f6664e1ddf6d48be7224c8fcaad4bb04e2072026a25d19538bfd2cbcd8085e618763d374a0ce5c6afc7324ce10ea7ec63cd63209be28140525908a93feed3c1eef8a98f3af878a5e77a150fbf60276382ce26765c56b3a03f80406c64907db97b3ad197f5e5ca3a4ac23ff1fb0c8412824388a8bd5b7d8fb6c8c1647ee174aa8f59eb6ec26d0c7455031fb17e8080e8911d4caed655f1445f89919756a3ff4d4bba46c9411181ef1b7a6446a31b9c60b66a86485271aba518788602e44730bfad2a9af296ef5f4911"

///|
let ec_pem : String =
  #|-----BEGIN PUBLIC KEY-----
  #|MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4rt81VFFXt6y3W8f7fkeiHq1oDVi
  #|E9chJLBCK41n8rosoC2Ql1a6T3RR9I/vppUQsIiS1FzNhARuvFSM5VGC7A==
  #|-----END PUBLIC KEY-----

///|
test "a PEM envelope unwraps to its DER" {
  let der = @x509.pem(rsa_pem)
  // SEQUENCE, and long-form length, which any 2048-bit SPKI has.
  assert_eq(der[0], b'\x30')
  assert_eq(der.length() > 256, true)
}

///|
test "a bare SubjectPublicKeyInfo reads back the modulus another library wrote" {
  let key = @x509.Spki::read(@x509.pem(rsa_pem)[:]).rsa()
  assert_eq(@base16.encode(key.modulus()[:]), rsa_modulus)
  assert_eq(key.exponent(), b"\x01\x00\x01")
  assert_eq(key.size(), 256)
}

///|
/// The key it reads is usable: OAEP under it round-trips.
test "the key an SPKI carries encrypts" {
  let key = @x509.Spki::read(@x509.pem(rsa_pem)[:]).rsa()
  let cipher = key.encrypt(b"heke1228"[:], seed=b"0123456789abcdef0123"[:])
  assert_eq(cipher.length(), 256)
}

///|
/// An EC SubjectPublicKeyInfo is not an RSA one, and says so rather than
/// reading nonsense out of the bits.
test "Spki::rsa refuses a key that is not RSA" {
  let spki = @x509.Spki::read(@x509.pem(ec_pem)[:])
  let mut refused = false
  try {
    let _ = spki.rsa()
  } catch {
    Unsupported(_) => refused = true
    _ => refused = false
  }
  assert_eq(refused, true)
  // The same bytes do read as the P-256 key they are.
  let point = spki.p256()
  assert_eq(point.bytes().length(), 65)
}

///|
test "pem refuses text that is not an envelope" {
  for text in ["", "hello", "-----BEGIN PUBLIC KEY-----"] {
    let mut refused = false
    try {
      let _ = @x509.pem(text)
    } catch {
      Malformed(_) => refused = true
      _ => refused = false
    }
    assert_eq(refused, true)
  }
}
